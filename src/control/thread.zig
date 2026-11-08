//! The control thread. It owns everything that is not on the hot path:
//! reading and validating config, building snapshots, publishing them
//! (RCU), waking workers with MSG_RING, reclaiming old snapshots, and the
//! local admin endpoint.

const std = @import("std");
const linux = std.os.linux;

const worker_mod = @import("../runtime/worker.zig");
const loop_mod = @import("../runtime/loop.zig");
const model = @import("../config/model.zig");
const snapshot = @import("../config/snapshot.zig");
const file_watch = @import("../config/sources/file_watch.zig");
const socket = @import("../net/socket.zig");
const admin = @import("admin_server.zig");
const ktls = @import("../tls/ktls.zig");
const build_options = @import("build_options");

const log = std.log.scoped(.control);
const access_log = @import("../observe/access_log.zig");

pub const Command = enum(u64) { reload = 1, drain = 2, stop = 4 };

pub const Control = struct {
    gpa: std.mem.Allocator,
    shared: *worker_mod.Shared,
    registry: *snapshot.Registry,
    config_path: []const u8,
    /// eventfd; other threads write Command bits into it.
    cmd_fd: linux.fd_t,
    pending_cmds: std.atomic.Value(u64) = .init(0),
    ring: linux.IoUring,
    watcher: ?file_watch.Watcher = null,
    admin_fd: linux.fd_t = -1,
    started_ms: u64,
    draining: bool = false,
    stopped: bool = false,
    reloads_ok: u64 = 0,
    reloads_failed: u64 = 0,
    last_error: [256]u8 = undefined,
    last_error_len: usize = 0,
    applied_version: [128]u8 = undefined,
    applied_version_len: usize = 0,
    /// Access log file, reopened whenever a new generation is applied.
    log_fd: linux.fd_t = -1,
    log_gen: u64 = 0,
    /// Workers still running (decremented by worker threads on exit).
    alive: *std.atomic.Value(u32),

    pub fn init(self: *Control, gpa: std.mem.Allocator, shared: *worker_mod.Shared, registry: *snapshot.Registry, config_path: []const u8, alive: *std.atomic.Value(u32)) !void {
        self.* = .{
            .gpa = gpa,
            .shared = shared,
            .registry = registry,
            .config_path = config_path,
            .cmd_fd = @intCast(try socket.check(linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK))),
            .ring = try linux.IoUring.init(64, 0),
            .started_ms = worker_mod.Worker.nowMs(),
            .alive = alive,
        };
        self.setVersion(shared.rcu.load().version);
        self.watcher = file_watch.Watcher.init(config_path) catch |e| blk: {
            log.warn("cannot watch {s} ({s}); reload with SIGHUP or POST /reload", .{ config_path, @errorName(e) });
            break :blk null;
        };
        if (shared.rcu.load().admin) |a| {
            self.admin_fd = socket.listen(&a, 64) catch {
                var buf: [64]u8 = undefined;
                log.err("admin: cannot listen on {s}: {s}", .{ a.format(&buf), @tagName(socket.last_errno) });
                return error.AdminListenFailed;
            };
        }
    }

    pub fn deinit(self: *Control) void {
        if (self.watcher) |*wt| wt.deinit();
        if (self.admin_fd >= 0) socket.closeFd(self.admin_fd);
        if (self.log_fd >= 0) socket.closeFd(self.log_fd);
        socket.closeFd(self.cmd_fd);
        self.ring.deinit();
    }

    /// Thread-safe: ask the control thread to do something.
    pub fn request(self: *Control, cmd: Command) void {
        _ = self.pending_cmds.fetchOr(@intFromEnum(cmd), .acq_rel);
        const one: u64 = 1;
        _ = linux.write(self.cmd_fd, std.mem.asBytes(&one), 8);
    }

    fn setVersion(self: *Control, v: []const u8) void {
        const n = @min(v.len, self.applied_version.len);
        @memcpy(self.applied_version[0..n], v[0..n]);
        self.applied_version_len = n;
    }

    pub fn version(self: *const Control) []const u8 {
        return self.applied_version[0..self.applied_version_len];
    }

    pub fn lastError(self: *const Control) []const u8 {
        return self.last_error[0..self.last_error_len];
    }

    fn setError(self: *Control, msg: []const u8) void {
        const n = @min(msg.len, self.last_error.len);
        @memcpy(self.last_error[0..n], msg[0..n]);
        self.last_error_len = n;
    }

    pub fn run(self: *Control) void {
        while (!self.stopped) {
            var fds: [3]linux.pollfd = undefined;
            var n: usize = 0;
            fds[n] = .{ .fd = self.cmd_fd, .events = linux.POLL.IN, .revents = 0 };
            n += 1;
            const watch_i = n;
            if (self.watcher) |wt| {
                fds[n] = .{ .fd = wt.fd, .events = linux.POLL.IN, .revents = 0 };
                n += 1;
            }
            const admin_i = n;
            if (self.admin_fd >= 0) {
                fds[n] = .{ .fd = self.admin_fd, .events = linux.POLL.IN, .revents = 0 };
                n += 1;
            }
            _ = linux.poll(&fds, n, 250);

            if (fds[0].revents != 0) {
                var v: u64 = 0;
                _ = linux.read(self.cmd_fd, std.mem.asBytes(&v), 8);
            }
            const cmds = self.pending_cmds.swap(0, .acq_rel);
            if (cmds & @intFromEnum(Command.reload) != 0) _ = self.reload("signal");
            if (cmds & @intFromEnum(Command.drain) != 0) self.drain();
            if (cmds & @intFromEnum(Command.stop) != 0) self.stopped = true;

            if (self.watcher != null and watch_i < n and fds[watch_i].revents != 0) {
                if (self.watcher.?.changed()) _ = self.reload("file change");
            }
            if (self.admin_fd >= 0 and admin_i < n and fds[admin_i].revents != 0) {
                admin.serveOne(self, self.admin_fd);
            }
            self.flushAccessLogs();
            _ = self.shared.rcu.reclaim();
        }
        self.flushAccessLogs();
    }

    /// Moves every worker's buffered access log lines to the log file.
    /// The file is reopened for each new generation, so renaming it and
    /// sending SIGHUP rotates the log.
    fn flushAccessLogs(self: *Control) void {
        const snap = self.shared.rcu.load();
        if (snap.generation != self.log_gen) {
            self.log_gen = snap.generation;
            if (self.log_fd >= 0) socket.closeFd(self.log_fd);
            self.log_fd = -1;
            if (snap.access_log) |al| {
                self.log_fd = access_log.open(al.path);
                if (self.log_fd < 0) log.err("access log: cannot open {s}", .{al.path});
            }
        }
        for (self.shared.access_logs) |*r| _ = r.drain(self.log_fd);
    }

    /// Reads, validates and publishes the config file. Returns true when a
    /// new snapshot was applied.
    pub fn reload(self: *Control, why: []const u8) bool {
        if (self.draining) return false;
        const text = file_watch.readFile(self.gpa, self.config_path) catch |e| {
            var buf: [256]u8 = undefined;
            self.fail(std.fmt.bufPrint(&buf, "read {s}: {s}", .{ self.config_path, @errorName(e) }) catch "read failed");
            return false;
        };
        defer self.gpa.free(text);
        var arena: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena.deinit();
        var jdiag: [256]u8 = undefined;
        @memset(&jdiag, 0);
        const cfg = model.parseJson(arena.allocator(), text, &jdiag) catch {
            self.fail(std.mem.sliceTo(&jdiag, 0));
            return false;
        };
        var diag: snapshot.Diag = .{};
        const snap = snapshot.build(self.gpa, &cfg, self.registry, &diag) catch |e| {
            self.fail(if (e == error.InvalidConfig) diag.message() else @errorName(e));
            return false;
        };
        if (snap.uses_tls and snap.require_ktls and !ktls.available()) {
            snap.destroy();
            self.fail("config uses TLS with require_ktls, but kernel TLS (the 'tls' module) is not loaded");
            return false;
        }
        const old = self.shared.rcu.load();
        if (snap.limits.max_connections_per_worker != old.limits.max_connections_per_worker)
            log.warn("limits.max_connections_per_worker changes take effect on restart", .{});
        if (snap.workers != old.workers) log.warn("workers changes take effect on restart", .{});
        self.shared.rcu.publish(snap) catch {
            snap.destroy();
            self.fail("out of memory");
            return false;
        };
        self.wakeWorkers(.config);
        if (self.shared.health) |h| h.setTargets(snap);
        self.reloads_ok += 1;
        self.last_error_len = 0;
        self.setVersion(snap.version);
        log.info("config applied ({s}): generation {d}, version '{s}'", .{ why, snap.generation, snap.version });
        return true;
    }

    fn fail(self: *Control, msg: []const u8) void {
        self.reloads_failed += 1;
        self.setError(msg);
        log.err("config rejected, keeping generation {d}: {s}", .{ self.shared.rcu.load().generation, msg });
    }

    fn wakeWorkers(self: *Control, why: worker_mod.Wake) void {
        var sent: u32 = 0;
        for (self.shared.ring_fds) |*rf| {
            const fd = rf.load(.acquire);
            if (fd < 0) continue;
            loop_mod.msgRing(&self.ring, fd, @intFromEnum(why), worker_mod.Worker.ud(.wake, 0, 0)) catch {
                _ = self.ring.submit() catch {};
                continue;
            };
            sent += 1;
            if (sent % 32 == 0) _ = self.ring.submit() catch {};
        }
        _ = self.ring.submit_and_wait(@min(sent, 1)) catch {};
        // Reap the MSG_RING completions on our own ring.
        var cqes: [64]linux.io_uring_cqe = undefined;
        while ((self.ring.copy_cqes(&cqes, 0) catch 0) > 0) {}
    }

    pub fn drain(self: *Control) void {
        if (self.draining) return;
        self.draining = true;
        log.info("draining: listeners closed, finishing in-flight requests", .{});
        self.wakeWorkers(.drain);
    }

    pub fn uptimeMs(self: *const Control) u64 {
        return worker_mod.Worker.nowMs() - self.started_ms;
    }

    pub fn buildVersion() []const u8 {
        return build_options.version;
    }
};
