//! Active health checks. One background thread probes the endpoints of
//! every cluster that has a `health_check`: a TCP connect, or an HTTP GET
//! whose status must be 200-399. After `unhealthy_threshold` failures in a
//! row an endpoint is marked down in a shared table (one byte per endpoint
//! id) that the workers' load balancers read; `healthy_threshold` passes
//! bring it back. Endpoints start healthy, so enabling checks never causes
//! an outage by itself.
//!
//! The control thread hands over a fresh copy of the targets whenever a
//! config is applied (`setTargets`), so this thread never touches a
//! snapshot that could be reclaimed.

const std = @import("std");
const linux = std.os.linux;
const Address = @import("../net/addr.zig").Address;
const socket = @import("../net/socket.zig");
const snapshot = @import("../config/snapshot.zig");

const log = std.log.scoped(.health);

/// Endpoint ids at or above this are not checked (they stay healthy).
pub const max_endpoints = 1 << 16;

pub const Check = struct {
    interval_ms: u32,
    timeout_ms: u32,
    healthy_threshold: u8,
    unhealthy_threshold: u8,
    /// HTTP GET path; null for a TCP connect check.
    path: ?[]const u8,
    host: ?[]const u8,
};

const Phase = enum { idle, connecting, sending, reading };

const Target = struct {
    ep_id: u32,
    addr: Address,
    /// "10.0.0.1:80", for logs and the default Host header.
    text: []const u8,
    cluster: []const u8,
    check: Check,
    // Probe state.
    phase: Phase = .idle,
    fd: linux.fd_t = -1,
    started_ms: u64 = 0,
    next_ms: u64 = 0,
    req: [512]u8 = undefined,
    req_len: u16 = 0,
    sent: u16 = 0,
    resp: [16]u8 = undefined,
    got: u8 = 0,
    // Result state.
    passes: u8 = 0,
    fails: u8 = 0,
    down: bool = false,
};

pub const ActiveHealth = struct {
    gpa: std.mem.Allocator,
    /// down[ep_id] != 0: failed its active checks. Read by workers.
    down: []std.atomic.Value(u8),
    checks_failed: std.atomic.Value(u64) = .init(0),
    unhealthy: std.atomic.Value(u32) = .init(0),

    /// Guards `pending` (taken briefly, on config reloads only).
    lock_flag: std.atomic.Value(bool) = .init(false),
    /// Pending target list from the control thread (owned arena).
    pending: ?std.heap.ArenaAllocator = null,
    pending_targets: []Target = &.{},
    stop: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    // Owned by the health thread.
    arena: ?std.heap.ArenaAllocator = null,
    targets: []Target = &.{},

    pub fn init(self: *ActiveHealth, gpa: std.mem.Allocator) !void {
        const down = try gpa.alloc(std.atomic.Value(u8), max_endpoints);
        for (down) |*d| d.* = .init(0);
        self.* = .{ .gpa = gpa, .down = down };
    }

    pub fn start(self: *ActiveHealth) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn deinit(self: *ActiveHealth) void {
        self.stop.store(true, .release);
        if (self.thread) |t| t.join();
        for (self.targets) |*t| if (t.fd >= 0) socket.closeFd(t.fd);
        if (self.arena) |*a| a.deinit();
        if (self.pending) |*a| a.deinit();
        self.gpa.free(self.down);
    }

    pub fn isDown(down: []const std.atomic.Value(u8), ep_id: u32) bool {
        return ep_id < down.len and down[ep_id].load(.monotonic) != 0;
    }

    /// Control thread: replace the targets with those of `snap`.
    pub fn setTargets(self: *ActiveHealth, snap: *const snapshot.Snapshot) void {
        var arena: std.heap.ArenaAllocator = .init(self.gpa);
        const a = arena.allocator();
        var list: std.ArrayList(Target) = .empty;
        var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;
        for (snap.clusters) |*c| if (c.health_check) |hc| for (c.endpoints) |*e| {
            // One check per endpoint: the first cluster that asks wins.
            if (e.id >= max_endpoints) continue;
            const gop = seen.getOrPut(a, e.id) catch break;
            if (gop.found_existing) continue;
            list.append(a, .{
                .ep_id = e.id,
                .addr = e.addr,
                .text = a.dupe(u8, e.text) catch break,
                .cluster = a.dupe(u8, c.name) catch break,
                .check = .{
                    .interval_ms = hc.interval_ms,
                    .timeout_ms = hc.timeout_ms,
                    .healthy_threshold = hc.healthy_threshold,
                    .unhealthy_threshold = hc.unhealthy_threshold,
                    .path = if (hc.path) |p| a.dupe(u8, p) catch break else null,
                    .host = if (hc.host) |h| a.dupe(u8, h) catch break else null,
                },
            }) catch break;
        };
        self.lock();
        defer self.unlock();
        if (self.pending) |*old| old.deinit();
        self.pending = arena;
        self.pending_targets = list.items;
    }

    fn adopt(self: *ActiveHealth) void {
        self.lock();
        const new_arena = self.pending orelse {
            self.unlock();
            return;
        };
        const new = self.pending_targets;
        self.pending = null;
        self.pending_targets = &.{};
        self.unlock();

        // Keep results for endpoints that are still checked; endpoints no
        // longer checked become healthy again.
        for (new) |*t| for (self.targets) |*o| if (o.ep_id == t.ep_id) {
            t.passes = o.passes;
            t.fails = o.fails;
            t.down = o.down;
            t.next_ms = o.next_ms;
            break;
        };
        for (self.targets) |*o| {
            if (o.fd >= 0) socket.closeFd(o.fd);
            const kept = for (new) |*t| {
                if (t.ep_id == o.ep_id) break true;
            } else false;
            if (o.down and !kept) self.setDown(o, false, "no longer checked");
        }
        if (self.arena) |*a| a.deinit();
        self.arena = new_arena;
        self.targets = new;
    }

    fn lock(self: *ActiveHealth) void {
        while (self.lock_flag.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    fn unlock(self: *ActiveHealth) void {
        self.lock_flag.store(false, .release);
    }

    fn setDown(self: *ActiveHealth, t: *Target, down: bool, why: []const u8) void {
        if (t.down == down) return;
        t.down = down;
        self.down[t.ep_id].store(@intFromBool(down), .monotonic);
        if (down) {
            _ = self.unhealthy.fetchAdd(1, .monotonic);
            log.warn("endpoint {s} in cluster '{s}' is unhealthy: {s}", .{ t.text, t.cluster, why });
        } else {
            _ = self.unhealthy.fetchSub(1, .monotonic);
            log.info("endpoint {s} in cluster '{s}' is healthy again", .{ t.text, t.cluster });
        }
    }

    fn run(self: *ActiveHealth) void {
        var fds: std.ArrayList(linux.pollfd) = .empty;
        defer fds.deinit(self.gpa);
        var owners: std.ArrayList(usize) = .empty;
        defer owners.deinit(self.gpa);
        while (!self.stop.load(.acquire)) {
            self.adopt();
            const now = nowMs();
            var wait_ms: u64 = 250;
            fds.clearRetainingCapacity();
            owners.clearRetainingCapacity();
            for (self.targets, 0..) |*t, i| {
                if (t.phase == .idle and now >= t.next_ms) self.begin(t, now);
                if (t.phase == .idle) {
                    wait_ms = @min(wait_ms, t.next_ms -| now);
                    continue;
                }
                if (now -| t.started_ms >= t.check.timeout_ms) {
                    self.finish(t, now, false, "timed out");
                    continue;
                }
                wait_ms = @min(wait_ms, t.started_ms + t.check.timeout_ms -| now);
                const ev: i16 = if (t.phase == .reading) linux.POLL.IN else linux.POLL.OUT;
                fds.append(self.gpa, .{ .fd = t.fd, .events = ev, .revents = 0 }) catch continue;
                owners.append(self.gpa, i) catch {
                    _ = fds.pop();
                    continue;
                };
            }
            _ = linux.poll(fds.items.ptr, @intCast(fds.items.len), @intCast(@max(wait_ms, 5)));
            const after = nowMs();
            for (fds.items, owners.items) |pfd, i| {
                if (pfd.revents == 0) continue;
                self.step(&self.targets[i], after);
            }
        }
    }

    fn begin(self: *ActiveHealth, t: *Target, now: u64) void {
        t.started_ms = now;
        t.got = 0;
        t.sent = 0;
        const fd = socket.connectSocket(&t.addr) catch return self.finish(t, now, false, "socket failed");
        t.fd = fd;
        const rc = linux.connect(fd, &t.addr.any, t.addr.len());
        switch (linux.errno(rc)) {
            .SUCCESS, .INPROGRESS => t.phase = .connecting,
            else => |e| return self.finish(t, now, false, @tagName(e)),
        }
    }

    fn step(self: *ActiveHealth, t: *Target, now: u64) void {
        switch (t.phase) {
            .idle => {},
            .connecting => {
                var err: i32 = 0;
                var len: linux.socklen_t = @sizeOf(i32);
                _ = linux.getsockopt(t.fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&err), &len);
                if (err != 0) return self.finish(t, now, false, @tagName(@as(linux.E, @enumFromInt(err))));
                const path = t.check.path orelse return self.finish(t, now, true, "");
                const req = std.fmt.bufPrint(&t.req, "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: likzik-health-check\r\nConnection: close\r\n\r\n", .{ path, t.check.host orelse t.text }) catch
                    return self.finish(t, now, false, "request too long");
                t.req_len = @intCast(req.len);
                t.phase = .sending;
                self.step(t, now);
            },
            .sending => {
                const n = socket.writeNb(t.fd, t.req[t.sent..t.req_len]) catch |e| switch (e) {
                    error.WouldBlock => return,
                    error.SyscallFailed => return self.finish(t, now, false, "send failed"),
                };
                t.sent += @intCast(n);
                if (t.sent == t.req_len) t.phase = .reading;
            },
            .reading => {
                const n = socket.recvNb(t.fd, t.resp[t.got..], false) catch |e| switch (e) {
                    error.WouldBlock => return,
                    error.SyscallFailed => return self.finish(t, now, false, "receive failed"),
                };
                if (n == 0 and t.got < 12) return self.finish(t, now, false, "closed without a response");
                t.got += @intCast(n);
                if (t.got < 12) return;
                // "HTTP/1.1 200"
                const line = t.resp[0..t.got];
                if (!std.mem.startsWith(u8, line, "HTTP/1.")) return self.finish(t, now, false, "not HTTP");
                const status = std.fmt.parseInt(u16, line[9..12], 10) catch return self.finish(t, now, false, "bad status line");
                var why: [32]u8 = undefined;
                if (status >= 200 and status < 400) return self.finish(t, now, true, "");
                self.finish(t, now, false, std.fmt.bufPrint(&why, "status {d}", .{status}) catch "bad status");
            },
        }
    }

    fn finish(self: *ActiveHealth, t: *Target, now: u64, ok: bool, why: []const u8) void {
        if (t.fd >= 0) socket.closeFd(t.fd);
        t.fd = -1;
        t.phase = .idle;
        // Spread probes a little so endpoints do not all fire together.
        t.next_ms = now + t.check.interval_ms + (t.ep_id % 16) * t.check.interval_ms / 64;
        if (ok) {
            t.fails = 0;
            t.passes +|= 1;
            if (t.down and t.passes >= t.check.healthy_threshold) self.setDown(t, false, "");
        } else {
            _ = self.checks_failed.fetchAdd(1, .monotonic);
            t.passes = 0;
            t.fails +|= 1;
            if (!t.down and t.fails >= t.check.unhealthy_threshold) self.setDown(t, true, why);
        }
    }
};

fn nowMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}
