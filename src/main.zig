//! likzik: high-performance reverse proxy (HTTP/1.1, TCP/L4) on io_uring.
//!
//! The main thread is the supervisor: it loads config, runs startup
//! checks, starts one worker per core and the control thread, then turns
//! signals into commands (SIGHUP reload, SIGTERM/SIGINT graceful drain;
//! a second SIGINT/SIGTERM exits immediately).

const std = @import("std");
const linux = std.os.linux;
const likzik = @import("likzik");
const build_options = @import("build_options");

const worker_mod = likzik.runtime.worker;
const Control = likzik.control.thread.Control;
const snapshot = likzik.config.snapshot;
const model = likzik.config.model;
const stats = likzik.observe.stats;
const checks = likzik.runtime.checks;
const file_watch = likzik.config.file_watch;

pub const std_options: std.Options = .{ .log_level = .info };

const log = std.log.scoped(.main);

const usage =
    \\usage: likzik [-c config.json] [options]
    \\
    \\  -c, --config PATH     config file (default: likzik.json)
    \\  -t, --check           validate the config and exit
    \\  -w, --workers N       override the worker count
    \\      --buffers N       provided recv buffers per worker (power of 2, default 256)
    \\      --no-pin          do not pin worker N to CPU N
    \\      --no-coalesce     (A/B testing) do not merge small bodies into the head send
    \\      --always-linger   (A/B testing) always wait for the client FIN before closing
    \\      --allow-old-kernel  allow kernels older than 6.14 (development)
    \\      --version         print the version and exit
    \\
;

const Args = struct {
    config: []const u8 = "likzik.json",
    check: bool = false,
    workers: ?u16 = null,
    pin: bool = true,
    allow_old_kernel: bool = false,
    buffers: u16 = 256,
};

fn parseArgs(list: []const [:0]const u8) !Args {
    var a: Args = .{};
    var i: usize = 1;
    while (i < list.len) : (i += 1) {
        const s = list[i];
        if (std.mem.eql(u8, s, "-c") or std.mem.eql(u8, s, "--config")) {
            i += 1;
            if (i >= list.len) return error.MissingValue;
            a.config = list[i];
        } else if (std.mem.eql(u8, s, "-t") or std.mem.eql(u8, s, "--check")) {
            a.check = true;
        } else if (std.mem.eql(u8, s, "-w") or std.mem.eql(u8, s, "--workers")) {
            i += 1;
            if (i >= list.len) return error.MissingValue;
            a.workers = try std.fmt.parseInt(u16, list[i], 10);
        } else if (std.mem.eql(u8, s, "--buffers")) {
            i += 1;
            if (i >= list.len) return error.MissingValue;
            a.buffers = try std.fmt.parseInt(u16, list[i], 10);
            if (!std.math.isPowerOfTwo(a.buffers)) return error.BadArgs;
        } else if (std.mem.eql(u8, s, "--pin-cpus")) {
            a.pin = true; // the default; kept for compatibility
        } else if (std.mem.eql(u8, s, "--no-pin")) {
            a.pin = false;
        } else if (std.mem.eql(u8, s, "--no-coalesce")) {
            likzik.proxy.http.coalesce_enabled = false;
        } else if (std.mem.eql(u8, s, "--always-linger")) {
            likzik.proxy.http.direct_close_enabled = false;
        } else if (std.mem.eql(u8, s, "--allow-old-kernel")) {
            a.allow_old_kernel = true;
        } else if (std.mem.eql(u8, s, "--version")) {
            std.debug.print("likzik {s}\n", .{build_options.version});
            std.process.exit(0);
        } else if (std.mem.eql(u8, s, "-h") or std.mem.eql(u8, s, "--help")) {
            std.debug.print("{s}", .{usage});
            std.process.exit(0);
        } else {
            std.debug.print("unknown argument: {s}\n{s}", .{ s, usage });
            return error.BadArgs;
        }
    }
    return a;
}

fn loadSnapshot(gpa: std.mem.Allocator, path: []const u8, reg: *snapshot.Registry) !*snapshot.Snapshot {
    const text = file_watch.readFile(gpa, path) catch |e| {
        log.err("cannot read {s}: {s}", .{ path, @errorName(e) });
        return error.InvalidConfig;
    };
    defer gpa.free(text);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var jdiag: [256]u8 = undefined;
    @memset(&jdiag, 0);
    const cfg = model.parseJson(arena.allocator(), text, &jdiag) catch {
        log.err("{s}: {s}", .{ path, std.mem.sliceTo(&jdiag, 0) });
        return error.InvalidConfig;
    };
    var diag: snapshot.Diag = .{};
    return snapshot.build(gpa, &cfg, reg, &diag) catch |e| {
        log.err("{s}: {s}", .{ path, if (e == error.InvalidConfig) diag.message() else @errorName(e) });
        return error.InvalidConfig;
    };
}

var alive: std.atomic.Value(u32) = .init(0);

fn workerEntry(gpa: std.mem.Allocator, id: u16, shared: *worker_mod.Shared) void {
    defer _ = alive.fetchSub(1, .acq_rel);
    worker_mod.Worker.main(gpa, id, shared);
}

fn controlEntry(c: *Control) void {
    c.run();
}

fn sleepMs(ms: u64) void {
    const ts: linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = linux.nanosleep(&ts, null);
}

pub fn main(init: std.process.Init) !u8 {
    return run(init);
}

/// The whole supervisor. Binaries that register an extension (likzik-gw)
/// set `likzik.proxy.filter.registered` and then call this.
pub fn run(init: std.process.Init) !u8 {
    const gpa = std.heap.smp_allocator;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args = parseArgs(argv) catch return 2;

    var registry = snapshot.Registry.init(gpa);
    defer registry.deinit();
    const first = loadSnapshot(gpa, args.config, &registry) catch return 1;
    if (args.check) {
        std.debug.print("{s}: configuration OK ({d} listeners, {d} clusters)\n", .{ args.config, first.listeners.len, first.clusters.len });
        first.destroy();
        return 0;
    }

    checks.run(gpa, .{ .allow_old_kernel = args.allow_old_kernel, .uses_tls = first.uses_tls, .need_ktls = first.require_ktls }) catch {
        first.destroy();
        return 1;
    };

    const n_workers: u16 = args.workers orelse if (first.workers != 0) first.workers else @intCast(@max(1, std.Thread.getCpuCount() catch 1));

    // Signals: handled synchronously through a signalfd on this thread.
    // SIGPIPE is ignored (splice can raise it on a reset peer).
    const ign: linux.Sigaction = .{ .handler = .{ .handler = linux.SIG.IGN }, .mask = linux.sigemptyset(), .flags = 0 };
    _ = linux.sigaction(.PIPE, &ign, null);
    var mask = linux.sigemptyset();
    linux.sigaddset(&mask, .INT);
    linux.sigaddset(&mask, .TERM);
    linux.sigaddset(&mask, .HUP);
    _ = linux.sigprocmask(linux.SIG.BLOCK, &mask, null);
    const sfd: linux.fd_t = @intCast(likzik.net.socket.check(linux.signalfd(-1, &mask, linux.SFD.CLOEXEC)) catch {
        log.err("signalfd failed", .{});
        return 1;
    });

    var rcu = try likzik.rcu.Rcu.init(gpa, first, n_workers);
    defer rcu.deinit();
    const worker_stats = try gpa.alloc(stats.WorkerStats, n_workers);
    defer gpa.free(worker_stats);
    for (worker_stats) |*s| s.* = .{};
    const ring_fds = try gpa.alloc(std.atomic.Value(i32), n_workers);
    defer gpa.free(ring_fds);
    for (ring_fds) |*f| f.* = .init(-1);
    const ext_states = try gpa.alloc(?*anyopaque, n_workers);
    defer gpa.free(ext_states);
    @memset(ext_states, null);
    var shared: worker_mod.Shared = .{ .rcu = &rcu, .stats = worker_stats, .ring_fds = ring_fds, .pin_cpus = args.pin, .pbuf_count = args.buffers, .ext_states = ext_states };

    const threads = try gpa.alloc(std.Thread, n_workers);
    defer gpa.free(threads);
    for (threads, 0..) |*t, i| {
        _ = alive.fetchAdd(1, .acq_rel);
        t.* = try std.Thread.spawn(.{ .stack_size = 1 << 20 }, workerEntry, .{ gpa, @as(u16, @intCast(i)), &shared });
    }

    // Wait for every worker to bind its listeners.
    var ready = false;
    var waited: u32 = 0;
    while (!ready and waited < 1000) : (waited += 1) {
        ready = true;
        for (ring_fds) |*f| {
            const v = f.load(.acquire);
            if (v == -2) {
                log.err("a worker failed to start; exiting", .{});
                for (ring_fds) |*g| if (g.load(.acquire) >= 0) {
                    // Workers that did start are told to stop below.
                };
                ready = false;
                waited = 1000;
                break;
            }
            if (v == -1) ready = false;
        }
        if (!ready and waited < 1000) sleepMs(5);
    }

    var control: Control = undefined;
    var control_ok = false;
    if (ready) {
        control.init(gpa, &shared, &registry, args.config, &alive) catch |e| {
            log.err("control thread: {s}", .{@errorName(e)});
            ready = false;
        };
        control_ok = ready;
    }
    if (!ready) {
        // Tell running workers to exit.
        var tmp = linux.IoUring.init(16, 0) catch return 1;
        for (ring_fds) |*f| {
            const fd = f.load(.acquire);
            if (fd >= 0) likzik.runtime.loop.msgRing(&tmp, fd, @intFromEnum(worker_mod.Wake.drain), worker_mod.Worker.ud(.wake, 0, 0)) catch {};
        }
        _ = tmp.submit() catch {};
        for (threads) |t| t.join();
        tmp.deinit();
        if (control_ok) control.deinit();
        return 1;
    }
    defer control.deinit();
    const control_thread = try std.Thread.spawn(.{}, controlEntry, .{&control});

    {
        var buf: [64]u8 = undefined;
        for (first.listeners) |l| log.info("listening on {s} ({s}, {s})", .{ l.addr.format(&buf), l.name, @tagName(l.protocol) });
        if (first.admin) |a| log.info("admin endpoint on {s}", .{a.format(&buf)});
        log.info("likzik {s} started: {d} workers, config generation {d}", .{ build_options.version, n_workers, first.generation });
    }

    var drain_requested = false;
    while (alive.load(.acquire) > 0) {
        var pfd = [_]linux.pollfd{.{ .fd = sfd, .events = linux.POLL.IN, .revents = 0 }};
        _ = linux.poll(&pfd, 1, 200);
        if (pfd[0].revents == 0) continue;
        var info: linux.signalfd_siginfo = undefined;
        if (linux.read(sfd, std.mem.asBytes(&info), @sizeOf(linux.signalfd_siginfo)) != @sizeOf(linux.signalfd_siginfo)) continue;
        switch (info.signo) {
            @intFromEnum(linux.SIG.HUP) => control.request(.reload),
            @intFromEnum(linux.SIG.INT), @intFromEnum(linux.SIG.TERM) => {
                if (drain_requested) {
                    log.warn("second signal: exiting immediately", .{});
                    linux.exit_group(1);
                }
                drain_requested = true;
                control.request(.drain);
            },
            else => {},
        }
    }
    for (threads) |t| t.join();
    control.request(.stop);
    control_thread.join();
    log.info("all workers stopped; bye", .{});
    return 0;
}
