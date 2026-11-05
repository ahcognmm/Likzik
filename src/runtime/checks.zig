//! Startup checks. We fail fast with a clear message rather than silently
//! degrading: a proxy that starts but cannot use io_uring is worse than
//! one that refuses to start.

const std = @import("std");
const linux = std.os.linux;
const file_watch = @import("../config/sources/file_watch.zig");

const log = std.log.scoped(.startup);

pub const min_kernel = std.SemanticVersion{ .major = 6, .minor = 14, .patch = 0 };

pub fn kernelVersion() ?std.SemanticVersion {
    var uts: linux.utsname = undefined;
    if (linux.errno(linux.uname(&uts)) != .SUCCESS) return null;
    const rel = std.mem.sliceTo(&uts.release, 0);
    var it = std.mem.tokenizeAny(u8, rel, ".-+");
    const major = std.fmt.parseInt(u32, it.next() orelse return null, 10) catch return null;
    const minor = std.fmt.parseInt(u32, it.next() orelse return null, 10) catch return null;
    const patch = std.fmt.parseInt(u32, it.next() orelse "0", 10) catch 0;
    return .{ .major = major, .minor = minor, .patch = patch };
}

fn readSmall(gpa: std.mem.Allocator, path: []const u8) ?[]u8 {
    return file_watch.readFile(gpa, path) catch null;
}

pub const Options = struct {
    /// Allow kernels older than `min_kernel` (development only).
    allow_old_kernel: bool = false,
    /// TLS listeners are configured: require the kernel tls module.
    need_ktls: bool = false,
};

pub fn run(gpa: std.mem.Allocator, opts: Options) !void {
    const v = kernelVersion() orelse return fail("cannot determine the kernel version", .{});
    if (v.order(min_kernel) == .lt) {
        if (!opts.allow_old_kernel)
            return fail("kernel {d}.{d} is too old: likzik needs Linux {d}.{d}+ (6.18 LTS in production). Use --allow-old-kernel for development on 6.1+.", .{ v.major, v.minor, min_kernel.major, min_kernel.minor });
        if (v.major < 6 or (v.major == 6 and v.minor < 1)) return fail("kernel {d}.{d}: io_uring features used here need at least 6.1", .{ v.major, v.minor });
        log.warn("kernel {d}.{d} is below the supported minimum {d}.{d}", .{ v.major, v.minor, min_kernel.major, min_kernel.minor });
    }

    if (readSmall(gpa, "/proc/sys/kernel/io_uring_disabled")) |s| {
        defer gpa.free(s);
        const val = std.mem.trim(u8, s, " \n");
        if (std.mem.eql(u8, val, "2"))
            return fail("io_uring is disabled by sysctl kernel.io_uring_disabled=2. Set it to 0 (see docs/deployment.md).", .{});
        if (std.mem.eql(u8, val, "1"))
            log.warn("kernel.io_uring_disabled=1: only members of kernel.io_uring_group may use io_uring", .{});
    }

    // Probe: create a ring with the flags the workers use.
    var params = std.mem.zeroInit(linux.io_uring_params, .{
        .flags = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_DEFER_TASKRUN | linux.IORING_SETUP_COOP_TASKRUN,
    });
    var ring = linux.IoUring.init_params(8, &params) catch |e| {
        return switch (e) {
            error.PermissionDenied => fail("io_uring_setup was denied (EPERM). A seccomp profile (Docker/containerd default) or kernel.io_uring_disabled is blocking it. See docs/deployment.md.", .{}),
            error.SystemOutdated => fail("io_uring is not available in this kernel (ENOSYS), or seccomp blocks it.", .{}),
            error.SystemResources => fail("io_uring_setup: out of locked memory. Raise RLIMIT_MEMLOCK (see docs/deployment.md).", .{}),
            else => fail("io_uring_setup failed: {s}", .{@errorName(e)}),
        };
    };
    ring.deinit();

    if (opts.need_ktls) {
        if (readSmall(gpa, "/proc/net/tls_stat")) |s| gpa.free(s) else return fail("kernel TLS (the 'tls' module) is not loaded: /proc/net/tls_stat is missing. Run 'modprobe tls'.", .{});
    }

    raiseNofile();
}

fn raiseNofile() void {
    var lim: linux.rlimit = undefined;
    if (linux.errno(linux.getrlimit(.NOFILE, &lim)) != .SUCCESS) return;
    if (lim.cur < lim.max) {
        lim.cur = lim.max;
        _ = linux.setrlimit(.NOFILE, &lim);
    }
    if (lim.cur < 65536) log.warn("RLIMIT_NOFILE is {d}; raise it for production", .{lim.cur});
}

fn fail(comptime fmt: []const u8, args: anytype) error{StartupCheckFailed} {
    log.err(fmt, args);
    return error.StartupCheckFailed;
}

test "kernel version parses" {
    const v = kernelVersion().?;
    try std.testing.expect(v.major >= 5);
}
