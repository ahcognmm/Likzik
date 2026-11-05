//! Thin, error-checked wrappers over raw Linux socket syscalls. The core
//! only touches std.os.linux, which keeps it insulated from churn in Zig's
//! higher-level std.Io APIs.

const std = @import("std");
const linux = std.os.linux;
const Address = @import("addr.zig").Address;

pub const Error = error{SyscallFailed};

pub fn check(rc: usize) Error!usize {
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        else => |e| {
            last_errno = e;
            return error.SyscallFailed;
        },
    };
}

pub threadlocal var last_errno: linux.E = .SUCCESS;

pub fn setInt(fd: linux.fd_t, level: i32, opt: u32, v: c_int) Error!void {
    _ = try check(linux.setsockopt(fd, level, opt, std.mem.asBytes(&v), @sizeOf(c_int)));
}

pub fn closeFd(fd: linux.fd_t) void {
    _ = linux.close(fd);
}

/// Creates a listening socket with SO_REUSEPORT so every worker can bind
/// its own socket to the same address; the kernel load-balances accepts.
pub fn listen(addr: *const Address, backlog: u32) Error!linux.fd_t {
    const fd: linux.fd_t = @intCast(try check(linux.socket(addr.family(), linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0)));
    errdefer closeFd(fd);
    try setInt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, 1);
    try setInt(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, 1);
    if (addr.family() == linux.AF.INET6) try setInt(fd, linux.IPPROTO.IPV6, linux.IPV6.V6ONLY, 1);
    _ = try check(linux.bind(fd, &addr.any, addr.len()));
    _ = try check(linux.listen(fd, backlog));
    return fd;
}

/// Non-blocking client socket for an upstream connection.
pub fn connectSocket(addr: *const Address) Error!linux.fd_t {
    const fd: linux.fd_t = @intCast(try check(linux.socket(addr.family(), linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0)));
    errdefer closeFd(fd);
    try setInt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, 1);
    // Bound how long unacknowledged data may sit before the kernel gives up.
    try setInt(fd, linux.IPPROTO.TCP, linux.TCP.USER_TIMEOUT, 30_000);
    return fd;
}

pub fn peerAddress(fd: linux.fd_t) Address {
    var a: Address = undefined;
    var len: linux.socklen_t = @sizeOf(Address);
    if (linux.errno(linux.getpeername(fd, &a.any, &len)) != .SUCCESS) {
        a = .{ .in4 = .{ .port = 0, .addr = 0 } };
    }
    return a;
}

pub fn localPort(fd: linux.fd_t) u16 {
    var a: Address = undefined;
    var len: linux.socklen_t = @sizeOf(Address);
    if (linux.errno(linux.getsockname(fd, &a.any, &len)) != .SUCCESS) return 0;
    return a.port();
}

pub fn shutdownWrite(fd: linux.fd_t) void {
    _ = linux.shutdown(fd, linux.SHUT.WR);
}

pub const SPLICE_F_MOVE = 1;
pub const SPLICE_F_NONBLOCK = 2;

/// splice(2). Returns bytes moved, 0 on EOF, or error.WouldBlock.
pub fn splice(fd_in: linux.fd_t, fd_out: linux.fd_t, len: usize) error{ WouldBlock, SyscallFailed }!usize {
    const rc = linux.syscall6(.splice, @bitCast(@as(isize, fd_in)), 0, @bitCast(@as(isize, fd_out)), 0, len, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    return switch (linux.errno(rc)) {
        .SUCCESS => rc,
        .AGAIN => error.WouldBlock,
        .INTR => error.WouldBlock,
        else => |e| {
            last_errno = e;
            return error.SyscallFailed;
        },
    };
}

pub fn pipe() Error![2]linux.fd_t {
    var fds: [2]linux.fd_t = undefined;
    _ = try check(linux.pipe2(&fds, .{ .CLOEXEC = true, .NONBLOCK = true }));
    return fds;
}
