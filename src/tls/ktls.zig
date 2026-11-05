//! Kernel TLS availability. The `tls` module exposes /proc/net/tls_stat
//! once loaded; without it OpenSSL silently falls back to userspace TLS.

const std = @import("std");
const linux = std.os.linux;

pub fn available() bool {
    const rc = linux.open("/proc/net/tls_stat", .{ .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}
