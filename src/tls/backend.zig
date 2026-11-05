//! The TLS backend interface, checked at compile time. The proxy only
//! talks to `Tls` (selected below); swapping OpenSSL for BoringSSL or
//! AWS-LC means providing another file with the same declarations.

const std = @import("std");

pub const Tls = @import("openssl.zig");

/// Where a connection's TLS runs.
pub const Mode = enum {
    /// Plain TCP.
    none,
    /// Handshake in progress (driven by readiness polls).
    handshake,
    /// Kernel TLS in both directions: the socket carries plaintext.
    ktls,
    /// Userspace fallback: SSL_read/SSL_write on readiness.
    user,
};

const required = [_][]const u8{
    "Ctx",           "Conn",        "Io",          "Diag",       "Server",     "CertSpec",
    "ClientSpec",    "newServer",   "newClient",   "freeCtx",    "newServerConn", "newClientConn",
    "freeConn",      "handshake",   "read",        "write",      "shutdown",   "pending",
    "ktlsStatus",    "describe",    "lastError",
};

comptime {
    for (required) |d| {
        if (!@hasDecl(Tls, d)) @compileError("TLS backend " ++ Tls.name ++ " lacks '" ++ d ++ "'");
    }
}
