//! OpenSSL 3.x implementation of the TlsBackend interface (see backend.zig).
//!
//! The handshake runs on the socket itself (a socket BIO) driven by
//! io_uring readiness, with SSL_OP_ENABLE_KTLS: when the kernel `tls`
//! module is present OpenSSL installs the traffic keys into the socket
//! (TLS_TX/TLS_RX) and from then on the socket carries plaintext, so the
//! normal io_uring data path (multishot recv into provided buffers,
//! sendmsg) works unchanged. OpenSSL can only enable kTLS on a socket
//! BIO, which is why the handshake is not done over memory BIOs.
//!
//! When kTLS is not active the connection stays in userspace mode:
//! SSL_read/SSL_write on readiness, counted by the tls_userspace metric.

const std = @import("std");
const c = @import("openssl_c.zig");
const sni = @import("sni.zig");

pub const Ctx = c.SSL_CTX;
pub const Conn = c.SSL;

pub const name = "openssl";

/// Only suites the kernel can offload: AES-GCM-128/256, ChaCha20-Poly1305.
const tls13_suites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
const tls12_ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" ++
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" ++
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
const alpn_wire = "\x08http/1.1";

pub const Error = error{TlsConfig};

pub const Diag = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,
    pub fn message(self: *const Diag) []const u8 {
        return self.buf[0..self.len];
    }
};

fn fail(d: *Diag, comptime what: []const u8, arg: []const u8) Error {
    var ebuf: [160]u8 = undefined;
    const e = c.ERR_get_error();
    var detail: []const u8 = "unknown error";
    if (e != 0) {
        c.ERR_error_string_n(e, &ebuf, ebuf.len);
        detail = std.mem.sliceTo(&ebuf, 0);
    }
    c.ERR_clear_error();
    const s = std.fmt.bufPrint(&d.buf, what ++ " '{s}': {s}", .{ arg, detail }) catch d.buf[0..];
    d.len = s.len;
    return error.TlsConfig;
}

fn zstr(buf: []u8, s: []const u8) ![*:0]const u8 {
    if (s.len >= buf.len) return error.TlsConfig;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return @ptrCast(buf.ptr);
}

fn common(ctx: *Ctx) void {
    _ = c.SSL_CTX_set_options(ctx, c.SSL_OP_ENABLE_KTLS | c.SSL_OP_NO_RENEGOTIATION | c.SSL_OP_NO_COMPRESSION | c.SSL_OP_IGNORE_UNEXPECTED_EOF);
    _ = c.SSL_CTX_ctrl(ctx, c.SSL_CTRL_SET_MIN_PROTO_VERSION, c.TLS1_2_VERSION, null);
    _ = c.SSL_CTX_ctrl(ctx, c.SSL_CTRL_MODE, c.SSL_MODE_ENABLE_PARTIAL_WRITE | c.SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | c.SSL_MODE_RELEASE_BUFFERS, null);
}

fn alpnSelect(_: *c.SSL, out: *[*c]const u8, outlen: *u8, in: [*c]const u8, inlen: c_uint, _: ?*anyopaque) callconv(.c) c_int {
    var o: [*c]u8 = undefined;
    if (c.SSL_select_next_proto(&o, outlen, alpn_wire, alpn_wire.len, in, inlen) != c.OPENSSL_NPN_NEGOTIATED)
        return c.SSL_TLSEXT_ERR_NOACK; // no overlap: continue without ALPN
    out.* = o;
    return c.SSL_TLSEXT_ERR_OK;
}

pub const CertSpec = struct {
    certificate_chain: []const u8,
    private_key: []const u8,
    server_names: []const []const u8,
};

/// One SSL_CTX per certificate; SNI picks among them.
pub const Server = struct {
    pub const Entry = struct { names: []const []const u8, ctx: *Ctx };
    entries: []Entry,

    pub fn defaultCtx(self: *const Server) *Ctx {
        return self.entries[0].ctx;
    }

    pub fn deinit(self: *Server) void {
        for (self.entries) |e| c.SSL_CTX_free(e.ctx);
    }
};

fn servername(ssl: *c.SSL, _: *c_int, arg: ?*anyopaque) callconv(.c) c_int {
    const srv: *const Server = @ptrCast(@alignCast(arg.?));
    const n = c.SSL_get_servername(ssl, c.TLSEXT_NAMETYPE_host_name) orelse return c.SSL_TLSEXT_ERR_OK;
    if (sni.select(Server.Entry, srv.entries, std.mem.sliceTo(n, 0))) |i| {
        if (i != 0) _ = c.SSL_set_SSL_CTX(ssl, srv.entries[i].ctx);
    }
    return c.SSL_TLSEXT_ERR_OK;
}

/// Builds the server contexts. `arena` owns the Server struct and names.
pub fn newServer(arena: std.mem.Allocator, certs: []const CertSpec, d: *Diag) !*Server {
    const srv = try arena.create(Server);
    srv.entries = try arena.alloc(Server.Entry, certs.len);
    var built: usize = 0;
    errdefer for (srv.entries[0..built]) |e| c.SSL_CTX_free(e.ctx);
    for (certs, 0..) |spec, i| {
        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return fail(d, "SSL_CTX_new", "server");
        common(ctx);
        _ = c.SSL_CTX_set_options(ctx, c.SSL_OP_CIPHER_SERVER_PREFERENCE);
        _ = c.SSL_CTX_set_num_tickets(ctx, 1);
        if (c.SSL_CTX_set_ciphersuites(ctx, tls13_suites) != 1 or c.SSL_CTX_set_cipher_list(ctx, tls12_ciphers) != 1) {
            c.SSL_CTX_free(ctx);
            return fail(d, "cipher configuration", "");
        }
        c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelect, null);
        var pbuf: [4096]u8 = undefined;
        const chain = zstr(&pbuf, spec.certificate_chain) catch {
            c.SSL_CTX_free(ctx);
            return fail(d, "path too long", spec.certificate_chain);
        };
        if (c.SSL_CTX_use_certificate_chain_file(ctx, chain) != 1) {
            c.SSL_CTX_free(ctx);
            return fail(d, "cannot load certificate chain", spec.certificate_chain);
        }
        const key = zstr(&pbuf, spec.private_key) catch {
            c.SSL_CTX_free(ctx);
            return fail(d, "path too long", spec.private_key);
        };
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key, c.SSL_FILETYPE_PEM) != 1 or c.SSL_CTX_check_private_key(ctx) != 1) {
            c.SSL_CTX_free(ctx);
            return fail(d, "cannot load private key (or it does not match the certificate)", spec.private_key);
        }
        const names = try arena.alloc([]const u8, spec.server_names.len);
        for (spec.server_names, names) |s, *o| o.* = try arena.dupe(u8, s);
        srv.entries[i] = .{ .names = names, .ctx = ctx };
        built += 1;
    }
    _ = c.SSL_CTX_callback_ctrl(srv.entries[0].ctx, c.SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, @ptrCast(&servername));
    _ = c.SSL_CTX_ctrl(srv.entries[0].ctx, c.SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, srv);
    return srv;
}

pub const ClientSpec = struct {
    verify: bool,
    ca_file: ?[]const u8,
};

pub fn newClient(spec: ClientSpec, d: *Diag) !*Ctx {
    const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return fail(d, "SSL_CTX_new", "client");
    errdefer c.SSL_CTX_free(ctx);
    common(ctx);
    if (c.SSL_CTX_set_ciphersuites(ctx, tls13_suites) != 1 or c.SSL_CTX_set_cipher_list(ctx, tls12_ciphers) != 1)
        return fail(d, "cipher configuration", "");
    if (c.SSL_CTX_set_alpn_protos(ctx, alpn_wire, alpn_wire.len) != 0) return fail(d, "ALPN", "http/1.1");
    if (spec.verify) {
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        if (spec.ca_file) |f| {
            var pbuf: [4096]u8 = undefined;
            const z = zstr(&pbuf, f) catch return fail(d, "path too long", f);
            if (c.SSL_CTX_load_verify_locations(ctx, z, null) != 1) return fail(d, "cannot load CA file", f);
        } else if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) return fail(d, "cannot load system CA store", "");
    } else c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
    return ctx;
}

pub fn freeCtx(ctx: *Ctx) void {
    c.SSL_CTX_free(ctx);
}

// ---------------------------------------------------------------- connections

pub const Io = union(enum) {
    /// Bytes transferred (0 for a completed handshake).
    n: usize,
    want_read,
    want_write,
    /// Clean close (close_notify, or EOF which we accept as close).
    eof,
    err,
};

pub fn newServerConn(ctx: *Ctx, fd: std.os.linux.fd_t) ?*Conn {
    const ssl = c.SSL_new(ctx) orelse return null;
    if (c.SSL_set_fd(ssl, fd) != 1) {
        c.SSL_free(ssl);
        return null;
    }
    c.SSL_set_accept_state(ssl);
    return ssl;
}

/// `host` is used for SNI and, when verifying, for the hostname check.
pub fn newClientConn(ctx: *Ctx, fd: std.os.linux.fd_t, host: ?[]const u8, verify: bool) ?*Conn {
    const ssl = c.SSL_new(ctx) orelse return null;
    if (c.SSL_set_fd(ssl, fd) != 1) {
        c.SSL_free(ssl);
        return null;
    }
    c.SSL_set_connect_state(ssl);
    if (host) |h| {
        var buf: [256]u8 = undefined;
        const z = zstr(&buf, h) catch {
            c.SSL_free(ssl);
            return null;
        };
        _ = c.SSL_ctrl(ssl, c.SSL_CTRL_SET_TLSEXT_HOSTNAME, c.TLSEXT_NAMETYPE_host_name, @constCast(@ptrCast(z)));
        if (verify and c.SSL_set1_host(ssl, z) != 1) {
            c.SSL_free(ssl);
            return null;
        }
    }
    return ssl;
}

pub fn freeConn(ssl: *Conn) void {
    c.SSL_free(ssl);
}

fn classify(ssl: *Conn, ret: c_int) Io {
    return switch (c.SSL_get_error(ssl, ret)) {
        c.SSL_ERROR_WANT_READ => .want_read,
        c.SSL_ERROR_WANT_WRITE => .want_write,
        c.SSL_ERROR_ZERO_RETURN => .eof,
        c.SSL_ERROR_SYSCALL => if (c.ERR_peek_error() == 0) .eof else .err,
        else => .err,
    };
}

pub fn handshake(ssl: *Conn) Io {
    c.ERR_clear_error();
    const r = c.SSL_do_handshake(ssl);
    if (r == 1) return .{ .n = 0 };
    return classify(ssl, r);
}

pub fn read(ssl: *Conn, buf: []u8) Io {
    c.ERR_clear_error();
    const r = c.SSL_read(ssl, buf.ptr, @intCast(@min(buf.len, std.math.maxInt(c_int))));
    if (r > 0) return .{ .n = @intCast(r) };
    return classify(ssl, r);
}

pub fn write(ssl: *Conn, data: []const u8) Io {
    c.ERR_clear_error();
    const r = c.SSL_write(ssl, data.ptr, @intCast(@min(data.len, std.math.maxInt(c_int))));
    if (r > 0) return .{ .n = @intCast(r) };
    return classify(ssl, r);
}

/// Sends close_notify (best effort, non-blocking).
pub fn shutdown(ssl: *Conn) void {
    c.ERR_clear_error();
    _ = c.SSL_shutdown(ssl);
    c.ERR_clear_error();
}

pub fn pending(ssl: *Conn) bool {
    return c.SSL_pending(ssl) > 0;
}

pub const Offload = struct { tx: bool, rx: bool };

pub fn ktlsStatus(ssl: *Conn) Offload {
    return .{
        .tx = c.BIO_ctrl(c.SSL_get_wbio(ssl), c.BIO_CTRL_GET_KTLS_SEND, 0, null) > 0,
        .rx = c.BIO_ctrl(c.SSL_get_rbio(ssl), c.BIO_CTRL_GET_KTLS_RECV, 0, null) > 0,
    };
}

pub fn describe(ssl: *Conn, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s} {s}", .{ std.mem.sliceTo(c.SSL_get_version(ssl), 0), std.mem.sliceTo(c.SSL_CIPHER_get_name(c.SSL_get_current_cipher(ssl)), 0) }) catch buf[0..0];
}

pub fn lastError(buf: []u8) []const u8 {
    const e = c.ERR_get_error();
    if (e == 0) return "no error queued";
    c.ERR_error_string_n(e, buf.ptr, buf.len);
    c.ERR_clear_error();
    return std.mem.sliceTo(buf, 0);
}
