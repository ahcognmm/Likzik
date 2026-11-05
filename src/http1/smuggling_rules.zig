//! Message framing and request-smuggling rules (RFC 9112 section 6).
//!
//! Every rule here has a regression test. The rules are stricter than the
//! RFC where the RFC allows ambiguity a proxy cannot afford:
//!
//! * Content-Length together with Transfer-Encoding: reject.
//! * More than one Content-Length field, or a list value: reject.
//! * Content-Length that is not 1*DIGIT, or overflows u64: reject.
//! * Transfer-Encoding other than exactly `chunked`: 501 for requests,
//!   502 for responses. Transfer-Encoding in an HTTP/1.0 request: reject.
//! * Exactly one Host field, with a syntactically valid value.

const std = @import("std");
const parser = @import("parser.zig");
const headers = @import("headers.zig");
const chars = @import("chars.zig");

pub const Framing = union(enum) {
    /// No body.
    none,
    /// Exactly this many body bytes.
    length: u64,
    /// Chunked transfer coding.
    chunked,
    /// Body ends when the connection closes (responses only).
    close_delimited,
};

pub const max_connection_tokens = 16;

pub const ConnectionInfo = struct {
    close: bool = false,
    keep_alive: bool = false,
    upgrade: bool = false,
    /// Other tokens: names of headers that must be stripped.
    tokens: [max_connection_tokens][]const u8 = undefined,
    n_tokens: u8 = 0,

    pub fn names(self: *const ConnectionInfo) []const []const u8 {
        return self.tokens[0..self.n_tokens];
    }

    pub fn nominates(self: *const ConnectionInfo, name: []const u8) bool {
        for (self.names()) |t| if (std.ascii.eqlIgnoreCase(t, name)) return true;
        return false;
    }
};

pub const RequestInfo = struct {
    framing: Framing,
    host: []const u8,
    keep_alive: bool,
    expect_continue: bool,
    conn: ConnectionInfo,
};

pub const ResponseInfo = struct {
    framing: Framing,
    keep_alive: bool,
    conn: ConnectionInfo,
};

fn parseContentLength(v: []const u8) ?u64 {
    if (v.len == 0 or v.len > 19) return null;
    var n: u64 = 0;
    for (v) |c| {
        if (!chars.isDigit(c)) return null;
        n = n * 10 + (c - '0');
    }
    return n;
}

fn parseConnection(info: *ConnectionInfo, value: []const u8) error{BadRequest}!void {
    var it = std.mem.tokenizeScalar(u8, value, ',');
    while (it.next()) |raw| {
        const tok = std.mem.trim(u8, raw, " \t");
        if (tok.len == 0) continue;
        for (tok) |c| if (!chars.isTchar(c)) return error.BadRequest;
        if (std.ascii.eqlIgnoreCase(tok, "close")) {
            info.close = true;
        } else if (std.ascii.eqlIgnoreCase(tok, "keep-alive")) {
            info.keep_alive = true;
        } else {
            if (std.ascii.eqlIgnoreCase(tok, "upgrade")) info.upgrade = true;
            if (info.n_tokens == max_connection_tokens) return error.BadRequest;
            info.tokens[info.n_tokens] = tok;
            info.n_tokens += 1;
        }
    }
}

fn validHost(v: []const u8) bool {
    if (v.len == 0 or v.len > 255) return false;
    for (v) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '.', ':', '[', ']', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '%' => {},
        else => return false,
    };
    return true;
}

const Common = struct {
    cl: ?u64 = null,
    te_chunked: bool = false,
    te_seen: bool = false,
    te_other: bool = false,
    conn: ConnectionInfo = .{},
};

fn scanCommon(hs: []const parser.Header, host_out: ?*?[]const u8, expect_out: ?*bool) parser.Error!Common {
    var c: Common = .{};
    for (hs) |h| switch (h.id) {
        .content_length => {
            if (c.cl != null) return error.BadRequest; // duplicate (even if equal)
            c.cl = parseContentLength(h.value) orelse return error.BadRequest;
        },
        .transfer_encoding => {
            if (c.te_seen) return error.BadRequest; // multiple TE fields
            c.te_seen = true;
            if (std.ascii.eqlIgnoreCase(h.value, "chunked")) {
                c.te_chunked = true;
            } else {
                c.te_other = true;
            }
        },
        .connection => try parseConnection(&c.conn, h.value),
        .host => if (host_out) |ho| {
            if (ho.* != null) return error.BadRequest; // duplicate Host
            if (!validHost(h.value)) return error.BadRequest;
            ho.* = h.value;
        },
        .expect => if (expect_out) |eo| {
            if (std.ascii.eqlIgnoreCase(h.value, "100-continue")) eo.* = true else return error.NotImplemented;
        },
        else => {},
    };
    return c;
}

pub fn analyzeRequest(req: *const parser.Request) parser.Error!RequestInfo {
    var host: ?[]const u8 = null;
    var expect = false;
    const c = try scanCommon(req.headers, &host, &expect);
    if (host == null) return error.BadRequest;
    if (req.method == .CONNECT) return error.NotImplemented;

    // Request target: origin-form, or asterisk-form for OPTIONS.
    if (req.target[0] != '/') {
        if (!(req.method == .OPTIONS and req.target.len == 1 and req.target[0] == '*')) return error.BadRequest;
    }

    var framing: Framing = .none;
    if (c.te_seen) {
        if (c.cl != null) return error.BadRequest;
        if (req.version == .http10) return error.BadRequest;
        if (c.te_other) return error.NotImplemented;
        framing = .chunked;
    } else if (c.cl) |n| {
        framing = if (n == 0) .none else .{ .length = n };
    }

    const keep_alive = switch (req.version) {
        .http11 => !c.conn.close,
        .http10 => c.conn.keep_alive and !c.conn.close,
    };
    return .{ .framing = framing, .host = host.?, .keep_alive = keep_alive, .expect_continue = expect, .conn = c.conn };
}

/// `request_method` decides whether a body may follow (HEAD never has one).
pub fn analyzeResponse(resp: *const parser.Response, request_method: parser.Method) parser.Error!ResponseInfo {
    const c = try scanCommon(resp.headers, null, null);
    var keep_alive = switch (resp.version) {
        .http11 => !c.conn.close,
        .http10 => c.conn.keep_alive and !c.conn.close,
    };
    const no_body = request_method == .HEAD or (resp.status >= 100 and resp.status < 200) or resp.status == 204 or resp.status == 304;
    var framing: Framing = undefined;
    if (no_body) {
        framing = .none;
    } else if (c.te_seen) {
        if (c.cl != null) return error.BadRequest;
        if (c.te_other) return error.BadRequest;
        framing = .chunked;
    } else if (c.cl) |n| {
        framing = if (n == 0) .none else .{ .length = n };
    } else {
        framing = .close_delimited;
        keep_alive = false;
    }
    return .{ .framing = framing, .keep_alive = keep_alive, .conn = c.conn };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn tryReq(s: []const u8) parser.Error!RequestInfo {
    var hs: [parser.max_headers]parser.Header = undefined;
    const r = try parser.parseRequest(s, &hs);
    return analyzeRequest(&r);
}

test "framing: content-length" {
    const i = try tryReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n");
    try testing.expectEqual(@as(u64, 5), i.framing.length);
    try testing.expect(i.keep_alive);
}

test "framing: chunked" {
    const i = try tryReq("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
    try testing.expect(i.framing == .chunked);
}

test "smuggling: CL + TE rejected" {
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"));
}

test "smuggling: duplicate or conflicting CL rejected" {
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x5\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: \r\n\r\n"));
}

test "smuggling: only a final chunked TE" {
    try testing.expectError(error.NotImplemented, tryReq("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n"));
    try testing.expectError(error.NotImplemented, tryReq("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"));
    try testing.expectError(error.NotImplemented, tryReq("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked \x0b\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("POST / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"));
}

test "host rules" {
    try testing.expectError(error.BadRequest, tryReq("GET / HTTP/1.1\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("GET / HTTP/1.1\r\nHost: a b\r\n\r\n"));
    try testing.expectError(error.BadRequest, tryReq("GET / HTTP/1.1\r\nHost: a/b\r\n\r\n"));
    _ = try tryReq("GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n");
}

test "target forms" {
    try testing.expectError(error.BadRequest, tryReq("GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n"));
    try testing.expectError(error.NotImplemented, tryReq("CONNECT a:443 HTTP/1.1\r\nHost: a\r\n\r\n"));
    _ = try tryReq("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n");
    try testing.expectError(error.BadRequest, tryReq("GET * HTTP/1.1\r\nHost: a\r\n\r\n"));
}

test "keep-alive semantics" {
    try testing.expect(!(try tryReq("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")).keep_alive);
    try testing.expect(!(try tryReq("GET / HTTP/1.0\r\nHost: a\r\n\r\n")).keep_alive);
    try testing.expect((try tryReq("GET / HTTP/1.0\r\nHost: a\r\nConnection: Keep-Alive\r\n\r\n")).keep_alive);
    const i = try tryReq("GET / HTTP/1.1\r\nHost: a\r\nConnection: X-Secret, keep-alive\r\n\r\n");
    try testing.expect(i.conn.nominates("x-secret"));
}

test "response framing" {
    var hs: [parser.max_headers]parser.Header = undefined;
    const r1 = try parser.parseResponse("HTTP/1.1 200 OK\r\n\r\n", &hs);
    const a1 = try analyzeResponse(&r1, .GET);
    try testing.expect(a1.framing == .close_delimited);
    try testing.expect(!a1.keep_alive);
    const r2 = try parser.parseResponse("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", &hs);
    try testing.expect((try analyzeResponse(&r2, .HEAD)).framing == .none);
    const r3 = try parser.parseResponse("HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", &hs);
    try testing.expect((try analyzeResponse(&r3, .GET)).framing == .none);
    const r4 = try parser.parseResponse("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", &hs);
    try testing.expectError(error.BadRequest, analyzeResponse(&r4, .GET));
}
