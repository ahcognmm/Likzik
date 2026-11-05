//! Re-serialization of request and response heads.
//!
//! The proxy never forwards raw head bytes. It writes a fresh head from the
//! parsed fields, which drops anything the parser did not understand,
//! strips hop-by-hop headers and anything named in `Connection`, and emits
//! exactly one framing header.

const std = @import("std");
const parser = @import("parser.zig");
const headers = @import("headers.zig");
const rules = @import("smuggling_rules.zig");

pub const Error = error{NoSpace};

pub const Out = struct {
    buf: []u8,
    len: usize = 0,

    pub fn put(self: *Out, s: []const u8) Error!void {
        if (self.len + s.len > self.buf.len) return error.NoSpace;
        @memcpy(self.buf[self.len .. self.len + s.len], s);
        self.len += s.len;
    }

    pub fn putInt(self: *Out, v: u64) Error!void {
        var tmp: [20]u8 = undefined;
        const n = std.fmt.printInt(&tmp, v, 10, .lower, .{});
        try self.put(tmp[0..n]);
    }

    pub fn header(self: *Out, name: []const u8, value: []const u8) Error!void {
        try self.put(name);
        try self.put(": ");
        try self.put(value);
        try self.put("\r\n");
    }

    pub fn slice(self: *const Out) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const ForwardCtx = struct {
    /// Textual client address for X-Forwarded-For.
    client_ip: []const u8,
    /// "http" or "https".
    proto: []const u8,
    /// Trust (append to) the client's own X-Forwarded-* headers.
    trusted_client: bool = false,
    /// Replaces the target when a route rewrites the path.
    target: ?[]const u8 = null,
};

/// Writes the upstream request head.
pub fn writeRequest(out: *Out, req: *const parser.Request, info: *const rules.RequestInfo, ctx: ForwardCtx) Error!void {
    try out.put(req.method_raw);
    try out.put(" ");
    try out.put(ctx.target orelse req.target);
    try out.put(" HTTP/1.1\r\n");
    var xff_prev: ?[]const u8 = null;
    for (req.headers) |h| {
        if (headers.isHopByHop(h.id)) continue;
        switch (h.id) {
            .content_length => continue,
            .x_forwarded_for => {
                if (ctx.trusted_client) xff_prev = h.value;
                continue;
            },
            .x_forwarded_proto => if (!ctx.trusted_client) continue,
            else => {},
        }
        if (h.id == .other and info.conn.nominates(h.name)) continue;
        try out.header(h.name, h.value);
    }
    switch (info.framing) {
        .length => |n| {
            try out.put("Content-Length: ");
            try out.putInt(n);
            try out.put("\r\n");
        },
        .chunked => try out.put("Transfer-Encoding: chunked\r\n"),
        .none => if (req.method == .POST or req.method == .PUT or req.method == .PATCH) try out.put("Content-Length: 0\r\n"),
        .close_delimited => unreachable,
    }
    try out.put("X-Forwarded-For: ");
    if (xff_prev) |p| {
        try out.put(p);
        try out.put(", ");
    }
    try out.put(ctx.client_ip);
    try out.put("\r\n");
    if (!(ctx.trusted_client and hasHeader(req.headers, .x_forwarded_proto))) {
        try out.header("X-Forwarded-Proto", ctx.proto);
    }
    try out.put("\r\n");
}

fn hasHeader(hs: []const parser.Header, id: headers.Id) bool {
    for (hs) |h| if (h.id == id) return true;
    return false;
}

pub const ResponseMode = struct {
    /// Downstream connection stays open after this response.
    keep_alive: bool,
    /// Downstream speaks HTTP/1.0.
    client_http10: bool,
    /// Body is de-chunked for the client (HTTP/1.0 client, chunked upstream).
    dechunk: bool,
};

/// Writes the downstream response head.
pub fn writeResponse(out: *Out, resp: *const parser.Response, info: *const rules.ResponseInfo, mode: ResponseMode) Error!void {
    try out.put(if (mode.client_http10) "HTTP/1.0 " else "HTTP/1.1 ");
    var code: [3]u8 = undefined;
    code[0] = @intCast('0' + resp.status / 100);
    code[1] = @intCast('0' + (resp.status / 10) % 10);
    code[2] = @intCast('0' + resp.status % 10);
    try out.put(&code);
    try out.put(" ");
    try out.put(resp.reason);
    try out.put("\r\n");
    for (resp.headers) |h| {
        if (headers.isHopByHop(h.id)) continue;
        if (h.id == .other and info.conn.nominates(h.name)) continue;
        if (h.id == .content_length and mode.dechunk) continue;
        try out.header(h.name, h.value);
    }
    if (info.framing == .chunked and !mode.dechunk) try out.put("Transfer-Encoding: chunked\r\n");
    if (!mode.keep_alive) {
        try out.put("Connection: close\r\n");
    } else if (mode.client_http10) {
        try out.put("Connection: keep-alive\r\n");
    }
    try out.put("\r\n");
}

pub fn reasonPhrase(status: u16) []const u8 {
    return switch (status) {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        else => "Unknown",
    };
}

/// Writes a complete locally generated response.
pub fn writeLocal(out: *Out, status: u16, keep_alive: bool, body: []const u8) Error!void {
    try out.put("HTTP/1.1 ");
    try out.putInt(status);
    try out.put(" ");
    try out.put(reasonPhrase(status));
    try out.put("\r\nServer: likzik\r\nContent-Type: text/plain\r\nContent-Length: ");
    try out.putInt(body.len);
    try out.put(if (keep_alive) "\r\n\r\n" else "\r\nConnection: close\r\n\r\n");
    try out.put(body);
}

const testing = std.testing;

test "request re-serialization strips hop-by-hop and connection-named headers" {
    var hs: [parser.max_headers]parser.Header = undefined;
    const raw = "POST /x HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, X-Secret\r\nX-Secret: s\r\nKeep-Alive: 5\r\nTE: trailers\r\nX-Forwarded-For: 6.6.6.6\r\nTransfer-Encoding: chunked\r\nX-Ok: 1\r\n\r\n";
    const r = try parser.parseRequest(raw, &hs);
    const info = try rules.analyzeRequest(&r);
    var buf: [1024]u8 = undefined;
    var out: Out = .{ .buf = &buf };
    try writeRequest(&out, &r, &info, .{ .client_ip = "10.0.0.1", .proto = "http" });
    try testing.expectEqualStrings(
        "POST /x HTTP/1.1\r\nHost: h\r\nX-Ok: 1\r\nTransfer-Encoding: chunked\r\nX-Forwarded-For: 10.0.0.1\r\nX-Forwarded-Proto: http\r\n\r\n",
        out.slice(),
    );
}

test "trusted client XFF is appended" {
    var hs: [parser.max_headers]parser.Header = undefined;
    const r = try parser.parseRequest("GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-For: 1.1.1.1\r\nX-Forwarded-Proto: https\r\n\r\n", &hs);
    const info = try rules.analyzeRequest(&r);
    var buf: [1024]u8 = undefined;
    var out: Out = .{ .buf = &buf };
    try writeRequest(&out, &r, &info, .{ .client_ip = "10.0.0.1", .proto = "http", .trusted_client = true });
    try testing.expectEqualStrings(
        "GET / HTTP/1.1\r\nHost: h\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 1.1.1.1, 10.0.0.1\r\n\r\n",
        out.slice(),
    );
}

test "response serialization" {
    var hs: [parser.max_headers]parser.Header = undefined;
    const r = try parser.parseResponse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: x-a\r\nX-A: 1\r\nX-B: 2\r\n\r\n", &hs);
    const info = try rules.analyzeResponse(&r, .GET);
    var buf: [1024]u8 = undefined;
    var out: Out = .{ .buf = &buf };
    try writeResponse(&out, &r, &info, .{ .keep_alive = true, .client_http10 = false, .dechunk = false });
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nX-B: 2\r\nTransfer-Encoding: chunked\r\n\r\n", out.slice());
}

test "local response" {
    var buf: [256]u8 = undefined;
    var out: Out = .{ .buf = &buf };
    try writeLocal(&out, 502, false, "bad gateway\n");
    try testing.expect(std.mem.startsWith(u8, out.slice(), "HTTP/1.1 502 Bad Gateway\r\n"));
    try testing.expect(std.mem.endsWith(u8, out.slice(), "Connection: close\r\n\r\nbad gateway\n"));
}
