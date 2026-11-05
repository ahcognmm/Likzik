//! HTTP/1.1 request and response head parser.
//!
//! * `HeadScanner` is resumable: it remembers where it stopped and never
//!   rescans bytes it has already looked at. It finds the end of a head.
//! * `parseRequest` / `parseResponse` then validate a complete head in one
//!   pass. They allocate nothing: header names and values are slices into
//!   the caller's buffer.
//!
//! Strictness (see smuggling_rules.zig for the framing rules):
//! CRLF line endings only, no obs-fold, no whitespace before the colon,
//! no bare CR, no control characters in names or values.

const std = @import("std");
const chars = @import("chars.zig");
const headers = @import("headers.zig");

pub const max_headers = 100;

pub const Header = struct {
    name: []const u8,
    value: []const u8,
    id: headers.Id,
};

pub const Error = error{
    /// 400
    BadRequest,
    /// 431
    TooManyHeaders,
    /// 431 (head larger than the configured limit)
    HeadTooLarge,
    /// 505
    UnsupportedVersion,
    /// 501
    NotImplemented,
};

pub fn statusFor(err: Error) u16 {
    return switch (err) {
        error.BadRequest => 400,
        error.TooManyHeaders, error.HeadTooLarge => 431,
        error.UnsupportedVersion => 505,
        error.NotImplemented => 501,
    };
}

pub const Version = enum { http10, http11 };

pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
    other,

    pub fn parse(s: []const u8) Method {
        const info = @typeInfo(Method).@"enum";
        inline for (info.field_names, info.field_values) |fname, value| {
            if (std.mem.eql(u8, s, fname)) return @enumFromInt(value);
        }
        return .other;
    }

    /// RFC 9110 9.2.2
    pub fn idempotent(m: Method) bool {
        return switch (m) {
            .GET, .HEAD, .PUT, .DELETE, .OPTIONS, .TRACE => true,
            else => false,
        };
    }
};

/// Finds the end of an HTTP head (the empty line) incrementally.
pub const HeadScanner = struct {
    /// Next byte index to look at.
    pos: usize = 0,
    /// Start of the line being scanned.
    line_start: usize = 0,
    /// Leading empty lines (CRLF) skipped before the start line, RFC 9112 2.2.
    skip: usize = 0,

    pub fn reset(self: *HeadScanner) void {
        self.* = .{};
    }

    pub const Result = struct {
        /// Offset of the first byte of the head (after skipped CRLFs).
        start: usize,
        /// Offset one past the terminating empty line.
        end: usize,
    };

    /// `buf` must contain everything previously fed plus any new bytes.
    pub fn feed(self: *HeadScanner, buf: []const u8) ?Result {
        while (chars.findLf(buf, self.pos)) |lf| {
            self.pos = lf + 1;
            const line = buf[self.line_start..lf];
            const empty = line.len == 0 or (line.len == 1 and line[0] == '\r');
            if (empty) {
                if (self.line_start == self.skip) {
                    // Empty line before any start line: skip it (at most a few).
                    if (self.skip >= 8) return .{ .start = self.skip, .end = self.pos };
                    self.skip = self.pos;
                    self.line_start = self.pos;
                    continue;
                }
                return .{ .start = self.skip, .end = self.pos };
            }
            self.line_start = self.pos;
        }
        self.pos = buf.len;
        return null;
    }
};

pub const Request = struct {
    method: Method,
    method_raw: []const u8,
    target: []const u8,
    version: Version,
    headers: []Header,
};

pub const Response = struct {
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []Header,
};

fn expectCrlf(buf: []const u8, i: usize) Error!usize {
    if (i + 1 < buf.len and buf[i] == '\r' and buf[i + 1] == '\n') return i + 2;
    return error.BadRequest;
}

fn parseVersion(s: []const u8) Error!Version {
    if (s.len != 8) return error.BadRequest;
    if (!std.mem.eql(u8, s[0..5], "HTTP/") or s[6] != '.' or !chars.isDigit(s[5]) or !chars.isDigit(s[7]))
        return error.BadRequest;
    if (s[5] == '1' and s[7] == '1') return .http11;
    if (s[5] == '1' and s[7] == '0') return .http10;
    return error.UnsupportedVersion;
}

/// Parses header fields starting at `i` until the empty line. `head` must
/// end with the empty line (as returned by HeadScanner).
fn parseFields(head: []const u8, start: usize, out: []Header) Error![]Header {
    var i = start;
    var n: usize = 0;
    while (true) {
        if (i >= head.len) return error.BadRequest;
        if (head[i] == '\r') {
            _ = try expectCrlf(head, i);
            return out[0..n];
        }
        // obs-fold or leading whitespace.
        if (head[i] == ' ' or head[i] == '\t') return error.BadRequest;
        const name_end = chars.findTokenEnd(head, i);
        if (name_end == i or name_end >= head.len or head[name_end] != ':') return error.BadRequest;
        const name = head[i..name_end];
        var v = name_end + 1;
        while (v < head.len and (head[v] == ' ' or head[v] == '\t')) v += 1;
        const v_end = chars.findFieldValueEnd(head, v);
        if (v_end >= head.len or head[v_end] != '\r') return error.BadRequest; // bare LF or control byte
        var trimmed_end = v_end;
        while (trimmed_end > v and (head[trimmed_end - 1] == ' ' or head[trimmed_end - 1] == '\t')) trimmed_end -= 1;
        if (n == out.len) return error.TooManyHeaders;
        out[n] = .{ .name = name, .value = head[v..trimmed_end], .id = headers.lookup(name) };
        n += 1;
        i = try expectCrlf(head, v_end);
    }
}

/// Parses a complete request head (`head` ends with CRLFCRLF).
pub fn parseRequest(head: []const u8, out: []Header) Error!Request {
    const m_end = chars.findTokenEnd(head, 0);
    if (m_end == 0 or m_end >= head.len or head[m_end] != ' ') return error.BadRequest;
    const t_start = m_end + 1;
    const t_end = chars.findTargetEnd(head, t_start);
    if (t_end == t_start or t_end >= head.len or head[t_end] != ' ') return error.BadRequest;
    const v_start = t_end + 1;
    if (v_start + 10 > head.len) return error.BadRequest;
    const version = try parseVersion(head[v_start .. v_start + 8]);
    const fields_start = try expectCrlf(head, v_start + 8);
    const hs = try parseFields(head, fields_start, out);
    const method_raw = head[0..m_end];
    return .{
        .method = Method.parse(method_raw),
        .method_raw = method_raw,
        .target = head[t_start..t_end],
        .version = version,
        .headers = hs,
    };
}

/// Parses a complete response head from an upstream.
pub fn parseResponse(head: []const u8, out: []Header) Error!Response {
    if (head.len < 14) return error.BadRequest;
    const version = try parseVersion(head[0..8]);
    if (head[8] != ' ') return error.BadRequest;
    const d = head[9..12];
    for (d) |c| if (!chars.isDigit(c)) return error.BadRequest;
    const status: u16 = @as(u16, d[0] - '0') * 100 + @as(u16, d[1] - '0') * 10 + (d[2] - '0');
    if (status < 100) return error.BadRequest;
    var i: usize = 12;
    var reason: []const u8 = "";
    if (head[i] == ' ') {
        i += 1;
        const r_end = chars.findFieldValueEnd(head, i);
        reason = head[i..r_end];
        i = r_end;
    }
    const fields_start = try expectCrlf(head, i);
    const hs = try parseFields(head, fields_start, out);
    return .{ .version = version, .status = status, .reason = reason, .headers = hs };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn scanAll(s: []const u8) ?HeadScanner.Result {
    var sc: HeadScanner = .{};
    return sc.feed(s);
}

test "scanner finds head end incrementally" {
    const req = "GET / HTTP/1.1\r\nHost: a\r\n\r\nBODY";
    var sc: HeadScanner = .{};
    var r: ?HeadScanner.Result = null;
    for (1..req.len + 1) |n| {
        r = sc.feed(req[0..n]);
        if (r != null) {
            try testing.expectEqual(@as(usize, 27), n);
            break;
        }
    }
    try testing.expectEqual(@as(usize, 27), r.?.end);
    try testing.expectEqual(@as(usize, 0), r.?.start);
}

test "scanner skips leading CRLF" {
    const r = scanAll("\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n").?;
    try testing.expectEqual(@as(usize, 4), r.start);
}

test "parse simple request" {
    var hs: [max_headers]Header = undefined;
    const s = "GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t \r\nX-A:b\r\n\r\n";
    const r = try parseRequest(s, &hs);
    try testing.expectEqual(Method.GET, r.method);
    try testing.expectEqualStrings("/index.html?x=1", r.target);
    try testing.expectEqual(Version.http11, r.version);
    try testing.expectEqual(@as(usize, 3), r.headers.len);
    try testing.expectEqual(headers.Id.host, r.headers[0].id);
    try testing.expectEqualStrings("example.com", r.headers[0].value);
    try testing.expectEqualStrings("t", r.headers[1].value);
    try testing.expectEqualStrings("b", r.headers[2].value);
}

test "reject malformed requests" {
    var hs: [max_headers]Header = undefined;
    const bad = [_][]const u8{
        "GET / HTTP/1.1\r\nHost : a\r\n\r\n", // whitespace before colon
        "GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n", // obs-fold
        "GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n", // bare CR
        "GET / HTTP/1.1\nHost: a\r\n\r\n", // bare LF in start line
        "GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n", // bare LF in field
        "GET / HTTP/1.1\r\nHo\x01st: a\r\n\r\n", // ctl in name
        "GET / HTTP/1.1\r\nX: a\x00b\r\n\r\n", // NUL in value
        "GET /a b HTTP/1.1\r\nHost: a\r\n\r\n", // space in target
        "GET  / HTTP/1.1\r\nHost: a\r\n\r\n", // double space
        "G@T / HTTP/1.1\r\nHost: a\r\n\r\n", // bad method token
        "GET / HTTP/1.1 \r\nHost: a\r\n\r\n", // trailing junk
        "GET / http/1.1\r\nHost: a\r\n\r\n", // lowercase version
        "GET / HTTP/1.1\r\n: a\r\n\r\n", // empty name
        "GET / HTTP/1.1\r\nX: \x7f\r\n\r\n", // DEL
    };
    for (bad) |b| {
        if (parseRequest(b, &hs)) |_| {
            std.debug.print("accepted: {s}\n", .{b});
            return error.TestUnexpectedResult;
        } else |e| try testing.expectEqual(error.BadRequest, e);
    }
    try testing.expectError(error.UnsupportedVersion, parseRequest("GET / HTTP/2.0\r\nHost: a\r\n\r\n", &hs));
}

test "too many headers" {
    var hs: [2]Header = undefined;
    try testing.expectError(error.TooManyHeaders, parseRequest("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", &hs));
}

test "parse response" {
    var hs: [max_headers]Header = undefined;
    const r = try parseResponse("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", &hs);
    try testing.expectEqual(@as(u16, 404), r.status);
    try testing.expectEqualStrings("Not Found", r.reason);
    try testing.expectEqual(headers.Id.content_length, r.headers[0].id);
    const r2 = try parseResponse("HTTP/1.1 204\r\n\r\n", &hs);
    try testing.expectEqual(@as(u16, 204), r2.status);
    try testing.expectError(error.BadRequest, parseResponse("HTTP/1.1 20 OK\r\n\r\n", &hs));
}
