//! Reads the server name (SNI) from a TLS ClientHello without terminating
//! TLS, for SNI-based passthrough routing. The ClientHello may span several
//! TLS records (large post-quantum key shares do); its fragments are joined
//! in a caller-provided scratch buffer. Allocation-free; fuzzed.

const std = @import("std");

/// Largest ClientHello accepted (handshake message bytes).
pub const max_hello = 16 * 1024;

pub const Result = union(enum) {
    /// Not enough bytes yet.
    incomplete,
    /// Not a TLS ClientHello (or malformed).
    invalid,
    /// A complete ClientHello; the SNI host name, or null without one.
    done: ?[]const u8,
};

pub fn parse(buf: []const u8, scratch: *[max_hello]u8) Result {
    // Join handshake-record fragments until the message is complete.
    var have: usize = 0;
    var need: ?usize = null;
    var off: usize = 0;
    while (true) {
        if (buf.len - off < 5) return if (buf.len >= 5 or off > 0 or isPrefix(buf)) .incomplete else .invalid;
        const rec = buf[off..];
        if (rec[0] != 0x16 or rec[1] != 3 or rec[2] > 4) return .invalid;
        const rlen = std.mem.readInt(u16, rec[3..5], .big);
        if (rlen == 0 or rlen > 16384 + 256) return .invalid;
        if (rec.len < 5 + @as(usize, rlen)) return .incomplete;
        const frag = rec[5 .. 5 + rlen];
        if (have + frag.len > scratch.len) return .invalid;
        @memcpy(scratch[have .. have + frag.len], frag);
        have += frag.len;
        off += 5 + rlen;
        if (need == null and have >= 4) {
            if (scratch[0] != 1) return .invalid; // not a ClientHello
            const n = std.mem.readInt(u24, scratch[1..4], .big);
            if (n + 4 > scratch.len) return .invalid;
            need = n + 4;
        }
        if (need) |n| if (have >= n) return parseHello(scratch[4..n]);
    }
}

/// A short first read that still looks like the start of a TLS record.
fn isPrefix(buf: []const u8) bool {
    if (buf.len >= 1 and buf[0] != 0x16) return false;
    if (buf.len >= 2 and buf[1] != 3) return false;
    return true;
}

const Reader = struct {
    b: []const u8,
    i: usize = 0,

    fn take(r: *Reader, n: usize) ?[]const u8 {
        if (r.b.len - r.i < n) return null;
        defer r.i += n;
        return r.b[r.i .. r.i + n];
    }
    fn int(r: *Reader, comptime T: type) ?T {
        const s = r.take(@sizeOf(T)) orelse return null;
        return std.mem.readInt(T, s[0..@sizeOf(T)], .big);
    }
    fn vec(r: *Reader, comptime L: type) ?[]const u8 {
        const n = r.int(L) orelse return null;
        return r.take(n);
    }
};

fn parseHello(body: []const u8) Result {
    var r: Reader = .{ .b = body };
    _ = r.take(2 + 32) orelse return .invalid; // legacy_version, random
    _ = r.vec(u8) orelse return .invalid; // legacy_session_id
    _ = r.vec(u16) orelse return .invalid; // cipher_suites
    _ = r.vec(u8) orelse return .invalid; // legacy_compression_methods
    if (r.i == body.len) return .{ .done = null }; // no extensions (TLS 1.0-style)
    const exts = r.vec(u16) orelse return .invalid;
    var e: Reader = .{ .b = exts };
    while (e.i < exts.len) {
        const typ = e.int(u16) orelse return .invalid;
        const data = e.vec(u16) orelse return .invalid;
        if (typ != 0) continue;
        // server_name: ServerNameList
        var s: Reader = .{ .b = data };
        const list = s.vec(u16) orelse return .invalid;
        var l: Reader = .{ .b = list };
        while (l.i < list.len) {
            const name_type = l.int(u8) orelse return .invalid;
            const name = l.vec(u16) orelse return .invalid;
            if (name_type == 0) return if (validHost(name)) .{ .done = name } else .invalid;
        }
        return .{ .done = null };
    }
    return .{ .done = null };
}

fn validHost(n: []const u8) bool {
    if (n.len == 0 or n.len > 253) return false;
    for (n) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '.', '_' => {},
        else => return false,
    };
    return true;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {
    const a: [n]u8 = @splat(c);
    return &a;
}

/// Builds a ClientHello record (or records, split at `split`).
fn hello(out: []u8, sni: ?[]const u8, split: ?usize) []const u8 {
    var body: [512]u8 = undefined;
    var n: usize = 0;
    const put = struct {
        fn f(b: []u8, i: *usize, s: []const u8) void {
            @memcpy(b[i.* .. i.* + s.len], s);
            i.* += s.len;
        }
    }.f;
    put(&body, &n, "\x03\x03" ++ rep("R"[0], 32) ++ "\x00" ++ "\x00\x02\x13\x01" ++ "\x01\x00");
    var ext: [300]u8 = undefined;
    var en: usize = 0;
    put(&ext, &en, "\x00\x2b\x00\x03\x02\x03\x04"); // supported_versions first
    if (sni) |h| {
        var hb: [2]u8 = undefined;
        put(&ext, &en, "\x00\x00");
        std.mem.writeInt(u16, &hb, @intCast(h.len + 5), .big);
        put(&ext, &en, &hb);
        std.mem.writeInt(u16, &hb, @intCast(h.len + 3), .big);
        put(&ext, &en, &hb);
        put(&ext, &en, "\x00");
        std.mem.writeInt(u16, &hb, @intCast(h.len), .big);
        put(&ext, &en, &hb);
        put(&ext, &en, h);
    }
    var lb: [2]u8 = undefined;
    std.mem.writeInt(u16, &lb, @intCast(en), .big);
    put(&body, &n, &lb);
    put(&body, &n, ext[0..en]);

    var msg: [600]u8 = undefined;
    msg[0] = 1;
    std.mem.writeInt(u24, msg[1..4], @intCast(n), .big);
    @memcpy(msg[4 .. 4 + n], body[0..n]);
    const m = msg[0 .. 4 + n];
    const parts: []const []const u8 = if (split) |s| &.{ m[0..s], m[s..] } else &.{m};
    var o: usize = 0;
    for (parts) |p| {
        out[o] = 0x16;
        out[o + 1] = 3;
        out[o + 2] = 1;
        std.mem.writeInt(u16, out[o + 3 ..][0..2], @intCast(p.len), .big);
        @memcpy(out[o + 5 .. o + 5 + p.len], p);
        o += 5 + p.len;
    }
    return out[0..o];
}

test "sni from one record, every prefix incomplete" {
    var buf: [1024]u8 = undefined;
    var scratch: [max_hello]u8 = undefined;
    const h = hello(&buf, "api.example.com", null);
    try testing.expectEqualStrings("api.example.com", parse(h, &scratch).done.?);
    for (0..h.len) |i| try testing.expect(parse(h[0..i], &scratch) == .incomplete);
}

test "sni split across records" {
    var buf: [1024]u8 = undefined;
    var scratch: [max_hello]u8 = undefined;
    const h = hello(&buf, "a.test", 3);
    try testing.expectEqualStrings("a.test", parse(h, &scratch).done.?);
    for (0..h.len) |i| try testing.expect(parse(h[0..i], &scratch) == .incomplete);
}

test "no sni, not tls, bad names" {
    var buf: [1024]u8 = undefined;
    var scratch: [max_hello]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), parse(hello(&buf, null, null), &scratch).done);
    try testing.expect(parse("GET / HTTP/1.1\r\n", &scratch) == .invalid);
    try testing.expect(parse("\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00", &scratch) == .invalid); // ServerHello
    try testing.expect(parse(hello(&buf, "bad host", null), &scratch) == .invalid);
}
