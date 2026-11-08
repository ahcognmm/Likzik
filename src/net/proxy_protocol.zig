//! HAProxy PROXY protocol, versions 1 (text) and 2 (binary): parse the
//! header a load balancer puts in front of a connection, and write one in
//! front of an upstream connection. Allocation-free; fuzzed in tests/fuzz.
//! Spec: https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt

const std = @import("std");
const linux = std.os.linux;
const Address = @import("addr.zig").Address;

pub const Version = enum { v1, v2 };

/// Largest header accepted: v1 is at most 107 bytes; v2 allows TLVs (AWS,
/// GCP and Azure add a few), capped here.
pub const max_len = 1024;

const v2_sig = "\r\n\r\n\x00\r\nQUIT\n";

pub const Header = struct {
    /// Bytes to strip from the start of the stream.
    len: usize,
    /// Original client and destination; null for LOCAL (health checks)
    /// and UNKNOWN connections, which keep the real peer address.
    src: ?Address = null,
    dst: ?Address = null,
};

pub const Result = union(enum) {
    /// Not enough bytes yet.
    incomplete,
    invalid,
    done: Header,
};

pub fn parse(buf: []const u8) Result {
    if (buf.len == 0) return .incomplete;
    if (buf[0] == 'P') return parseV1(buf);
    if (buf[0] == '\r') return parseV2(buf);
    return .invalid;
}

fn parseV1(buf: []const u8) Result {
    const prefix = "PROXY ";
    const n = @min(buf.len, prefix.len);
    if (!std.mem.eql(u8, buf[0..n], prefix[0..n])) return .invalid;
    const end = std.mem.indexOf(u8, buf[0..@min(buf.len, 107)], "\r\n") orelse
        return if (buf.len >= 107) .invalid else .incomplete;
    const line = buf[prefix.len..end];
    const hlen = end + 2;
    var it = std.mem.splitScalar(u8, line, ' ');
    const proto = it.next() orelse return .invalid;
    if (std.mem.eql(u8, proto, "UNKNOWN")) return .{ .done = .{ .len = hlen } };
    const v6 = std.mem.eql(u8, proto, "TCP6");
    if (!v6 and !std.mem.eql(u8, proto, "TCP4")) return .invalid;
    const sip = it.next() orelse return .invalid;
    const dip = it.next() orelse return .invalid;
    const sport = it.next() orelse return .invalid;
    const dport = it.next() orelse return .invalid;
    if (it.next() != null) return .invalid;
    const src = ipPort(v6, sip, sport) orelse return .invalid;
    const dst = ipPort(v6, dip, dport) orelse return .invalid;
    return .{ .done = .{ .len = hlen, .src = src, .dst = dst } };
}

fn ipPort(v6: bool, ip: []const u8, port: []const u8) ?Address {
    if (port.len == 0 or port.len > 5 or (port.len > 1 and port[0] == '0')) return null;
    var b: [64]u8 = undefined;
    const s = (if (v6)
        std.fmt.bufPrint(&b, "[{s}]:{s}", .{ ip, port })
    else
        std.fmt.bufPrint(&b, "{s}:{s}", .{ ip, port })) catch return null;
    const a = Address.parse(s) catch return null;
    if ((a.family() == linux.AF.INET6) != v6) return null;
    return a;
}

fn parseV2(buf: []const u8) Result {
    const n = @min(buf.len, v2_sig.len);
    if (!std.mem.eql(u8, buf[0..n], v2_sig[0..n])) return .invalid;
    if (buf.len < 16) return .incomplete;
    const ver_cmd = buf[12];
    if (ver_cmd >> 4 != 2) return .invalid;
    const cmd = ver_cmd & 0x0f;
    if (cmd > 1) return .invalid;
    const fam = buf[13];
    const body_len = std.mem.readInt(u16, buf[14..16], .big);
    const total = 16 + @as(usize, body_len);
    if (total > max_len) return .invalid;
    if (buf.len < total) return .incomplete;
    const body = buf[16..total];
    // LOCAL: the proxy's own connection (health check); keep the peer.
    if (cmd == 0) return .{ .done = .{ .len = total } };
    switch (fam) {
        0x11, 0x12 => { // TCP or UDP over IPv4
            if (body.len < 12) return .invalid;
            var src: Address = .{ .in4 = .{ .port = 0, .addr = 0 } };
            var dst = src;
            src.in4.addr = @bitCast(body[0..4].*);
            dst.in4.addr = @bitCast(body[4..8].*);
            src.in4.port = @bitCast(body[8..10].*);
            dst.in4.port = @bitCast(body[10..12].*);
            return .{ .done = .{ .len = total, .src = src, .dst = dst } };
        },
        0x21, 0x22 => { // over IPv6
            if (body.len < 36) return .invalid;
            var src: Address = .{ .in6 = .{ .port = 0, .flowinfo = 0, .addr = undefined, .scope_id = 0 } };
            var dst = src;
            src.in6.addr = body[0..16].*;
            dst.in6.addr = body[16..32].*;
            src.in6.port = @bitCast(body[32..34].*);
            dst.in6.port = @bitCast(body[34..36].*);
            return .{ .done = .{ .len = total, .src = src, .dst = dst } };
        },
        // UNSPEC or unix sockets: valid, but no usable address.
        0x00, 0x31, 0x32 => return .{ .done = .{ .len = total } },
        else => return .invalid,
    }
}

/// Writes a header for a connection from `src` to `dst` (both the same
/// family). Returns the bytes written.
pub fn write(ver: Version, src: *const Address, dst: *const Address, out: *[max_len]u8) []const u8 {
    const v6 = src.family() == linux.AF.INET6;
    if (v6 != (dst.family() == linux.AF.INET6)) return writeUnknown(ver, out);
    switch (ver) {
        .v1 => {
            var sb: [64]u8 = undefined;
            var db: [64]u8 = undefined;
            return std.fmt.bufPrint(out, "PROXY {s} {s} {s} {d} {d}\r\n", .{
                if (v6) "TCP6" else "TCP4", src.formatIp(&sb), dst.formatIp(&db), src.port(), dst.port(),
            }) catch unreachable;
        },
        .v2 => {
            @memcpy(out[0..12], v2_sig);
            out[12] = 0x21; // version 2, PROXY
            if (v6) {
                out[13] = 0x21;
                std.mem.writeInt(u16, out[14..16], 36, .big);
                out[16..32].* = src.in6.addr;
                out[32..48].* = dst.in6.addr;
                out[48..50].* = @bitCast(src.in6.port);
                out[50..52].* = @bitCast(dst.in6.port);
                return out[0..52];
            }
            out[13] = 0x11;
            std.mem.writeInt(u16, out[14..16], 12, .big);
            out[16..20].* = @bitCast(src.in4.addr);
            out[20..24].* = @bitCast(dst.in4.addr);
            out[24..26].* = @bitCast(src.in4.port);
            out[26..28].* = @bitCast(dst.in4.port);
            return out[0..28];
        },
    }
}

fn writeUnknown(ver: Version, out: *[max_len]u8) []const u8 {
    switch (ver) {
        .v1 => {
            const s = "PROXY UNKNOWN\r\n";
            @memcpy(out[0..s.len], s);
            return out[0..s.len];
        },
        .v2 => {
            @memcpy(out[0..12], v2_sig);
            out[12] = 0x21;
            out[13] = 0x00;
            out[14] = 0;
            out[15] = 0;
            return out[0..16];
        },
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn rep(comptime c: u8, comptime n: usize) *const [n]u8 {
    const a: [n]u8 = @splat(c);
    return &a;
}

fn fmt(a: ?Address, buf: []u8) []const u8 {
    return if (a) |x| x.format(buf) else "none";
}

test "v1" {
    var b: [64]u8 = undefined;
    const r = parse("PROXY TCP4 192.0.2.1 198.51.100.7 56324 443\r\nGET /");
    try testing.expectEqual(@as(usize, 45), r.done.len);
    try testing.expectEqualStrings("192.0.2.1:56324", fmt(r.done.src, &b));
    try testing.expectEqualStrings("198.51.100.7:443", fmt(r.done.dst, &b));
    const r6 = parse("PROXY TCP6 2001:db8::1 2001:db8::2 1 2\r\n");
    try testing.expectEqualStrings("[2001:db8:0:0:0:0:0:1]:1", fmt(r6.done.src, &b));
    try testing.expect(parse("PROXY UNKNOWN ffff::1 x y z\r\n").done.src == null);
    try testing.expect(parse("PROXY TCP4 192.0.2.1") == .incomplete);
    try testing.expect(parse("PRO") == .incomplete);
    try testing.expect(parse("GET / HTTP/1.1\r\n") == .invalid);
    try testing.expect(parse("PROXY TCP4 192.0.2.1 198.51.100.7 56324\r\n") == .invalid);
    try testing.expect(parse("PROXY TCP4 2001:db8::1 198.51.100.7 1 2\r\n") == .invalid);
    try testing.expect(parse("PROXY TCP4 1.2.3.4 1.2.3.4 01 2\r\n") == .invalid);
    try testing.expect(parse("PROXY TCP4 1.2.3.4 1.2.3.4 70000 2\r\n") == .invalid);
    try testing.expect(parse("PROXY " ++ rep("x"[0], 120)) == .invalid);
}

test "v2 round trip, LOCAL, TLVs, truncation" {
    var out: [max_len]u8 = undefined;
    var b: [64]u8 = undefined;
    const src = try Address.parse("192.0.2.1:56324");
    const dst = try Address.parse("198.51.100.7:443");
    const h4 = write(.v2, &src, &dst, &out)[0..28].*; // copy: `out` is reused below
    const h: []const u8 = &h4;
    const r = parse(h);
    try testing.expectEqual(h.len, r.done.len);
    try testing.expectEqualStrings("192.0.2.1:56324", fmt(r.done.src, &b));
    try testing.expectEqualStrings("198.51.100.7:443", fmt(r.done.dst, &b));
    for (0..h.len) |i| try testing.expect(parse(h[0..i]) == .incomplete);

    const s6 = try Address.parse("[2001:db8::1]:1000");
    const d6 = try Address.parse("[2001:db8::2]:443");
    const r6 = parse(write(.v2, &s6, &d6, &out));
    try testing.expectEqualStrings("[2001:db8:0:0:0:0:0:1]:1000", fmt(r6.done.src, &b));

    // LOCAL with a TLV: consumed, no address.
    const local = v2_sig ++ "\x20\x00\x00\x03\x01\x00\x00";
    try testing.expectEqual(@as(usize, 19), parse(local).done.len);
    try testing.expect(parse(local).done.src == null);
    // TLVs after the addresses are skipped.
    var with_tlv: [64]u8 = undefined;
    @memcpy(with_tlv[0..28], h);
    std.mem.writeInt(u16, with_tlv[14..16], 12 + 5, .big);
    @memcpy(with_tlv[28..33], "\x05\x00\x02ab");
    try testing.expectEqual(@as(usize, 33), parse(with_tlv[0..33]).done.len);

    try testing.expect(parse(v2_sig ++ "\x31\x11\x00\x0c" ++ rep("x"[0], 12)) == .invalid); // version 3
    try testing.expect(parse(v2_sig ++ "\x21\x11\x00\x04abcd") == .invalid); // too short for IPv4
    try testing.expect(parse(v2_sig ++ "\x21\x11\xff\xff") == .invalid); // over max_len
    try testing.expect(parse("\r\n\r\nX") == .invalid);
}

test "v1 write" {
    var out: [max_len]u8 = undefined;
    const src = try Address.parse("192.0.2.1:56324");
    const dst = try Address.parse("198.51.100.7:443");
    try testing.expectEqualStrings("PROXY TCP4 192.0.2.1 198.51.100.7 56324 443\r\n", write(.v1, &src, &dst, &out));
    const s6 = try Address.parse("[2001:db8::1]:1");
    try testing.expectEqualStrings("PROXY UNKNOWN\r\n", write(.v1, &s6, &dst, &out));
}
