//! Socket addresses: parse "ip:port" / "[ip6]:port" and format them back.

const std = @import("std");
const linux = std.os.linux;

pub const Address = extern union {
    any: linux.sockaddr,
    in4: linux.sockaddr.in,
    in6: linux.sockaddr.in6,

    pub fn family(self: *const Address) u16 {
        return self.any.family;
    }

    pub fn len(self: *const Address) linux.socklen_t {
        return if (self.any.family == linux.AF.INET6) @sizeOf(linux.sockaddr.in6) else @sizeOf(linux.sockaddr.in);
    }

    pub fn port(self: *const Address) u16 {
        return std.mem.bigToNative(u16, if (self.any.family == linux.AF.INET6) self.in6.port else self.in4.port);
    }

    pub fn eql(a: *const Address, b: *const Address) bool {
        if (a.any.family != b.any.family) return false;
        if (a.any.family == linux.AF.INET6) {
            return a.in6.port == b.in6.port and std.mem.eql(u8, &a.in6.addr, &b.in6.addr);
        }
        return a.in4.port == b.in4.port and a.in4.addr == b.in4.addr;
    }

    pub fn parse(s: []const u8) !Address {
        if (s.len > 0 and s[0] == '[') {
            const close = std.mem.indexOfScalar(u8, s, ']') orelse return error.InvalidAddress;
            if (close + 1 >= s.len or s[close + 1] != ':') return error.InvalidAddress;
            const p = std.fmt.parseInt(u16, s[close + 2 ..], 10) catch return error.InvalidAddress;
            var a: Address = .{ .in6 = .{ .port = std.mem.nativeToBig(u16, p), .flowinfo = 0, .addr = undefined, .scope_id = 0 } };
            a.in6.addr = try parseIp6(s[1..close]);
            return a;
        }
        const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.InvalidAddress;
        const p = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.InvalidAddress;
        const ip = try parseIp4(s[0..colon]);
        return .{ .in4 = .{ .port = std.mem.nativeToBig(u16, p), .addr = ip } };
    }

    /// Formats only the IP part (used for X-Forwarded-For).
    pub fn formatIp(self: *const Address, buf: []u8) []const u8 {
        if (self.any.family == linux.AF.INET6) {
            return formatIp6(&self.in6.addr, buf);
        }
        const b: [4]u8 = @bitCast(self.in4.addr);
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch buf[0..0];
    }

    pub fn format(self: *const Address, buf: []u8) []const u8 {
        var ipbuf: [64]u8 = undefined;
        const ip = self.formatIp(&ipbuf);
        if (self.any.family == linux.AF.INET6) {
            return std.fmt.bufPrint(buf, "[{s}]:{d}", .{ ip, self.port() }) catch buf[0..0];
        }
        return std.fmt.bufPrint(buf, "{s}:{d}", .{ ip, self.port() }) catch buf[0..0];
    }
};

fn parseIp4(s: []const u8) !u32 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i == 4 or part.len == 0 or part.len > 3) return error.InvalidAddress;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidAddress;
    }
    if (i != 4) return error.InvalidAddress;
    return @bitCast(out);
}

fn parseIp6(s: []const u8) ![16]u8 {
    var groups: [8]u16 = [_]u16{0} ** 8;
    var head: [8]u16 = undefined;
    var tail: [8]u16 = undefined;
    var nh: usize = 0;
    var nt: usize = 0;
    var seen_gap = false;
    if (std.mem.indexOf(u8, s, "::")) |gap| {
        seen_gap = true;
        if (std.mem.indexOf(u8, s[gap + 2 ..], "::") != null) return error.InvalidAddress;
        if (gap > 0) nh = try parseGroups(s[0..gap], &head);
        if (gap + 2 < s.len) nt = try parseGroups(s[gap + 2 ..], &tail);
        if (nh + nt > 7) return error.InvalidAddress;
    } else {
        nh = try parseGroups(s, &head);
        if (nh != 8) return error.InvalidAddress;
    }
    for (0..nh) |i| groups[i] = head[i];
    for (0..nt) |i| groups[8 - nt + i] = tail[i];
    var out: [16]u8 = undefined;
    for (groups, 0..) |g, i| {
        out[i * 2] = @intCast(g >> 8);
        out[i * 2 + 1] = @intCast(g & 0xff);
    }
    return out;
}

fn parseGroups(s: []const u8, out: *[8]u16) !usize {
    var it = std.mem.splitScalar(u8, s, ':');
    var n: usize = 0;
    while (it.next()) |g| {
        if (n == 8 or g.len == 0 or g.len > 4) return error.InvalidAddress;
        out[n] = std.fmt.parseInt(u16, g, 16) catch return error.InvalidAddress;
        n += 1;
    }
    return n;
}

fn formatIp6(a: *const [16]u8, buf: []u8) []const u8 {
    var n: usize = 0;
    for (0..8) |i| {
        const g = (@as(u16, a[i * 2]) << 8) | a[i * 2 + 1];
        const s = std.fmt.bufPrint(buf[n..], "{s}{x}", .{ if (i == 0) "" else ":", g }) catch return buf[0..n];
        n += s.len;
    }
    return buf[0..n];
}

test "parse and format" {
    const a = try Address.parse("127.0.0.1:8080");
    try std.testing.expectEqual(@as(u16, 8080), a.port());
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("127.0.0.1:8080", a.format(&buf));
    const b = try Address.parse("[::1]:443");
    try std.testing.expectEqual(@as(u16, 443), b.port());
    try std.testing.expectEqual(@as(u8, 1), b.in6.addr[15]);
    try std.testing.expectEqualStrings("[0:0:0:0:0:0:0:1]:443", b.format(&buf));
    try std.testing.expectError(error.InvalidAddress, Address.parse("1.2.3:80"));
    try std.testing.expectError(error.InvalidAddress, Address.parse("1.2.3.4"));
    try std.testing.expectError(error.InvalidAddress, Address.parse("1.2.3.256:80"));
}
