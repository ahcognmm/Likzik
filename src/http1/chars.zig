//! Shared byte-class core for the HTTP/1.1 parsers.
//!
//! All tables are built at comptime. The SIMD scanners use `@Vector` and
//! compile to SSE2/AVX2 on x86_64 and NEON on arm64.

const std = @import("std");

pub const Class = packed struct(u8) {
    /// RFC 9110 `tchar` (token characters: methods, header names).
    tchar: bool = false,
    /// Allowed inside a field value: VCHAR, SP, HTAB, obs-text.
    field_value: bool = false,
    /// Allowed inside a request-target: VCHAR (0x21..0x7E) plus obs-text is rejected.
    target: bool = false,
    /// Hexadecimal digit.
    hex: bool = false,
    /// Decimal digit.
    digit: bool = false,
    /// Allowed inside a reason phrase: HTAB, SP, VCHAR, obs-text.
    reason: bool = false,
    _pad: u2 = 0,
};

pub const table: [256]Class = blk: {
    var t: [256]Class = [_]Class{.{}} ** 256;
    for (0..256) |i| {
        const c: u8 = @intCast(i);
        var cl: Class = .{};
        cl.tchar = switch (c) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            '0'...'9', 'a'...'z', 'A'...'Z' => true,
            else => false,
        };
        cl.field_value = (c == '\t') or (c >= 0x20 and c != 0x7f);
        cl.reason = cl.field_value;
        cl.target = c > 0x20 and c < 0x7f;
        cl.hex = switch (c) {
            '0'...'9', 'a'...'f', 'A'...'F' => true,
            else => false,
        };
        cl.digit = c >= '0' and c <= '9';
        t[i] = cl;
    }
    break :blk t;
};

pub inline fn isTchar(c: u8) bool {
    return table[c].tchar;
}
pub inline fn isFieldValue(c: u8) bool {
    return table[c].field_value;
}
pub inline fn isTarget(c: u8) bool {
    return table[c].target;
}
pub inline fn isHex(c: u8) bool {
    return table[c].hex;
}
pub inline fn isDigit(c: u8) bool {
    return table[c].digit;
}

pub inline fn hexVal(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => unreachable,
    };
}

pub const vec_len = std.simd.suggestVectorLength(u8) orelse 16;
const V = @Vector(vec_len, u8);
const B = @Vector(vec_len, bool);

/// Returns the index of the first `\n` at or after `start`, or null.
pub fn findLf(buf: []const u8, start: usize) ?usize {
    var i = start;
    const lf: V = @splat('\n');
    while (i + vec_len <= buf.len) : (i += vec_len) {
        const chunk: V = buf[i..][0..vec_len].*;
        if (std.simd.firstTrue(chunk == lf)) |off| return i + off;
    }
    while (i < buf.len) : (i += 1) {
        if (buf[i] == '\n') return i;
    }
    return null;
}

/// Returns the index of the first byte at or after `start` that is not a
/// valid field-value byte (i.e. a control character other than HTAB, or DEL).
/// CR and LF are both reported, which is how line ends are found.
pub fn findFieldValueEnd(buf: []const u8, start: usize) usize {
    var i = start;
    const sp: V = @splat(0x20);
    const tab: V = @splat('\t');
    const del: V = @splat(0x7f);
    while (i + vec_len <= buf.len) : (i += vec_len) {
        const chunk: V = buf[i..][0..vec_len].*;
        const ctl: B = chunk < sp;
        const not_tab: B = chunk != tab;
        const bad = @select(bool, ctl, not_tab, chunk == del);
        if (std.simd.firstTrue(bad)) |off| return i + off;
    }
    while (i < buf.len) : (i += 1) {
        if (!isFieldValue(buf[i])) return i;
    }
    return buf.len;
}

/// Returns the index of the first byte at or after `start` that is not a
/// valid request-target byte (VCHAR). Reports SP, which ends the target.
pub fn findTargetEnd(buf: []const u8, start: usize) usize {
    var i = start;
    const lo: V = @splat(0x21);
    const hi: V = @splat(0x7e);
    while (i + vec_len <= buf.len) : (i += vec_len) {
        const chunk: V = buf[i..][0..vec_len].*;
        const below: B = chunk < lo;
        const above: B = chunk > hi;
        const bad = @select(bool, below, below, above);
        if (std.simd.firstTrue(bad)) |off| return i + off;
    }
    while (i < buf.len) : (i += 1) {
        if (!isTarget(buf[i])) return i;
    }
    return buf.len;
}

/// Returns the index of the first non-tchar at or after `start`.
pub fn findTokenEnd(buf: []const u8, start: usize) usize {
    var i = start;
    while (i < buf.len and isTchar(buf[i])) : (i += 1) {}
    return i;
}

test "byte classes" {
    try std.testing.expect(isTchar('a'));
    try std.testing.expect(!isTchar(':'));
    try std.testing.expect(!isTchar(' '));
    try std.testing.expect(isFieldValue('\t'));
    try std.testing.expect(isFieldValue(0x80));
    try std.testing.expect(!isFieldValue('\r'));
    try std.testing.expect(!isFieldValue(0x7f));
    try std.testing.expect(!isTarget(' '));
}

test "simd scanners" {
    const s = "abcdefghijklmnopqrstuvwxyz0123456789\r\nxyz";
    try std.testing.expectEqual(@as(?usize, 37), findLf(s, 0));
    try std.testing.expectEqual(@as(usize, 36), findFieldValueEnd(s, 0));
    try std.testing.expectEqual(@as(usize, 36), findTargetEnd(s, 0));
    const t = "/a/very/long/path/that/goes/on/and/on?q=1 HTTP/1.1";
    try std.testing.expectEqual(@as(usize, 41), findTargetEnd(t, 0));
    const ctl = "value with a\x01control char";
    try std.testing.expectEqual(@as(usize, 12), findFieldValueEnd(ctl, 0));
    const tab = "value\twith\ttabs and spaces only.....";
    try std.testing.expectEqual(tab.len, findFieldValueEnd(tab, 0));
}
