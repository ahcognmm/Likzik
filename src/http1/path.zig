//! Request path normalization for routing. Matching uses the normalized
//! path so that "/public/../admin", "//admin" and "/%61dmin" route where
//! the upstream will resolve them; the request is forwarded unchanged.

const std = @import("std");

/// Longest path that is normalized; longer ones match no route.
pub const max_len = 8192;

fn unreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

fn hexv(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Normalizes the path part of a request target into `out` for matching.
/// Returns null if it does not fit. The query string is not included.
pub fn normalize(target: []const u8, out: []u8) ?[]const u8 {
    const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
    // 1. Decode %XX only for unreserved characters (RFC 3986 6.2.2.2).
    var dec: [max_len]u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (n == dec.len) return null;
        var c = path[i];
        if (c == '%' and i + 2 < path.len) {
            if (hexv(path[i + 1])) |h| if (hexv(path[i + 2])) |l| {
                const v = h * 16 + l;
                if (unreserved(v)) {
                    c = v;
                    i += 2;
                }
            };
        }
        dec[n] = c;
        n += 1;
    }
    // 2. Remove dot segments and empty segments.
    var stack: [64][]const u8 = undefined;
    var depth: usize = 0;
    var it = std.mem.tokenizeScalar(u8, dec[0..n], '/');
    while (it.next()) |seg| {
        if (std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (depth > 0) depth -= 1;
            continue;
        }
        if (depth == stack.len) return null;
        stack[depth] = seg;
        depth += 1;
    }
    var o: usize = 0;
    if (depth == 0) {
        if (out.len < 1) return null;
        out[0] = '/';
        return out[0..1];
    }
    for (stack[0..depth]) |seg| {
        if (o + 1 + seg.len > out.len) return null;
        out[o] = '/';
        @memcpy(out[o + 1 .. o + 1 + seg.len], seg);
        o += 1 + seg.len;
    }
    // Keep a trailing slash ("/dir/" stays distinct from "/dir").
    if (path.len > 1 and path[path.len - 1] == '/' and o < out.len) {
        out[o] = '/';
        o += 1;
    }
    return out[0..o];
}

const testing = std.testing;

test "normalize" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("/public", normalize("/admin/../public", &buf).?);
    try testing.expectEqualStrings("/a/b", normalize("//a/./b?x=1", &buf).?);
    try testing.expectEqualStrings("/admin", normalize("/%61dmin", &buf).?);
    try testing.expectEqualStrings("/a%2Fb", normalize("/a%2Fb", &buf).?);
    try testing.expectEqualStrings("/", normalize("/../..", &buf).?);
    try testing.expectEqualStrings("/dir/", normalize("/dir/", &buf).?);
    try testing.expectEqualStrings("/x", normalize("/%2e%2e/x", &buf).?);
}
