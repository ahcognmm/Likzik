//! SNI certificate selection: exact names first, then the longest
//! "*.suffix" wildcard (one label deep, as in RFC 6125), then the default.

const std = @import("std");

pub fn matches(pattern: []const u8, name: []const u8) bool {
    if (pattern.len > 2 and pattern[0] == '*' and pattern[1] == '.') {
        const suffix = pattern[1..]; // ".example.com"
        if (name.len <= suffix.len or !std.ascii.endsWithIgnoreCase(name, suffix)) return false;
        // The wildcard covers exactly one label.
        return std.mem.indexOfScalar(u8, name[0 .. name.len - suffix.len], '.') == null;
    }
    return std.ascii.eqlIgnoreCase(pattern, name);
}

/// Returns the index of the best entry for `name`, or null (use default).
pub fn select(comptime T: type, entries: []const T, name: []const u8) ?usize {
    var best: ?usize = null;
    var best_len: usize = 0;
    for (entries, 0..) |e, i| {
        for (e.names) |p| {
            if (!matches(p, name)) continue;
            if (p[0] != '*') return i; // exact match wins
            if (p.len > best_len) {
                best = i;
                best_len = p.len;
            }
        }
    }
    return best;
}

test "sni matching" {
    try std.testing.expect(matches("example.com", "EXAMPLE.com"));
    try std.testing.expect(matches("*.example.com", "a.example.com"));
    try std.testing.expect(!matches("*.example.com", "a.b.example.com"));
    try std.testing.expect(!matches("*.example.com", "example.com"));
    const E = struct { names: []const []const u8 };
    const es = [_]E{ .{ .names = &.{"*.example.com"} }, .{ .names = &.{ "api.example.com", "x.org" } } };
    try std.testing.expectEqual(@as(?usize, 1), select(E, &es, "api.example.com"));
    try std.testing.expectEqual(@as(?usize, 0), select(E, &es, "www.example.com"));
    try std.testing.expectEqual(@as(?usize, null), select(E, &es, "other.net"));
}
