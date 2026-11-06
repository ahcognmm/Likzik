//! API keys. The snapshot stores only SHA-256 hashes of the keys (the
//! config may give the hash itself, so the key never has to be written
//! down); a request's key is hashed and looked up. A miss reveals nothing
//! about stored keys, so lookup timing does not matter.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Hash = [Sha256.digest_length]u8;

pub const Set = struct {
    name: []const u8,
    header: []const u8,
    query: ?[]const u8,
    strip: bool,
    /// Key hash -> consumer name.
    keys: std.AutoHashMapUnmanaged(Hash, []const u8),

    pub fn lookup(self: *const Set, key: []const u8) ?[]const u8 {
        var h: Hash = undefined;
        Sha256.hash(key, &h, .{});
        return self.keys.get(h);
    }
};

pub fn parseHexHash(s: []const u8) ?Hash {
    if (s.len != 64) return null;
    var h: Hash = undefined;
    _ = std.fmt.hexToBytes(&h, s) catch return null;
    return h;
}

pub fn hashKey(key: []const u8) Hash {
    var h: Hash = undefined;
    Sha256.hash(key, &h, .{});
    return h;
}

test "lookup by hash" {
    var set: Set = .{ .name = "k", .header = "X-API-Key", .query = null, .strip = true, .keys = .empty };
    defer set.keys.deinit(std.testing.allocator);
    try set.keys.put(std.testing.allocator, hashKey("secret-1"), "alice");
    // sha256("secret-2"), as an operator would put it in the config
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{hashKey("secret-2")}) catch unreachable;
    try set.keys.put(std.testing.allocator, parseHexHash(&hex).?, "bob");
    try std.testing.expectEqualStrings("alice", set.lookup("secret-1").?);
    try std.testing.expectEqualStrings("bob", set.lookup("secret-2").?);
    try std.testing.expect(set.lookup("secret-3") == null);
    try std.testing.expect(parseHexHash("zz") == null);
}
