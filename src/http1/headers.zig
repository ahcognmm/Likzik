//! Well-known header names mapped to an enum by a comptime-generated
//! perfect hash. Lookup is one hash, one table load and one
//! case-insensitive compare; nothing is allocated.

const std = @import("std");

pub const Id = enum(u8) {
    other = 0,
    host,
    content_length,
    transfer_encoding,
    connection,
    keep_alive,
    proxy_connection,
    te,
    trailer,
    upgrade,
    proxy_authenticate,
    proxy_authorization,
    expect,
    x_forwarded_for,
    x_forwarded_proto,
    x_forwarded_host,
    forwarded,
    via,
    date,
    server,
    content_type,
    user_agent,
    accept,
    accept_encoding,
    authorization,
    cookie,
    set_cookie,
    cache_control,
    traceparent,
    tracestate,
    x_request_id,
    location,
    content_encoding,
    vary,
    etag,
    last_modified,
    referer,
    origin,
    if_none_match,
    if_modified_since,
    range,
};

/// Lowercase canonical spelling of each id (index = @intFromEnum).
pub const names = blk: {
    const field_names = @typeInfo(Id).@"enum".field_names;
    var out: [field_names.len][]const u8 = undefined;
    for (field_names, 0..) |fname, i| {
        var buf: [fname.len]u8 = undefined;
        for (fname, 0..) |c, j| buf[j] = if (c == '_') '-' else c;
        const final = buf;
        out[i] = &final;
    }
    out[0] = "";
    break :blk out;
};

/// Canonical display spelling used when we emit a header ourselves.
pub fn canonical(id: Id) []const u8 {
    return switch (id) {
        .host => "Host",
        .content_length => "Content-Length",
        .transfer_encoding => "Transfer-Encoding",
        .connection => "Connection",
        .x_forwarded_for => "X-Forwarded-For",
        .x_forwarded_proto => "X-Forwarded-Proto",
        .x_forwarded_host => "X-Forwarded-Host",
        .date => "Date",
        .server => "Server",
        .content_type => "Content-Type",
        else => names[@intFromEnum(id)],
    };
}

const table_bits = 7;
const table_size = 1 << table_bits;

inline fn lower(c: u8) u8 {
    return c | @as(u8, if (c >= 'A' and c <= 'Z') 0x20 else 0);
}

inline fn hash(seed: u32, s: []const u8) u32 {
    // Mix length and up to four characters: first, second, second-to-last, last.
    var h: u32 = seed ^ @as(u32, @intCast(s.len)) *% 0x9e3779b1;
    h = (h ^ lower(s[0])) *% 0x01000193;
    h = (h ^ lower(s[@min(1, s.len - 1)])) *% 0x01000193;
    h = (h ^ lower(s[s.len - 1])) *% 0x01000193;
    h = (h ^ lower(s[s.len - @min(2, s.len)])) *% 0x01000193;
    return (h ^ (h >> 15)) & (table_size - 1);
}

const Table = struct { seed: u32, slots: [table_size]Id };

const perfect: Table = blk: {
    @setEvalBranchQuota(2_000_000);
    var seed: u32 = 1;
    search: while (seed < 100_000) : (seed += 1) {
        var slots: [table_size]Id = @splat(.other);
        for (1..names.len) |i| {
            const slot = hash(seed, names[i]);
            if (slots[slot] != .other) continue :search;
            slots[slot] = @enumFromInt(i);
        }
        break :blk .{ .seed = seed, .slots = slots };
    }
    @compileError("no perfect hash seed found for header table");
};

pub fn lookup(name: []const u8) Id {
    if (name.len == 0 or name.len > 32) return .other;
    const id = perfect.slots[hash(perfect.seed, name)];
    if (id == .other) return .other;
    return if (std.ascii.eqlIgnoreCase(names[@intFromEnum(id)], name)) id else .other;
}

/// Headers that are connection-specific and never forwarded (RFC 9110 7.6.1,
/// plus the de-facto ones).
pub fn isHopByHop(id: Id) bool {
    return switch (id) {
        .connection, .keep_alive, .proxy_connection, .te, .trailer, .upgrade, .transfer_encoding, .proxy_authenticate, .proxy_authorization => true,
        else => false,
    };
}

test "perfect hash lookup" {
    try std.testing.expectEqual(Id.host, lookup("Host"));
    try std.testing.expectEqual(Id.host, lookup("HOST"));
    try std.testing.expectEqual(Id.content_length, lookup("content-length"));
    try std.testing.expectEqual(Id.transfer_encoding, lookup("Transfer-Encoding"));
    try std.testing.expectEqual(Id.x_forwarded_for, lookup("X-Forwarded-For"));
    try std.testing.expectEqual(Id.te, lookup("TE"));
    try std.testing.expectEqual(Id.other, lookup("X-Custom"));
    try std.testing.expectEqual(Id.other, lookup("Hostx"));
    try std.testing.expectEqual(Id.other, lookup("content_length"));
    for (1..names.len) |i| {
        try std.testing.expectEqual(@as(Id, @enumFromInt(i)), lookup(names[i]));
    }
}
