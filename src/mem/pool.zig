//! Fixed-capacity object pool (slab) with a free list and per-slot
//! generations. Objects never move, so pointers into them are stable;
//! the generation lets io_uring completions detect a reused slot.
//! Owned by one worker: no locks.

const std = @import("std");
const region = @import("region.zig");

pub fn Pool(comptime T: type) type {
    return struct {
        const Self = @This();

        items: []T,
        gens: []u32,
        live: []bool,
        free: []u32,
        free_len: usize,

        pub fn init(gpa: std.mem.Allocator, capacity: u32) !Self {
            _ = gpa;
            const items = try region.alloc(T, capacity);
            errdefer region.free(T, items);
            const gens = try region.alloc(u32, capacity);
            errdefer region.free(u32, gens);
            const live = try region.alloc(bool, capacity);
            errdefer region.free(bool, live);
            const free = try region.alloc(u32, capacity);
            // Generations start at 0 (fresh mmap memory is zeroed); the
            // first release bumps them. live[] starts all-false.
            // Pop from the end: hand out low indices first.
            for (free, 0..) |*f, i| f.* = @intCast(capacity - 1 - i);
            return .{ .items = items, .gens = gens, .live = live, .free = free, .free_len = capacity };
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            _ = gpa;
            region.free(T, self.items);
            region.free(u32, self.gens);
            region.free(bool, self.live);
            region.free(u32, self.free);
        }

        pub fn alloc(self: *Self) ?u32 {
            if (self.free_len == 0) return null;
            self.free_len -= 1;
            const idx = self.free[self.free_len];
            self.live[idx] = true;
            return idx;
        }

        pub fn release(self: *Self, idx: u32) void {
            std.debug.assert(self.live[idx]);
            self.live[idx] = false;
            self.gens[idx] +%= 1;
            self.free[self.free_len] = idx;
            self.free_len += 1;
        }

        pub inline fn get(self: *Self, idx: u32) *T {
            return &self.items[idx];
        }

        pub inline fn gen(self: *const Self, idx: u32) u32 {
            return self.gens[idx];
        }

        /// True when `idx` is live and still the same object as `g`.
        pub inline fn valid(self: *const Self, idx: u32, g: u32) bool {
            return idx < self.items.len and self.live[idx] and self.gens[idx] == g;
        }

        pub fn inUse(self: *const Self) usize {
            return self.items.len - self.free_len;
        }
    };
}

test "pool alloc/release/generation" {
    var p = try Pool(u64).init(std.testing.allocator, 4);
    defer p.deinit(std.testing.allocator);
    const a = p.alloc().?;
    const g = p.gen(a);
    try std.testing.expect(p.valid(a, g));
    p.release(a);
    try std.testing.expect(!p.valid(a, g));
    const b = p.alloc().?;
    try std.testing.expectEqual(a, b);
    try std.testing.expect(p.gen(b) != g);
    _ = p.alloc().?;
    _ = p.alloc().?;
    _ = p.alloc().?;
    try std.testing.expect(p.alloc() == null);
    try std.testing.expectEqual(@as(usize, 4), p.inUse());
}
