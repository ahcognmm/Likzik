//! Per-worker pool of fixed-size, reference-counted byte blocks. Used for
//! request-head accumulation, serialized heads and pipelined bytes. A
//! block is returned to the pool when its last reference is dropped, which
//! happens only after every send that reads from it has completed.

const std = @import("std");
const region = @import("region.zig");

pub const block_size = 16 * 1024;

pub const Blocks = struct {
    mem: []u8,
    refs: []u16,
    free: []u32,
    free_len: usize,

    pub fn init(gpa: std.mem.Allocator, count: u32) !Blocks {
        _ = gpa;
        const m = try region.alloc(u8, @as(usize, count) * block_size);
        errdefer region.free(u8, m);
        const refs = try region.alloc(u16, count);
        errdefer region.free(u16, refs);
        const free = try region.alloc(u32, count);
        for (free, 0..) |*f, i| f.* = @intCast(count - 1 - i);
        return .{ .mem = m, .refs = refs, .free = free, .free_len = count };
    }

    pub fn deinit(self: *Blocks, gpa: std.mem.Allocator) void {
        _ = gpa;
        region.free(u8, self.mem);
        region.free(u16, self.refs);
        region.free(u32, self.free);
    }

    /// Returns a block with one reference, or null when exhausted.
    pub fn alloc(self: *Blocks) ?u32 {
        if (self.free_len == 0) return null;
        self.free_len -= 1;
        const id = self.free[self.free_len];
        std.debug.assert(self.refs[id] == 0);
        self.refs[id] = 1;
        return id;
    }

    pub fn ref(self: *Blocks, id: u32) void {
        std.debug.assert(self.refs[id] > 0);
        self.refs[id] += 1;
    }

    pub fn unref(self: *Blocks, id: u32) void {
        std.debug.assert(self.refs[id] > 0);
        self.refs[id] -= 1;
        if (self.refs[id] == 0) {
            self.free[self.free_len] = id;
            self.free_len += 1;
        }
    }

    pub inline fn bytes(self: *Blocks, id: u32) *[block_size]u8 {
        return self.mem[@as(usize, id) * block_size ..][0..block_size];
    }

    pub fn available(self: *const Blocks) usize {
        return self.free_len;
    }
};

/// A byte range inside one block, used to accumulate input.
pub const InBuf = struct {
    block: ?u32 = null,
    start: u32 = 0,
    end: u32 = 0,

    pub fn slice(self: *const InBuf, blocks: *Blocks) []u8 {
        const b = self.block orelse return &.{};
        return blocks.bytes(b)[self.start..self.end];
    }

    pub fn len(self: *const InBuf) usize {
        return self.end - self.start;
    }

    pub fn isEmpty(self: *const InBuf) bool {
        return self.end == self.start;
    }

    /// Appends bytes, compacting or moving to a fresh block when the
    /// current one is shared or full. Fails when the total would exceed
    /// one block.
    pub fn append(self: *InBuf, blocks: *Blocks, data: []const u8) error{ NoSpace, OutOfBlocks }!void {
        if (self.len() + data.len > block_size) return error.NoSpace;
        if (self.block == null) {
            self.block = blocks.alloc() orelse return error.OutOfBlocks;
            self.start = 0;
            self.end = 0;
        }
        if (self.end + data.len > block_size) {
            const b = self.block.?;
            if (blocks.refs[b] == 1) {
                const mem = blocks.bytes(b);
                std.mem.copyForwards(u8, mem[0..self.len()], mem[self.start..self.end]);
            } else {
                // Shared with an in-flight send: move to a new block.
                const nb = blocks.alloc() orelse return error.OutOfBlocks;
                @memcpy(blocks.bytes(nb)[0..self.len()], blocks.bytes(b)[self.start..self.end]);
                blocks.unref(b);
                self.block = nb;
            }
            self.end -= self.start;
            self.start = 0;
        }
        const mem = blocks.bytes(self.block.?);
        @memcpy(mem[self.end .. self.end + data.len], data);
        self.end += @intCast(data.len);
    }

    pub fn consume(self: *InBuf, n: usize) void {
        self.start += @intCast(n);
        std.debug.assert(self.start <= self.end);
    }

    /// Drops the block when empty, so idle connections hold no memory.
    pub fn trim(self: *InBuf, blocks: *Blocks) void {
        if (self.block) |b| if (self.isEmpty()) {
            blocks.unref(b);
            self.* = .{};
        };
    }

    pub fn release(self: *InBuf, blocks: *Blocks) void {
        if (self.block) |b| blocks.unref(b);
        self.* = .{};
    }
};

test "inbuf append, compact, move when shared" {
    var blocks = try Blocks.init(std.testing.allocator, 4);
    defer blocks.deinit(std.testing.allocator);
    var in: InBuf = .{};
    try in.append(&blocks, "hello");
    try in.append(&blocks, " world");
    try std.testing.expectEqualStrings("hello world", in.slice(&blocks));
    in.consume(6);
    var big: [block_size - 6]u8 = undefined;
    @memset(&big, 'x');
    // Compacts in place (block not shared).
    const b0 = in.block.?;
    try in.append(&blocks, big[0 .. block_size - 10]);
    try std.testing.expectEqual(b0, in.block.?);
    try std.testing.expectEqualStrings("world", in.slice(&blocks)[0..5]);
    // Share the block, consume, then force a move.
    blocks.ref(b0);
    in.consume(in.len() - 3);
    try in.append(&blocks, big[0..20]);
    try std.testing.expect(in.block.? != b0);
    blocks.unref(b0);
    try std.testing.expectError(error.NoSpace, in.append(&blocks, &big));
    in.release(&blocks);
    try std.testing.expectEqual(@as(usize, 4), blocks.available());
}
