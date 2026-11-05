//! Per-socket ordered send queue. Segments point into provided buffers,
//! refcounted blocks or static memory; the owner reference is dropped
//! only after the kernel reports the bytes as sent. One sendmsg with up to
//! `max_iov` segments is in flight at a time.

const std = @import("std");
const linux = std.os.linux;
const region = @import("../mem/region.zig");

pub const max_iov = 16;

pub const Owner = union(enum) {
    none,
    pbuf: u16,
    block: u32,
};

pub const Seg = struct {
    ptr: [*]const u8,
    len: u32,
    owner: Owner,
    next: ?u32 = null,
};

pub const SegPool = struct {
    segs: []Seg,
    free: []u32,
    free_len: usize,

    pub fn init(gpa: std.mem.Allocator, n: u32) !SegPool {
        _ = gpa;
        const segs = try region.alloc(Seg, n);
        errdefer region.free(Seg, segs);
        const free = try region.alloc(u32, n);
        for (free, 0..) |*f, i| f.* = @intCast(n - 1 - i);
        return .{ .segs = segs, .free = free, .free_len = n };
    }

    pub fn deinit(self: *SegPool, gpa: std.mem.Allocator) void {
        _ = gpa;
        region.free(Seg, self.segs);
        region.free(u32, self.free);
    }

    pub fn alloc(self: *SegPool) ?u32 {
        if (self.free_len == 0) return null;
        self.free_len -= 1;
        return self.free[self.free_len];
    }

    pub fn release(self: *SegPool, i: u32) void {
        self.free[self.free_len] = i;
        self.free_len += 1;
    }
};

pub const SendQueue = struct {
    head: ?u32 = null,
    tail: ?u32 = null,
    /// Bytes queued and not yet acknowledged by a send completion.
    bytes: usize = 0,
    inflight: bool = false,
    iov: [max_iov]std.posix.iovec_const = undefined,
    msg: linux.msghdr_const = undefined,

    pub fn isEmpty(self: *const SendQueue) bool {
        return self.head == null;
    }

    pub fn push(self: *SendQueue, pool: *SegPool, seg: Seg) error{OutOfSegments}!void {
        std.debug.assert(seg.len > 0);
        const i = pool.alloc() orelse return error.OutOfSegments;
        pool.segs[i] = seg;
        pool.segs[i].next = null;
        if (self.tail) |t| pool.segs[t].next = i else self.head = i;
        self.tail = i;
        self.bytes += seg.len;
    }

    /// Fills the iovec array from the queue head; returns the msghdr.
    pub fn prepare(self: *SendQueue, pool: *SegPool) *const linux.msghdr_const {
        var n: usize = 0;
        var it = self.head;
        while (it) |i| : (it = pool.segs[i].next) {
            if (n == max_iov) break;
            self.iov[n] = .{ .base = pool.segs[i].ptr, .len = pool.segs[i].len };
            n += 1;
        }
        self.msg = .{ .name = null, .namelen = 0, .iov = &self.iov, .iovlen = n, .control = null, .controllen = 0, .flags = 0 };
        self.inflight = true;
        return &self.msg;
    }

    /// Consumes `sent` bytes from the head; calls `rel.releaseOwner(owner)`
    /// for every fully sent segment.
    pub fn complete(self: *SendQueue, pool: *SegPool, sent: usize, rel: anytype) void {
        self.inflight = false;
        var left = sent;
        self.bytes -= sent;
        while (left > 0) {
            const i = self.head.?;
            const s = &pool.segs[i];
            if (left >= s.len) {
                left -= s.len;
                self.head = s.next;
                if (self.head == null) self.tail = null;
                const owner = s.owner;
                pool.release(i);
                rel.releaseOwner(owner);
            } else {
                s.ptr += left;
                s.len -= @intCast(left);
                left = 0;
            }
        }
    }

    /// Drops everything (connection closing, nothing in flight).
    pub fn clear(self: *SendQueue, pool: *SegPool, rel: anytype) void {
        std.debug.assert(!self.inflight);
        var it = self.head;
        while (it) |i| {
            it = pool.segs[i].next;
            const owner = pool.segs[i].owner;
            pool.release(i);
            rel.releaseOwner(owner);
        }
        self.head = null;
        self.tail = null;
        self.bytes = 0;
    }
};

test "send queue partial completion" {
    var pool = try SegPool.init(std.testing.allocator, 8);
    defer pool.deinit(std.testing.allocator);
    const Rel = struct {
        released: u32 = 0,
        fn releaseOwner(self: *@This(), o: Owner) void {
            _ = o;
            self.released += 1;
        }
    };
    var rel: Rel = .{};
    var q: SendQueue = .{};
    try q.push(&pool, .{ .ptr = "hello", .len = 5, .owner = .none });
    try q.push(&pool, .{ .ptr = "world", .len = 5, .owner = .{ .pbuf = 3 } });
    const m = q.prepare(&pool);
    try std.testing.expectEqual(@as(usize, 2), m.iovlen);
    q.complete(&pool, 7, &rel);
    try std.testing.expectEqual(@as(u32, 1), rel.released);
    try std.testing.expectEqual(@as(usize, 3), q.bytes);
    const m2 = q.prepare(&pool);
    try std.testing.expectEqual(@as(usize, 3), m2.iov[0].len);
    try std.testing.expectEqual(@as(u8, 'r'), m2.iov[0].base[0]);
    q.complete(&pool, 3, &rel);
    try std.testing.expect(q.isEmpty());
    try std.testing.expectEqual(@as(u32, 2), rel.released);
}
