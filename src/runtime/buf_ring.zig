//! Provided buffer ring (IORING_REGISTER_PBUF_RING), one per worker.
//!
//! Ownership rule: a buffer belongs to us from the CQE that carries it
//! until its last reference is dropped. The receive path takes the first
//! reference; every send that reads from the buffer takes another. The
//! buffer goes back to the kernel only at zero, and its generation is
//! bumped so a stale reference trips an assertion in safe builds.
//!
//! Incremental consumption (IOU_PBUF_RING_INC) is deliberately not used:
//! one CQE = one whole buffer keeps the ownership rule simple.

const std = @import("std");
const linux = std.os.linux;
const IoUring = linux.IoUring;
const region = @import("../mem/region.zig");

pub const BufRing = struct {
    ring_fd: linux.fd_t,
    br: *align(std.heap.page_size_min) linux.io_uring_buf_ring,
    mem: []u8,
    buf_size: u32,
    count: u16,
    group_id: u16,
    refs: []u16,
    gens: []u32,
    /// Buffers currently owned by userspace.
    out: u32 = 0,

    pub fn init(gpa: std.mem.Allocator, ring: *IoUring, group_id: u16, buf_size: u32, count: u16) !BufRing {
        const mem = try region.alloc(u8, @as(usize, buf_size) * count);
        errdefer region.free(u8, mem);
        const refs = try gpa.alloc(u16, count);
        errdefer gpa.free(refs);
        const gens = try gpa.alloc(u32, count);
        errdefer gpa.free(gens);
        @memset(refs, 0);
        @memset(gens, 0);
        const br = try IoUring.setup_buf_ring(ring.fd, count, group_id, .{ .inc = false });
        IoUring.buf_ring_init(br);
        const mask = IoUring.buf_ring_mask(count);
        for (0..count) |i| {
            const id: u16 = @intCast(i);
            IoUring.buf_ring_add(br, mem[@as(usize, id) * buf_size ..][0..buf_size], id, mask, id);
        }
        IoUring.buf_ring_advance(br, count);
        return .{ .ring_fd = ring.fd, .br = br, .mem = mem, .buf_size = buf_size, .count = count, .group_id = group_id, .refs = refs, .gens = gens };
    }

    pub fn deinit(self: *BufRing, gpa: std.mem.Allocator) void {
        IoUring.free_buf_ring(self.ring_fd, self.br, self.count, self.group_id);
        region.free(u8, self.mem);
        gpa.free(self.refs);
        gpa.free(self.gens);
    }

    /// Called once per CQE that carries a buffer. Returns the data.
    pub fn take(self: *BufRing, cqe: *const linux.io_uring_cqe) ![]u8 {
        const id = try cqe.buffer_id();
        std.debug.assert(self.refs[id] == 0);
        self.refs[id] = 1;
        self.out += 1;
        const n: usize = @intCast(cqe.res);
        return self.mem[@as(usize, id) * self.buf_size ..][0..n];
    }

    pub fn idOf(self: *const BufRing, cqe: *const linux.io_uring_cqe) u16 {
        _ = self;
        return cqe.buffer_id() catch unreachable;
    }

    pub fn ref(self: *BufRing, id: u16) void {
        std.debug.assert(self.refs[id] > 0);
        self.refs[id] += 1;
    }

    pub fn unref(self: *BufRing, id: u16) void {
        std.debug.assert(self.refs[id] > 0);
        self.refs[id] -= 1;
        if (self.refs[id] == 0) {
            self.gens[id] +%= 1;
            self.out -= 1;
            const mask = IoUring.buf_ring_mask(self.count);
            IoUring.buf_ring_add(self.br, self.mem[@as(usize, id) * self.buf_size ..][0..self.buf_size], id, mask, 0);
            IoUring.buf_ring_advance(self.br, 1);
        }
    }

    pub fn ptrOf(self: *BufRing, id: u16) [*]u8 {
        return self.mem.ptr + @as(usize, id) * self.buf_size;
    }
};
