//! Large, lazily committed memory regions. Pools are sized for the
//! configured connection limit up front, but pages are only backed by RAM
//! when first touched, so RSS follows actual concurrency. (Going through
//! an Allocator would fill the memory with 0xaa in safe builds and commit
//! every page at startup.)

const std = @import("std");
const linux = std.os.linux;

pub fn alloc(comptime T: type, n: usize) ![]T {
    if (n == 0) return &.{};
    const bytes = std.mem.alignForward(usize, n * @sizeOf(T), std.heap.page_size_min);
    const rc = linux.mmap(null, bytes, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .NORESERVE = true }, -1, 0);
    if (linux.errno(rc) != .SUCCESS) return error.OutOfMemory;
    const p: [*]T = @ptrFromInt(rc);
    return p[0..n];
}

pub fn free(comptime T: type, s: []T) void {
    if (s.len == 0) return;
    const bytes = std.mem.alignForward(usize, s.len * @sizeOf(T), std.heap.page_size_min);
    _ = linux.munmap(@ptrCast(s.ptr), bytes);
}

test "region is zeroed and usable" {
    const s = try alloc(u64, 100_000);
    defer free(u64, s);
    try std.testing.expectEqual(@as(u64, 0), s[99_999]);
    s[5] = 7;
    try std.testing.expectEqual(@as(u64, 7), s[5]);
}
