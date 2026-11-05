//! Worker-local endpoint state: in-flight request counts for least-request
//! LB, passive health (consecutive connect failures -> ejection with
//! exponential backoff), the idle-connection list head and smooth-WRR
//! state. Indexed by the stable endpoint id from the config registry.

const std = @import("std");

pub const EpState = struct {
    active: u32 = 0,
    consecutive_failures: u8 = 0,
    ejections: u8 = 0,
    ejected_until_ms: u64 = 0,
    /// Head of this endpoint's idle upstream connection list.
    idle_head: ?u32 = null,
    idle_count: u32 = 0,
    /// Smooth weighted round robin running weight.
    rr_current: i64 = 0,

    pub fn healthy(self: *const EpState, now_ms: u64) bool {
        return self.ejected_until_ms <= now_ms;
    }

    /// Returns true when this failure ejected the endpoint.
    pub fn recordFailure(self: *EpState, now_ms: u64, threshold: u8, base_ms: u32) bool {
        self.consecutive_failures +|= 1;
        if (threshold == 0 or self.consecutive_failures < threshold) return false;
        // Back off exponentially on repeated ejections, capped at 32x.
        const shift: u6 = @intCast(@min(self.ejections, 5));
        self.ejected_until_ms = now_ms + (@as(u64, base_ms) << shift);
        self.ejections +|= 1;
        self.consecutive_failures = 0;
        return true;
    }

    pub fn recordSuccess(self: *EpState) void {
        self.consecutive_failures = 0;
        self.ejections = 0;
    }
};

pub const Table = struct {
    items: std.ArrayList(EpState) = .empty,

    pub fn get(self: *Table, gpa: std.mem.Allocator, id: u32) !*EpState {
        if (id >= self.items.items.len) {
            const old = self.items.items.len;
            try self.items.resize(gpa, @max(id + 1, old * 2));
            for (self.items.items[old..]) |*e| e.* = .{};
        }
        return &self.items.items[id];
    }

    pub fn deinit(self: *Table, gpa: std.mem.Allocator) void {
        self.items.deinit(gpa);
    }
};

test "ejection with backoff" {
    var e: EpState = .{};
    try std.testing.expect(!e.recordFailure(0, 3, 1000));
    try std.testing.expect(!e.recordFailure(0, 3, 1000));
    try std.testing.expect(e.recordFailure(0, 3, 1000));
    try std.testing.expect(!e.healthy(500));
    try std.testing.expect(e.healthy(1000));
    _ = e.recordFailure(1000, 3, 1000);
    _ = e.recordFailure(1000, 3, 1000);
    try std.testing.expect(e.recordFailure(1000, 3, 1000));
    try std.testing.expectEqual(@as(u64, 3000), e.ejected_until_ms);
    e.recordSuccess();
    try std.testing.expectEqual(@as(u8, 0), e.ejections);
}
