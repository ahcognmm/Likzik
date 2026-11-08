//! Per-worker, per-cluster load accounting for circuit breaking and the
//! retry budget. Limits in the config are for the whole process; each
//! worker enforces its share (limit / workers, rounded up), so no counter
//! is shared between threads.

const std = @import("std");

pub const ClusterState = struct {
    /// Requests bound to the cluster and not finished.
    active_rq: u32 = 0,
    /// Upstream connections this worker opened for the cluster.
    active_cx: u32 = 0,
    /// Requests currently being retried.
    active_retries: u32 = 0,
};

pub const Table = struct {
    items: std.ArrayList(ClusterState) = .empty,

    pub fn get(self: *Table, gpa: std.mem.Allocator, id: u32) !*ClusterState {
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

/// This worker's share of a process-wide limit (0 = unlimited).
pub fn share(limit: u32, workers: usize) u32 {
    if (limit == 0) return std.math.maxInt(u32);
    const w: u32 = @intCast(@max(workers, 1));
    return (limit + w - 1) / w;
}

/// Retries may use `budget_percent` of the active requests, but at least
/// `min_retry_concurrency` at a time, so low traffic can still retry.
pub const min_retry_concurrency = 3;

pub fn retryAllowed(st: *const ClusterState, budget_percent: u8, max_retries: u32, workers: usize) bool {
    if (st.active_retries >= share(max_retries, workers)) return false;
    const budget = @max(min_retry_concurrency, st.active_rq * budget_percent / 100);
    return st.active_retries < budget;
}

test "shares and retry budget" {
    try std.testing.expectEqual(@as(u32, 3), share(10, 4));
    try std.testing.expectEqual(std.math.maxInt(u32), share(0, 4));
    var st: ClusterState = .{ .active_rq = 100 };
    try std.testing.expect(retryAllowed(&st, 20, 0, 1));
    st.active_retries = 20;
    try std.testing.expect(!retryAllowed(&st, 20, 0, 1)); // 20% of 100 used
    st = .{ .active_rq = 1, .active_retries = 2 };
    try std.testing.expect(retryAllowed(&st, 20, 0, 1)); // minimum concurrency
    try std.testing.expect(!retryAllowed(&st, 20, 4, 2)); // max_retries 4 over 2 workers
}
