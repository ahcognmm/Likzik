//! RCU-style publication of immutable snapshots with epoch-based
//! reclamation.
//!
//! * The control thread publishes a new snapshot with one atomic pointer
//!   store and bumps the generation.
//! * A worker loads the pointer when a request starts and keeps using that
//!   snapshot until the request ends.
//! * At quiescent points (once per event-loop iteration) each worker
//!   stores the oldest generation it still uses. The control thread frees
//!   a retired snapshot once every worker has moved past it.

const std = @import("std");
const Snapshot = @import("snapshot.zig").Snapshot;

pub const idle_epoch = std.math.maxInt(u64);

pub const EpochSlot = struct {
    v: std.atomic.Value(u64) align(std.atomic.cache_line) = .init(0),
};

pub const Rcu = struct {
    gpa: std.mem.Allocator,
    current: std.atomic.Value(*Snapshot),
    generation: std.atomic.Value(u64),
    epochs: []EpochSlot,
    /// Control thread only.
    retired: std.ArrayList(*Snapshot) = .empty,

    pub fn init(gpa: std.mem.Allocator, first: *Snapshot, n_workers: usize) !Rcu {
        first.generation = 1;
        const epochs = try gpa.alloc(EpochSlot, n_workers);
        for (epochs) |*e| e.* = .{ .v = .init(1) };
        return .{ .gpa = gpa, .current = .init(first), .generation = .init(1), .epochs = epochs };
    }

    pub fn deinit(self: *Rcu) void {
        for (self.retired.items) |s| s.destroy();
        self.retired.deinit(self.gpa);
        self.current.load(.acquire).destroy();
        self.gpa.free(self.epochs);
    }

    pub fn load(self: *Rcu) *Snapshot {
        return self.current.load(.acquire);
    }

    /// Control thread: publish `s`; the old snapshot is retired.
    pub fn publish(self: *Rcu, s: *Snapshot) !void {
        try self.retired.ensureUnusedCapacity(self.gpa, 1);
        const g = self.generation.load(.monotonic) + 1;
        s.generation = g;
        const old = self.current.swap(s, .acq_rel);
        self.generation.store(g, .release);
        self.retired.appendAssumeCapacity(old);
    }

    /// Worker `w`: report the oldest generation still in use.
    pub fn quiesce(self: *Rcu, w: usize, oldest_in_use: u64) void {
        self.epochs[w].v.store(oldest_in_use, .release);
    }

    pub fn minEpoch(self: *Rcu) u64 {
        var m: u64 = idle_epoch;
        for (self.epochs) |*e| m = @min(m, e.v.load(.acquire));
        return m;
    }

    /// Control thread: frees retired snapshots no worker can still see.
    pub fn reclaim(self: *Rcu) usize {
        const min = self.minEpoch();
        var freed: usize = 0;
        var i: usize = 0;
        while (i < self.retired.items.len) {
            const s = self.retired.items[i];
            if (s.generation < min) {
                s.destroy();
                _ = self.retired.swapRemove(i);
                freed += 1;
            } else i += 1;
        }
        return freed;
    }
};

/// Worker-side bookkeeping: which snapshots this worker's in-flight
/// requests still hold, with counts. Tiny (old snapshots drain quickly).
pub const Pins = struct {
    const Entry = struct { snap: *Snapshot, count: u32 };
    entries: [16]Entry = undefined,
    len: usize = 0,

    pub fn pin(self: *Pins, s: *Snapshot) bool {
        for (self.entries[0..self.len]) |*e| if (e.snap == s) {
            e.count += 1;
            return true;
        };
        if (self.len == self.entries.len) return false;
        self.entries[self.len] = .{ .snap = s, .count = 1 };
        self.len += 1;
        return true;
    }

    pub fn unpin(self: *Pins, s: *Snapshot) void {
        for (self.entries[0..self.len], 0..) |*e, i| if (e.snap == s) {
            e.count -= 1;
            if (e.count == 0) {
                self.entries[i] = self.entries[self.len - 1];
                self.len -= 1;
            }
            return;
        };
        unreachable;
    }

    pub fn oldest(self: *const Pins, current_gen: u64) u64 {
        var m = current_gen;
        for (self.entries[0..self.len]) |e| m = @min(m, e.snap.generation);
        return m;
    }
};

test "pins track the oldest generation" {
    var a: Snapshot = undefined;
    a.generation = 3;
    var b: Snapshot = undefined;
    b.generation = 5;
    var p: Pins = .{};
    try std.testing.expect(p.pin(&a));
    try std.testing.expect(p.pin(&b));
    try std.testing.expect(p.pin(&a));
    try std.testing.expectEqual(@as(u64, 3), p.oldest(6));
    p.unpin(&a);
    try std.testing.expectEqual(@as(u64, 3), p.oldest(6));
    p.unpin(&a);
    try std.testing.expectEqual(@as(u64, 5), p.oldest(6));
    p.unpin(&b);
    try std.testing.expectEqual(@as(u64, 6), p.oldest(6));
}
