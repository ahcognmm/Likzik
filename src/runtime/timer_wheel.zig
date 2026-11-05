//! Per-worker hashed timer wheel with O(1) schedule and cancel.
//!
//! Timers are intrusive nodes embedded in connection objects, so arming a
//! timer never allocates. Each slot is a doubly linked list; an entry whose
//! deadline lies beyond one revolution simply stays in its slot until its
//! deadline is reached.

const std = @import("std");

pub const tick_ms = 50;
const slots_bits = 10;
const n_slots = 1 << slots_bits;

pub const Timer = struct {
    next: ?*Timer = null,
    prev: ?*Timer = null,
    deadline: u64 = 0,
    armed: bool = false,
    slot: u16 = 0,
    /// Owner tag and index, interpreted by the worker.
    kind: u8 = 0,
    idx: u32 = 0,
    gen: u32 = 0,
};

pub const Wheel = struct {
    slots: [n_slots]?*Timer = [_]?*Timer{null} ** n_slots,
    /// Tick last processed.
    cur_tick: u64,
    count: usize = 0,

    pub fn init(now_ms: u64) Wheel {
        return .{ .cur_tick = now_ms / tick_ms };
    }

    pub fn schedule(self: *Wheel, t: *Timer, deadline_ms: u64) void {
        if (t.armed) self.cancel(t);
        // Round up: when the slot for `tick` is processed, now >= tick *
        // tick_ms >= deadline, so the entry is guaranteed to expire then
        // (rounding down could leave it parked for a whole revolution).
        // Never place a timer in a slot that was already processed.
        const tick = @max((deadline_ms + tick_ms - 1) / tick_ms, self.cur_tick + 1);
        const si: u16 = @intCast(tick & (n_slots - 1));
        const slot = &self.slots[si];
        t.slot = si;
        t.deadline = deadline_ms;
        t.prev = null;
        t.next = slot.*;
        if (slot.*) |head| head.prev = t;
        slot.* = t;
        t.armed = true;
        self.count += 1;
    }

    pub fn cancel(self: *Wheel, t: *Timer) void {
        if (!t.armed) return;
        if (t.prev) |p| {
            p.next = t.next;
        } else {
            std.debug.assert(self.slots[t.slot] == t);
            self.slots[t.slot] = t.next;
        }
        if (t.next) |n| n.prev = t.prev;
        t.next = null;
        t.prev = null;
        t.armed = false;
        self.count -= 1;
    }

    /// Moves time forward and pushes expired timers onto `out` (via the
    /// `next` field, as a singly linked list). Returns the list head.
    pub fn advance(self: *Wheel, now_ms: u64) ?*Timer {
        var expired: ?*Timer = null;
        const target = now_ms / tick_ms;
        var steps: u64 = 0;
        while (self.cur_tick < target) : (steps += 1) {
            self.cur_tick += 1;
            const slot = &self.slots[self.cur_tick & (n_slots - 1)];
            var it = slot.*;
            while (it) |t| {
                const next = t.next;
                if (t.deadline <= now_ms) {
                    // Unlink.
                    if (t.prev) |p| p.next = next else slot.* = next;
                    if (next) |n| n.prev = t.prev;
                    t.armed = false;
                    self.count -= 1;
                    t.prev = null;
                    t.next = expired;
                    expired = t;
                }
                it = next;
            }
            // After one full revolution every slot has been visited.
            if (steps > n_slots) {
                self.cur_tick = target;
                break;
            }
        }
        return expired;
    }
};

test "wheel fires in order of deadline, cancel works" {
    var w = Wheel.init(1000);
    var a: Timer = .{ .idx = 1 };
    var b: Timer = .{ .idx = 2 };
    var c: Timer = .{ .idx = 3 };
    w.schedule(&a, 1100);
    w.schedule(&b, 1200);
    w.schedule(&c, 1000 + 60_000 * 2); // more than one revolution
    try std.testing.expect(w.advance(1090) == null);
    const e1 = w.advance(1150).?;
    try std.testing.expectEqual(@as(u32, 1), e1.idx);
    try std.testing.expect(e1.next == null);
    w.cancel(&b);
    try std.testing.expect(w.advance(1300) == null);
    // c survives passes through its slot before its deadline.
    try std.testing.expect(w.advance(1000 + 60_000) == null);
    const e3 = w.advance(1000 + 60_000 * 2 + 10).?;
    try std.testing.expectEqual(@as(u32, 3), e3.idx);
    try std.testing.expectEqual(@as(usize, 0), w.count);
}

test "reschedule moves a timer" {
    var w = Wheel.init(0);
    var a: Timer = .{};
    w.schedule(&a, 100);
    w.schedule(&a, 500);
    try std.testing.expect(w.advance(200) == null);
    try std.testing.expect(w.advance(600) != null);
}

test "deadline inside a tick fires on that tick, not a revolution later" {
    var w = Wheel.init(1000);
    var a: Timer = .{};
    w.schedule(&a, 1025); // between ticks 20 (1000) and 21 (1050)
    try std.testing.expect(w.advance(1010) == null);
    try std.testing.expect(w.advance(1049) == null);
    try std.testing.expect(w.advance(1050) != null);
}
