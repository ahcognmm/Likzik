//! Local rate limiting: token buckets in one table shared by all workers
//! of the process.
//!
//! The plan proposed per-worker buckets with "global rate / workers". That
//! under-limits a client whose connections all land on one worker
//! (SO_REUSEPORT hashes connections, not requests): it would get rate/N.
//! A shared table keeps "100 req/s per IP" exact. Each bucket has its own
//! spinlock, held for a few nanoseconds and touched only by requests on a
//! rate-limited route, so contention needs the same key hit on several
//! workers at the same instant.
//!
//! The table has a fixed size (no allocation per new key). When a probe
//! window is full, the stalest bucket is reused, so with more distinct
//! keys than slots, limits get looser, never stricter.

const std = @import("std");

pub const slots = 1 << 16;
const probe = 8;
/// Fixed-point scale for tokens: precise enough for slow rates
/// (2 per minute) and large enough for bursts in the millions.
const scale: u64 = 1_000_000_000;

const Bucket = struct {
    lock: std.atomic.Value(u32) align(64) = .init(0),
    key: u64 = 0,
    /// Tokens, scaled by 1e9 (see `scale`).
    tokens: u64 = 0,
    last_ms: u64 = 0,

    fn acquire(self: *Bucket) void {
        while (self.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn release(self: *Bucket) void {
        self.lock.store(0, .release);
    }
};

pub const Table = struct {
    buckets: []Bucket,

    pub fn init(gpa: std.mem.Allocator) !*Table {
        const t = try gpa.create(Table);
        t.buckets = try gpa.alloc(Bucket, slots);
        for (t.buckets) |*b| b.* = .{};
        return t;
    }

    pub fn deinit(self: *Table, gpa: std.mem.Allocator) void {
        gpa.free(self.buckets);
        gpa.destroy(self);
    }

    pub const Limit = struct {
        /// Tokens added per millisecond, scaled by 1e9 (see `scale`).
        rate_per_ms: u64,
        /// Bucket capacity, scaled by 1e9 (see `scale`).
        capacity: u64,
        requests: u32,
        period_ms: u64,

        pub fn init(requests: u32, period_ms: u64, burst: u32) Limit {
            const per_ms = (@as(u64, requests) * scale) / period_ms;
            return .{ .rate_per_ms = @max(per_ms, 1), .capacity = @as(u64, @max(burst, 1)) * scale, .requests = requests, .period_ms = period_ms };
        }
    };

    pub const Outcome = struct {
        allowed: bool,
        /// Whole requests left after this one (allowed) or 0.
        remaining: u64,
        /// When denied: milliseconds until one request is available.
        retry_after_ms: u64,
    };

    /// Takes one token for `key` (a hash; 0 is reserved and remapped).
    pub fn take(self: *Table, key_in: u64, limit: Limit, now_ms: u64) Outcome {
        const key = if (key_in == 0) 1 else key_in;
        const mask = slots - 1;
        const start = key & mask;
        var chosen: *Bucket = &self.buckets[start];
        var found = false;
        var oldest: u64 = std.math.maxInt(u64);
        var i: u64 = 0;
        while (i < probe) : (i += 1) {
            const b = &self.buckets[(start + i) & mask];
            const k = @atomicLoad(u64, &b.key, .acquire);
            if (k == key) {
                chosen = b;
                found = true;
                break;
            }
            if (k == 0) {
                chosen = b;
                oldest = 0;
                break;
            }
            const last = @atomicLoad(u64, &b.last_ms, .monotonic);
            if (last < oldest) {
                oldest = last;
                chosen = b;
            }
        }
        const b = chosen;
        b.acquire();
        defer b.release();
        if (b.key != key) {
            // New (or reclaimed) bucket starts full.
            @atomicStore(u64, &b.key, key, .release);
            b.tokens = limit.capacity;
            @atomicStore(u64, &b.last_ms, now_ms, .monotonic);
        } else if (!found) {
            // Another worker claimed it for the same key meanwhile: fine.
        }
        if (now_ms > b.last_ms) {
            const add = (now_ms - b.last_ms) *| limit.rate_per_ms;
            b.tokens = @min(limit.capacity, b.tokens +| add);
            @atomicStore(u64, &b.last_ms, now_ms, .monotonic);
        }
        if (b.tokens >= scale) {
            b.tokens -= scale;
            return .{ .allowed = true, .remaining = b.tokens / scale, .retry_after_ms = 0 };
        }
        const missing = scale - b.tokens;
        return .{ .allowed = false, .remaining = 0, .retry_after_ms = (missing + limit.rate_per_ms - 1) / limit.rate_per_ms };
    }
};

pub fn keyHash(limit_index: usize, parts: []const []const u8) u64 {
    var h = std.hash.Wyhash.init(@as(u64, limit_index) *% 0x9e3779b97f4a7c15);
    for (parts) |p| {
        h.update(p);
        h.update(&.{0});
    }
    return h.final();
}

test "token bucket: burst, refill, retry-after" {
    const t = try Table.init(std.testing.allocator);
    defer t.deinit(std.testing.allocator);
    const lim = Table.Limit.init(10, 1000, 5); // 10/s, burst 5
    const k = keyHash(0, &.{"1.2.3.4"});
    var now: u64 = 1_000;
    for (0..5) |_| try std.testing.expect(t.take(k, lim, now).allowed);
    const denied = t.take(k, lim, now);
    try std.testing.expect(!denied.allowed);
    try std.testing.expectEqual(@as(u64, 100), denied.retry_after_ms);
    now += 100; // one token back
    try std.testing.expect(t.take(k, lim, now).allowed);
    try std.testing.expect(!t.take(k, lim, now).allowed);
    // Other keys are independent.
    try std.testing.expect(t.take(keyHash(0, &.{"5.6.7.8"}), lim, now).allowed);
    // Long idle: refill capped at the burst.
    now += 60_000;
    for (0..5) |_| try std.testing.expect(t.take(k, lim, now).allowed);
    try std.testing.expect(!t.take(k, lim, now).allowed);
}

test "slow rates (fewer requests than periods)" {
    const t = try Table.init(std.testing.allocator);
    defer t.deinit(std.testing.allocator);
    const lim = Table.Limit.init(2, 60_000, 2); // 2 per minute
    const k = keyHash(1, &.{"x"});
    try std.testing.expect(t.take(k, lim, 0).allowed);
    try std.testing.expect(t.take(k, lim, 0).allowed);
    const d = t.take(k, lim, 0);
    try std.testing.expect(!d.allowed);
    try std.testing.expect(d.retry_after_ms >= 30_000 and d.retry_after_ms <= 30_001);
    // Retrying after the advertised delay succeeds.
    try std.testing.expect(t.take(k, lim, d.retry_after_ms).allowed);
}

test "shared across threads: the total never exceeds the budget" {
    const t = try Table.init(std.testing.allocator);
    defer t.deinit(std.testing.allocator);
    const lim = Table.Limit.init(1, 3_600_000, 1000); // 1000 burst, ~no refill
    const k = keyHash(2, &.{"shared"});
    var allowed: std.atomic.Value(u32) = .init(0);
    const Worker = struct {
        fn run(tt: *Table, l: Table.Limit, key: u64, a: *std.atomic.Value(u32)) void {
            for (0..1000) |_| {
                if (tt.take(key, l, 5).allowed) _ = a.fetchAdd(1, .monotonic);
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*th| th.* = try std.Thread.spawn(.{}, Worker.run, .{ t, lim, k, &allowed });
    for (threads) |th| th.join();
    try std.testing.expectEqual(@as(u32, 1000), allowed.load(.monotonic));
}
