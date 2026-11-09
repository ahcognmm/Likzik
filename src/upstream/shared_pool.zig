//! Idle upstream connections shared between workers.
//!
//! Each worker keeps its share of idle connections per endpoint
//! (max_idle_per_endpoint / workers) in its own list; extra idle
//! connections are parked here instead, and a worker that finds no idle
//! connection of its own takes one from here before opening a new one. A
//! parked connection has no ring operation outstanding, so any worker's
//! ring can adopt its socket; plain and kTLS connections move, userspace
//! TLS ones stay with their worker.
//!
//! One small stack per endpoint id behind a spinlock: the critical sections
//! are a few loads and stores, and only workers using the same endpoint
//! meet there. The newest connection is taken first (warmest).

const std = @import("std");
const linux = std.os.linux;
const Address = @import("../net/addr.zig").Address;
const socket = @import("../net/socket.zig");
const region = @import("../mem/region.zig");
const tls_backend = @import("../tls/backend.zig");
const Tls = tls_backend.Tls;

/// Endpoint ids at or above this are not shared.
pub const max_endpoints = 1 << 16;
/// Parked connections per endpoint.
pub const slot_cap = 64;

pub const Entry = struct {
    fd: linux.fd_t,
    addr: Address,
    pool_key: u32,
    tls: ?*Tls.Conn,
    tls_mode: tls_backend.Mode,
    parked_ms: u64,
    idle_timeout_ms: u32,
};

const Slot = struct {
    lock: std.atomic.Value(bool) = .init(false),
    len: u32 = 0,
    items: [slot_cap]Entry = undefined,

    fn acquire(self: *Slot) void {
        while (self.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn release(self: *Slot) void {
        self.lock.store(false, .release);
    }
};

pub const SharedPool = struct {
    gpa: std.mem.Allocator,
    /// Lazily created slot per endpoint id.
    slots: []std.atomic.Value(?*Slot),
    parked: std.atomic.Value(u32) = .init(0),

    pub fn init(gpa: std.mem.Allocator) !SharedPool {
        const slots = try region.alloc(std.atomic.Value(?*Slot), max_endpoints);
        return .{ .gpa = gpa, .slots = slots };
    }

    /// Closes everything parked (no worker is running any more).
    pub fn deinit(self: *SharedPool) void {
        for (self.slots) |*sp| if (sp.load(.acquire)) |s| {
            for (s.items[0..s.len]) |*e| discard(e);
            self.gpa.destroy(s);
        };
        region.free(std.atomic.Value(?*Slot), self.slots);
    }

    fn slot(self: *SharedPool, ep_id: u32, create: bool) ?*Slot {
        if (ep_id >= max_endpoints) return null;
        const sp = &self.slots[ep_id];
        if (sp.load(.acquire)) |s| return s;
        if (!create) return null;
        const s = self.gpa.create(Slot) catch return null;
        s.* = .{};
        if (sp.cmpxchgStrong(null, s, .acq_rel, .acquire)) |winner| {
            self.gpa.destroy(s);
            return winner;
        }
        return s;
    }

    /// Parks a connection. False when the endpoint's stack is full (the
    /// caller closes the connection).
    pub fn park(self: *SharedPool, ep_id: u32, e: Entry, limit: u32) bool {
        const s = self.slot(ep_id, true) orelse return false;
        s.acquire();
        defer s.release();
        if (s.len >= @min(limit, slot_cap)) return false;
        s.items[s.len] = e;
        s.len += 1;
        _ = self.parked.fetchAdd(1, .monotonic);
        return true;
    }

    /// Takes the newest parked connection for `pool_key`, if any. Expired
    /// entries met on the way are closed. The caller checks liveness.
    pub fn take(self: *SharedPool, ep_id: u32, pool_key: u32, now_ms: u64) ?Entry {
        const s = self.slot(ep_id, false) orelse return null;
        if (@atomicLoad(u32, &s.len, .monotonic) == 0) return null; // racy fast path
        var expired: [8]Entry = undefined;
        var n_expired: usize = 0;
        var found: ?Entry = null;
        s.acquire();
        var i: usize = s.len;
        while (i > 0) {
            i -= 1;
            const e = s.items[i];
            const stale = now_ms -| e.parked_ms >= e.idle_timeout_ms;
            if (!stale and e.pool_key != pool_key) continue;
            if (stale and n_expired == expired.len) continue;
            removeAt(s, i);
            _ = self.parked.fetchSub(1, .monotonic);
            if (stale) {
                expired[n_expired] = e;
                n_expired += 1;
                continue;
            }
            found = e;
            break;
        }
        s.release();
        for (expired[0..n_expired]) |*e| discard(e);
        return found;
    }

    /// Control thread: closes parked connections past their idle timeout.
    pub fn sweep(self: *SharedPool, now_ms: u64) void {
        for (self.slots) |*sp| {
            const s = sp.load(.acquire) orelse continue;
            if (@atomicLoad(u32, &s.len, .monotonic) == 0) continue;
            var expired: [slot_cap]Entry = undefined;
            var n: usize = 0;
            s.acquire();
            var i: usize = s.len;
            while (i > 0) {
                i -= 1;
                if (now_ms -| s.items[i].parked_ms < s.items[i].idle_timeout_ms) continue;
                expired[n] = s.items[i];
                n += 1;
                removeAt(s, i);
            }
            s.release();
            if (n > 0) _ = self.parked.fetchSub(@intCast(n), .monotonic);
            for (expired[0..n]) |*e| discard(e);
        }
    }
};

fn removeAt(s: *Slot, i: usize) void {
    var j = i;
    while (j + 1 < s.len) : (j += 1) s.items[j] = s.items[j + 1];
    s.len -= 1;
}

/// Closes a parked connection.
pub fn discard(e: *const Entry) void {
    if (e.tls) |t| Tls.freeConn(t);
    socket.closeFd(e.fd);
}

/// True when the parked socket still looks usable: nothing to read (no
/// EOF, no stray bytes, no error) without blocking.
pub fn alive(fd: linux.fd_t) bool {
    var b: [1]u8 = undefined;
    _ = socket.recvNb(fd, &b, true) catch |e| return e == error.WouldBlock;
    return false;
}

test "park, take by key, expiry and liveness" {
    var p = try SharedPool.init(std.testing.allocator);
    defer p.deinit();
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds));
    const base: Entry = .{ .fd = fds[0], .addr = try Address.parse("127.0.0.1:1"), .pool_key = 7, .tls = null, .tls_mode = .none, .parked_ms = 1000, .idle_timeout_ms = 500 };
    try std.testing.expect(p.park(3, base, 4));
    try std.testing.expect(p.take(3, 8, 1100) == null); // other pool key
    const got = p.take(3, 7, 1100).?;
    try std.testing.expectEqual(fds[0], got.fd);
    try std.testing.expect(alive(got.fd)); // peer open, nothing sent
    _ = linux.write(fds[1], "x", 1);
    try std.testing.expect(!alive(got.fd)); // stray bytes: not reusable
    try std.testing.expect(p.park(3, got, 4));
    try std.testing.expect(p.take(3, 7, 2000) == null); // expired: closed on the way
    try std.testing.expectEqual(@as(u32, 0), p.parked.load(.monotonic));
    socket.closeFd(fds[1]);
}
