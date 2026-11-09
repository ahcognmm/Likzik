//! A worker: one thread, pinned to one core, with its own io_uring, its
//! own provided-buffer ring, its own pools and its own SO_REUSEPORT
//! listeners. Workers share nothing on the hot path; the only shared
//! state is the RCU snapshot pointer and per-worker stats blocks.

const std = @import("std");
const linux = std.os.linux;

const loop_mod = @import("loop.zig");
const Loop = loop_mod.Loop;
const Op = loop_mod.Op;
const Ud = loop_mod.Ud;
const BufRing = @import("buf_ring.zig").BufRing;
const tw = @import("timer_wheel.zig");
const sq = @import("send_queue.zig");
const Blocks = @import("../mem/blocks.zig").Blocks;
const Pool = @import("../mem/pool.zig").Pool;
const rcu_mod = @import("../config/rcu.zig");
const snapshot = @import("../config/snapshot.zig");
const stats_mod = @import("../observe/stats.zig");
const health = @import("../upstream/health.zig");
const lb = @import("../upstream/lb.zig");
const socket = @import("../net/socket.zig");
const Address = @import("../net/addr.zig").Address;
const http = @import("../proxy/http.zig");
const upool = @import("../upstream/pool.zig");
const tcp = @import("../l4/tcp_proxy.zig");
const filter = @import("../proxy/filter.zig");
const mirror = @import("../proxy/mirror.zig");

const log = std.log.scoped(.worker);

pub const buffer_group: u16 = 0;
pub const max_listeners = 64;

pub const TimerKind = enum(u8) { down = 1, up = 2, tunnel = 3, shadow = 4 };

/// Process-wide state shared between main, the control thread and workers.
pub const Shared = struct {
    rcu: *rcu_mod.Rcu,
    stats: []stats_mod.WorkerStats,
    /// Ring fd of each worker once it is running; -1 before, -2 on failure.
    ring_fds: []std.atomic.Value(i32),
    /// Tuning that is fixed for the process lifetime.
    pbuf_size: u32 = 16 * 1024,
    /// Each worker's extension state, for the control thread's metrics.
    ext_states: []?*anyopaque = &.{},
    /// One access log ring per worker (drained by the control thread).
    access_logs: []@import("../observe/access_log.zig").Ring = &.{},
    /// Active health check results, one byte per endpoint id.
    ep_down: []const std.atomic.Value(u8) = &.{},
    health: ?*@import("../upstream/active_health.zig").ActiveHealth = null,
    xds: ?*@import("../config/sources/xds.zig").Client = null,
    pbuf_count: u16 = 256,
    pin_cpus: bool = true,
};

/// Wake reasons carried in the MSG_RING CQE result.
pub const Wake = enum(u32) { config = 0, drain = 1 };

pub const WListener = struct {
    fd: linux.fd_t = -1,
    active: bool = false,
    /// Index into the current snapshot's listeners (valid while active).
    snap_idx: u16 = 0,
    name_buf: [64]u8 = undefined,
    name_len: u8 = 0,
    addr: Address = undefined,
    protocol: @import("../config/model.zig").Protocol = .http,
    accept_armed: bool = false,
    /// Accept SQE outstanding (counts toward pending).
    pending: u16 = 0,
    gen: u32 = 1,
    /// Live connections accepted on this listener.
    conns: u32 = 0,

    pub fn name(self: *const WListener) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const Reap = struct { kind: TimerKind, idx: u32, gen: u32 };

pub const Worker = struct {
    id: u16,
    gpa: std.mem.Allocator,
    shared: *Shared,
    loop: Loop,
    bufs: BufRing,
    blocks: Blocks,
    segs: sq.SegPool,
    downs: Pool(http.Down),
    ups: Pool(upool.Up),
    tunnels: Pool(tcp.Tunnel),
    shadows: Pool(mirror.Shadow),
    listeners: [max_listeners]WListener = @splat(.{}),
    cur: *snapshot.Snapshot,
    pins: rcu_mod.Pins = .{},
    eps: health.Table = .{},
    /// Per-cluster load for circuit breakers and the retry budget.
    cluster_load: @import("../upstream/breaker.zig").Table = .{},
    wheel: tw.Wheel,
    now_ms: u64,
    prng: std.Random.DefaultPrng,
    stats: *stats_mod.WorkerStats,
    /// Per-worker state of the registered extension (null without one).
    ext_ws: ?*anyopaque = null,
    reap: std.ArrayList(Reap) = .empty,
    rearm_downs: std.ArrayList(Reap) = .empty,
    rearm_ups: std.ArrayList(Reap) = .empty,
    /// Userspace-TLS connections to read from at the end of this
    /// iteration (reads are deferred to avoid re-entering the state
    /// machine from inside itself).
    tls_kicks: std.ArrayList(Reap) = .empty,
    /// Connections with queued output, flushed once after the current
    /// completion is handled (so a head and a small body coalesce into
    /// one send).
    dirty_downs: std.ArrayList(Reap) = .empty,
    dirty_ups: std.ArrayList(Reap) = .empty,
    draining: bool = false,
    drain_deadline_ms: u64 = 0,
    /// Set by CPU-heavy work (TLS handshakes): flush queued SQEs right away
    /// so sends are not held behind the rest of the completion batch.
    flush_now: bool = false,
    tick_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = tw.tick_ms * std.time.ns_per_ms },
    cqes: [512]linux.io_uring_cqe = undefined,

    pub fn nowMs() u64 {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
    }

    pub fn init(self: *Worker, gpa: std.mem.Allocator, id: u16, shared: *Shared) !void {
        const snap = shared.rcu.load();
        const max_conns = snap.limits.max_connections_per_worker;
        const now = nowMs();
        self.* = .{
            .id = id,
            .gpa = gpa,
            .shared = shared,
            .loop = try Loop.init(4096),
            .bufs = undefined,
            .blocks = undefined,
            .segs = undefined,
            .downs = undefined,
            .ups = undefined,
            .tunnels = undefined,
            .shadows = undefined,
            .cur = snap,
            .wheel = tw.Wheel.init(now),
            .now_ms = now,
            .prng = std.Random.DefaultPrng.init(@as(u64, id) *% 0x9e3779b97f4a7c15 ^ now),
            .stats = &shared.stats[id],
        };
        errdefer self.loop.deinit();
        self.bufs = try BufRing.init(gpa, &self.loop.ring, buffer_group, shared.pbuf_size, shared.pbuf_count);
        errdefer self.bufs.deinit(gpa);
        self.blocks = try Blocks.init(gpa, max_conns + 256);
        errdefer self.blocks.deinit(gpa);
        self.segs = try sq.SegPool.init(gpa, max_conns * 8 + 1024);
        errdefer self.segs.deinit(gpa);
        self.downs = try Pool(http.Down).init(gpa, max_conns);
        errdefer self.downs.deinit(gpa);
        self.ups = try Pool(upool.Up).init(gpa, max_conns);
        errdefer self.ups.deinit(gpa);
        self.tunnels = try Pool(tcp.Tunnel).init(gpa, max_conns);
        self.shadows = try Pool(mirror.Shadow).init(gpa, mirror.max_in_flight);
        if (filter.registered) |ext| {
            self.ext_ws = try ext.initWorker(gpa, id, @intCast(shared.stats.len));
            if (id < shared.ext_states.len) @atomicStore(?*anyopaque, &shared.ext_states[id], self.ext_ws, .release);
        }
        self.stats.set(.snapshot_generation, snap.generation);
    }

    pub fn deinit(self: *Worker) void {
        if (filter.registered) |ext| if (self.ext_ws) |ws| {
            if (self.id < self.shared.ext_states.len) @atomicStore(?*anyopaque, &self.shared.ext_states[self.id], null, .release);
            ext.deinitWorker(self.gpa, ws);
        };
        for (&self.listeners) |*l| if (l.fd >= 0) socket.closeFd(l.fd);
        self.reap.deinit(self.gpa);
        self.rearm_downs.deinit(self.gpa);
        self.rearm_ups.deinit(self.gpa);
        self.tls_kicks.deinit(self.gpa);
        self.dirty_downs.deinit(self.gpa);
        self.dirty_ups.deinit(self.gpa);
        self.eps.deinit(self.gpa);
        self.cluster_load.deinit(self.gpa);
        self.tunnels.deinit(self.gpa);
        self.shadows.deinit(self.gpa);
        self.ups.deinit(self.gpa);
        self.downs.deinit(self.gpa);
        self.segs.deinit(self.gpa);
        self.blocks.deinit(self.gpa);
        self.bufs.deinit(self.gpa);
        self.loop.deinit();
    }

    /// Thread entry point.
    pub fn main(gpa: std.mem.Allocator, id: u16, shared: *Shared) void {
        if (shared.pin_cpus) pinToCpu(id);
        var w: Worker = undefined;
        w.init(gpa, id, shared) catch |e| {
            log.err("worker {d}: init failed: {s}", .{ id, @errorName(e) });
            shared.ring_fds[id].store(-2, .release);
            return;
        };
        defer w.deinit();
        w.reconcileListeners(true) catch {
            shared.ring_fds[id].store(-2, .release);
            return;
        };
        shared.ring_fds[id].store(w.loop.ring.fd, .release);
        w.run();
    }

    fn pinToCpu(id: u16) void {
        const n = std.Thread.getCpuCount() catch return;
        var set: linux.cpu_set_t = std.mem.zeroes(linux.cpu_set_t);
        const cpu = id % n;
        set[cpu / @bitSizeOf(usize)] |= @as(usize, 1) << @intCast(cpu % @bitSizeOf(usize));
        linux.sched_setaffinity(0, &set) catch {};
    }

    pub fn ud(op: Op, idx: u32, gen: u32) u64 {
        return Ud.encode(op, idx, gen);
    }

    // ------------------------------------------------------------ loop

    pub fn run(self: *Worker) void {
        self.loop.tickTimer(&self.tick_ts, ud(.tick, 0, 0));
        while (true) {
            self.loop.submitAndWait(1) catch |e| {
                log.err("worker {d}: io_uring_enter failed: {s}", .{ self.id, @errorName(e) });
                return;
            };
            self.now_ms = nowMs();
            while (true) {
                const n = self.loop.ring.copy_cqes(&self.cqes, 0) catch 0;
                for (self.cqes[0..n]) |*cqe| {
                    self.dispatch(cqe);
                    self.flushDirty();
                    if (self.flush_now or self.loop.ring.sq_ready() >= 64) {
                        self.flush_now = false;
                        _ = self.loop.ring.submit() catch {};
                    }
                }
                if (n < self.cqes.len) break;
            }
            self.processTlsKicks();
            self.flushDirty();
            self.processReap();
            self.processRearm();
            self.checkSnapshot();
            self.shared.rcu.quiesce(self.id, self.pins.oldest(self.cur.generation));
            if (self.draining and self.drainDone()) break;
        }
        self.shutdownAll();
    }

    fn dispatch(self: *Worker, cqe: *const linux.io_uring_cqe) void {
        const u = Ud.decode(cqe.user_data);
        switch (u.op) {
            .ignore => {},
            .tick => self.onTick(cqe),
            .wake => self.onWake(cqe),
            .accept => self.onAccept(u, cqe),
            .d_recv => http.onDownRecv(self, u.idx, cqe),
            .d_send => http.onDownSend(self, u.idx, cqe),
            .u_connect => http.onUpConnect(self, u.idx, cqe),
            .u_recv => http.onUpRecv(self, u.idx, cqe),
            .u_send => http.onUpSend(self, u.idx, cqe),
            .t_in_d, .t_in_u, .t_out_d, .t_out_u, .t_connect, .t_pre => tcp.onEvent(self, u, cqe),
            .d_pre => http.onDownPreamble(self, u.idx, cqe),
            .m_connect, .m_send, .m_read => mirror.onEvent(self, u, cqe),
            .d_tls_in => http.onDownTlsEvent(self, u.idx, true, cqe),
            .d_tls_out => http.onDownTlsEvent(self, u.idx, false, cqe),
            .u_tls_in => http.onUpTlsEvent(self, u.idx, true, cqe),
            .u_tls_out => http.onUpTlsEvent(self, u.idx, false, cqe),
        }
    }

    pub fn releaseOwner(self: *Worker, o: sq.Owner) void {
        switch (o) {
            .none => {},
            .pbuf => |id| self.bufs.unref(id),
            .block => |id| self.blocks.unref(id),
        }
    }

    pub fn schedule(self: *Worker, t: *tw.Timer, kind: TimerKind, idx: u32, gen: u32, after_ms: u64) void {
        t.kind = @intFromEnum(kind);
        t.idx = idx;
        t.gen = gen;
        self.wheel.schedule(t, self.now_ms + after_ms);
    }

    pub fn reapLater(self: *Worker, kind: TimerKind, idx: u32, gen: u32) void {
        self.reap.append(self.gpa, .{ .kind = kind, .idx = idx, .gen = gen }) catch {
            // Allocation failure: the next loop iteration retries via timers.
        };
    }

    fn processReap(self: *Worker) void {
        var i: usize = 0;
        while (i < self.reap.items.len) : (i += 1) {
            const r = self.reap.items[i];
            switch (r.kind) {
                .down => if (self.downs.valid(r.idx, r.gen)) http.maybeFreeDown(self, r.idx),
                .up => if (self.ups.valid(r.idx, r.gen)) upool.maybeFree(self, r.idx),
                .tunnel => if (self.tunnels.valid(r.idx, r.gen)) tcp.maybeFree(self, r.idx),
                .shadow => if (self.shadows.valid(r.idx, r.gen)) mirror.maybeFree(self, r.idx),
            }
        }
        self.reap.clearRetainingCapacity();
    }

    pub fn needRearm(self: *Worker, kind: TimerKind, idx: u32, gen: u32) void {
        const list = if (kind == .down) &self.rearm_downs else &self.rearm_ups;
        list.append(self.gpa, .{ .kind = kind, .idx = idx, .gen = gen }) catch {};
    }

    pub fn markDirty(self: *Worker, kind: TimerKind, idx: u32, gen: u32) void {
        const list = if (kind == .down) &self.dirty_downs else &self.dirty_ups;
        list.append(self.gpa, .{ .kind = kind, .idx = idx, .gen = gen }) catch {
            // Out of memory: flush right away instead.
            if (kind == .down) http.flushDownNow(self, idx) else upool.flushNow(self, idx);
        };
    }

    fn flushDirty(self: *Worker) void {
        if (self.dirty_downs.items.len == 0 and self.dirty_ups.items.len == 0) return;
        // Ups first: request bytes go out before we look at more input.
        var i: usize = 0;
        while (i < self.dirty_ups.items.len) : (i += 1) {
            const r = self.dirty_ups.items[i];
            if (self.ups.valid(r.idx, r.gen)) upool.flushNow(self, r.idx);
        }
        self.dirty_ups.clearRetainingCapacity();
        i = 0;
        while (i < self.dirty_downs.items.len) : (i += 1) {
            const r = self.dirty_downs.items[i];
            if (self.downs.valid(r.idx, r.gen)) http.flushDownNow(self, r.idx);
        }
        self.dirty_downs.clearRetainingCapacity();
    }

    pub fn tlsKick(self: *Worker, kind: TimerKind, idx: u32, gen: u32) void {
        self.tls_kicks.append(self.gpa, .{ .kind = kind, .idx = idx, .gen = gen }) catch {};
    }

    fn processTlsKicks(self: *Worker) void {
        // Kicks may queue more kicks; process until quiet (bounded).
        var rounds: u8 = 0;
        while (self.tls_kicks.items.len > 0 and rounds < 8) : (rounds += 1) {
            var list = self.tls_kicks;
            self.tls_kicks = .empty;
            for (list.items) |k| switch (k.kind) {
                .down => if (self.downs.valid(k.idx, k.gen)) http.tlsReadDown(self, k.idx),
                .up => if (self.ups.valid(k.idx, k.gen)) http.tlsReadUp(self, k.idx),
                .tunnel, .shadow => {},
            };
            list.deinit(self.gpa);
        }
    }

    fn processRearm(self: *Worker) void {
        // Only re-arm when the buffer ring has buffers again.
        if (self.bufs.out >= self.bufs.count) return;
        for (self.rearm_downs.items) |r| if (self.downs.valid(r.idx, r.gen)) http.updateDownRecv(self, r.idx);
        for (self.rearm_ups.items) |r| if (self.ups.valid(r.idx, r.gen)) upool.updateRecv(self, r.idx);
        self.rearm_downs.clearRetainingCapacity();
        self.rearm_ups.clearRetainingCapacity();
    }

    fn onTick(self: *Worker, cqe: *const linux.io_uring_cqe) void {
        if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
            self.loop.tickTimer(&self.tick_ts, ud(.tick, 0, 0));
        }
        var it = self.wheel.advance(self.now_ms);
        while (it) |t| {
            it = t.next;
            t.next = null;
            switch (@as(TimerKind, @enumFromInt(t.kind))) {
                .down => if (self.downs.valid(t.idx, t.gen)) http.onDownTimer(self, t.idx),
                .up => if (self.ups.valid(t.idx, t.gen)) upool.onTimer(self, t.idx),
                .tunnel => if (self.tunnels.valid(t.idx, t.gen)) tcp.onTimer(self, t.idx),
                .shadow => if (self.shadows.valid(t.idx, t.gen)) mirror.onTimer(self, t.idx),
            }
        }
        // Re-arm accepts that failed transiently (EMFILE and friends).
        for (&self.listeners, 0..) |*l, i| {
            if (l.active and !l.accept_armed and !self.draining) self.armAccept(@intCast(i));
        }
        self.stats.set(.upstream_cx_idle, self.countIdle());
    }

    fn countIdle(self: *Worker) u64 {
        var n: u64 = 0;
        for (self.eps.items.items) |e| n += e.idle_count;
        return n;
    }

    fn onWake(self: *Worker, cqe: *const linux.io_uring_cqe) void {
        const code: u32 = @bitCast(cqe.res);
        if (code == @intFromEnum(Wake.drain)) self.startDrain();
        // Wake.config: checkSnapshot runs at the end of every iteration.
    }

    // ------------------------------------------------------------ snapshot

    fn checkSnapshot(self: *Worker) void {
        const s = self.shared.rcu.load();
        if (s == self.cur) return;
        self.cur = s;
        self.stats.set(.snapshot_generation, s.generation);
        self.stats.inc(.snapshot_swaps);
        self.reconcileListeners(false) catch {};
    }

    /// Requests started from now on use the current snapshot.
    pub fn pinCurrent(self: *Worker) ?*snapshot.Snapshot {
        if (!self.pins.pin(self.cur)) return null;
        return self.cur;
    }

    pub fn unpin(self: *Worker, s: *snapshot.Snapshot) void {
        self.pins.unpin(s);
    }

    /// Passive health: counts a connect failure or a 5xx from an endpoint
    /// and ejects it at the cluster's threshold, unless that would pass
    /// max_ejection_percent.
    pub fn endpointFailed(self: *Worker, c: *const snapshot.Cluster, ep_id: u32, kind: health.Failure) void {
        const st = self.eps.get(self.gpa, ep_id) catch return;
        const threshold = switch (kind) {
            .connect => c.eject_after_failures,
            .http_5xx => c.consecutive_5xx,
        };
        const count = switch (kind) {
            .connect => st.consecutive_failures,
            .http_5xx => st.consecutive_5xx,
        };
        // Only look at the whole cluster when this failure could eject.
        var may = false;
        if (threshold != 0 and count +| 1 >= threshold) {
            var ctx = self.lbCtx();
            may = lb.mayEject(&ctx, c);
        }
        if (st.recordFailure(kind, self.now_ms, threshold, c.eject_ms, may)) self.stats.inc(.endpoint_ejections);
    }

    pub fn lbCtx(self: *Worker) lb.Ctx {
        return .{ .gpa = self.gpa, .eps = &self.eps, .rng = self.prng.random(), .now_ms = self.now_ms, .down = self.shared.ep_down };
    }

    pub fn listenerCfg(self: *Worker, slot: u16) ?*const snapshot.Listener {
        const l = &self.listeners[slot];
        if (!l.active) return null;
        return &self.cur.listeners[l.snap_idx];
    }

    /// Brings this worker's listening sockets in line with the snapshot:
    /// binds new listeners, keeps unchanged ones, drains removed ones.
    fn reconcileListeners(self: *Worker, initial: bool) !void {
        const s = self.cur;
        for (&self.listeners) |*l| if (l.active) {
            var keep = false;
            for (s.listeners, 0..) |*sl, si| {
                if (std.mem.eql(u8, sl.name, l.name()) and sl.addr.eql(&l.addr) and sl.protocol == l.protocol) {
                    l.snap_idx = @intCast(si);
                    keep = true;
                }
            }
            if (!keep) self.removeListener(l);
        };
        if (self.draining) return;
        for (s.listeners, 0..) |*sl, si| {
            var found = false;
            for (&self.listeners) |*l| if (l.active and std.mem.eql(u8, sl.name, l.name())) {
                found = true;
            };
            if (found) continue;
            const slot = self.freeListenerSlot() orelse {
                log.err("worker {d}: too many listeners", .{self.id});
                if (initial) return error.TooManyListeners;
                continue;
            };
            const fd = socket.listen(&sl.addr, 4096) catch {
                var buf: [64]u8 = undefined;
                log.err("worker {d}: cannot listen on {s} ({s}): {s}", .{ self.id, sl.addr.format(&buf), sl.name, @tagName(socket.last_errno) });
                if (initial) return error.ListenFailed;
                continue;
            };
            const l = &self.listeners[slot];
            l.* = .{ .fd = fd, .active = true, .snap_idx = @intCast(si), .addr = sl.addr, .protocol = sl.protocol, .gen = l.gen +% 1, .conns = 0 };
            const n = @min(sl.name.len, l.name_buf.len);
            @memcpy(l.name_buf[0..n], sl.name[0..n]);
            l.name_len = @intCast(n);
            self.armAccept(slot);
        }
    }

    fn freeListenerSlot(self: *Worker) ?u16 {
        for (&self.listeners, 0..) |*l, i| {
            if (!l.active and l.fd < 0 and l.conns == 0 and l.pending == 0) return @intCast(i);
        }
        return null;
    }

    fn removeListener(self: *Worker, l: *WListener) void {
        l.active = false;
        if (l.fd >= 0) {
            // Cancelling the multishot accept; the fd is closed when the
            // final accept CQE arrives (or right away if none is pending).
            if (l.pending > 0) {
                self.loop.cancelFd(l.fd);
            } else {
                socket.closeFd(l.fd);
                l.fd = -1;
            }
        }
        const slot: u16 = @intCast(l - &self.listeners[0]);
        http.drainListener(self, slot);
    }

    fn armAccept(self: *Worker, slot: u16) void {
        const l = &self.listeners[slot];
        if (l.accept_armed or !l.active) return;
        self.loop.acceptMultishot(l.fd, ud(.accept, slot, l.gen));
        l.accept_armed = true;
        l.pending += 1;
    }

    fn onAccept(self: *Worker, u: Ud, cqe: *const linux.io_uring_cqe) void {
        const slot: u16 = @intCast(u.idx);
        const l = &self.listeners[slot];
        const more = cqe.flags & linux.IORING_CQE_F_MORE != 0;
        if (!more) {
            l.accept_armed = false;
            l.pending -= 1;
            if (!l.active and l.fd >= 0 and l.pending == 0) {
                socket.closeFd(l.fd);
                l.fd = -1;
            }
        }
        if (cqe.res < 0) {
            const e: linux.E = @enumFromInt(-cqe.res);
            if (e != .CANCELED) log.warn("worker {d}: accept on {s}: {s}", .{ self.id, l.name(), @tagName(e) });
            return; // re-armed on the next tick
        }
        const fd: linux.fd_t = cqe.res;
        if (!l.active or self.draining or l.gen != u.gen) {
            socket.closeFd(fd);
            return;
        }
        if (!more) self.armAccept(slot);
        switch (l.protocol) {
            .http => http.accept(self, fd, slot),
            .tcp => tcp.accept(self, fd, slot),
        }
    }

    // ------------------------------------------------------------ drain

    fn startDrain(self: *Worker) void {
        if (self.draining) return;
        self.draining = true;
        self.stats.set(.draining, 1);
        self.drain_deadline_ms = self.now_ms + self.cur.limits.drain_timeout_ms;
        for (&self.listeners) |*l| if (l.active) self.removeListener(l);
        http.drainAll(self);
    }

    fn drainDone(self: *Worker) bool {
        if (self.downs.inUse() == 0 and self.tunnels.inUse() == 0) return true;
        if (self.now_ms >= self.drain_deadline_ms) {
            http.closeAll(self);
            tcp.closeAll(self);
            return self.downs.inUse() == 0 and self.tunnels.inUse() == 0;
        }
        return false;
    }

    /// Final teardown: cancel everything and wait for the kernel to give
    /// back every buffer before the memory is freed.
    fn shutdownAll(self: *Worker) void {
        upool.closeAll(self);
        var spins: u32 = 0;
        while (spins < 200 and (self.downs.inUse() > 0 or self.ups.inUse() > 0 or self.tunnels.inUse() > 0 or self.shadows.inUse() > 0)) : (spins += 1) {
            http.closeAll(self);
            tcp.closeAll(self);
            mirror.closeAll(self);
            upool.closeAll(self);
            // With DEFER_TASKRUN, completions only run inside an enter with
            // GETEVENTS; submit_and_wait(0) would not pass that flag.
            const to_submit = self.loop.ring.flush_sq();
            _ = self.loop.ring.enter(to_submit, 0, linux.IORING_ENTER_GETEVENTS) catch break;
            const n = self.loop.ring.copy_cqes(&self.cqes, 0) catch 0;
            for (self.cqes[0..n]) |*cqe| self.dispatch(cqe);
            self.processReap();
            if (n == 0) {
                const ts: linux.timespec = .{ .sec = 0, .nsec = 5 * std.time.ns_per_ms };
                _ = linux.nanosleep(&ts, null);
            }
        }
        self.shared.rcu.quiesce(self.id, rcu_mod.idle_epoch);
    }
};
