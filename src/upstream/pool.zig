//! Upstream connections and the per-worker connection pool.
//!
//! Idle connections are kept per endpoint in a LIFO list (most recently
//! used first, so the pool shrinks naturally) with an idle cap and an idle
//! timeout. A multishot recv stays armed on idle connections, so a close
//! by the upstream is noticed immediately and the connection leaves the
//! pool: the liveness check on reuse costs nothing.

const std = @import("std");
const linux = std.os.linux;

const Worker = @import("../runtime/worker.zig").Worker;
const worker_mod = @import("../runtime/worker.zig");
const tw = @import("../runtime/timer_wheel.zig");
const sq = @import("../runtime/send_queue.zig");
const InBuf = @import("../mem/blocks.zig").InBuf;
const HeadScanner = @import("../http1/parser.zig").HeadScanner;
const snapshot = @import("../config/snapshot.zig");
const socket = @import("../net/socket.zig");
const breaker = @import("breaker.zig");
const shared_pool = @import("shared_pool.zig");
const Address = @import("../net/addr.zig").Address;
const http = @import("../proxy/http.zig");
const tls_backend = @import("../tls/backend.zig");
const Tls = tls_backend.Tls;

/// Pool key for plaintext connections; TLS connections use the cluster id
/// (each cluster has its own TLS context, SNI and verification settings).
pub const plain_key = std.math.maxInt(u32);

pub const State = enum { connecting, busy, idle, closing };

pub const Up = struct {
    fd: linux.fd_t,
    ep_id: u32,
    addr: Address,
    state: State,
    /// Downstream connection using this upstream (state == busy).
    owner: ?u32 = null,
    owner_gen: u32 = 0,
    /// Cluster this connection was opened for (circuit breaker count).
    cb_cluster: ?u32 = null,
    in: InBuf = .{},
    scanner: HeadScanner = .{},
    out: sq.SendQueue = .{},
    timer: tw.Timer = .{},
    pending: u16 = 0,
    recv_armed: bool = false,
    recv_cancelling: bool = false,
    idle_prev: ?u32 = null,
    idle_next: ?u32 = null,
    /// Taken from the pool rather than freshly connected.
    reused: bool = false,
    /// Closing in order to be parked in the shared pool (cleared if
    /// anything arrives on the socket meanwhile).
    park: bool = false,
    /// The cluster that last used it shares idle connections.
    share: bool = true,
    idle_timeout_ms: u32,
    max_idle: u32,
    connect_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 },
    pool_key: u32 = plain_key,
    tls: ?*Tls.Conn = null,
    tls_mode: tls_backend.Mode = .none,
    tls_poll_in: bool = false,
    tls_poll_out: bool = false,
    tls_flushing: bool = false,
    tls_reading: bool = false,
    dirty: bool = false,
};

pub fn get(w: *Worker, ui: u32) *Up {
    return w.ups.get(ui);
}

pub fn udOf(w: *Worker, op: @import("../runtime/loop.zig").Op, ui: u32) u64 {
    return Worker.ud(op, ui, w.ups.gen(ui));
}

/// Returns an upstream connection to `ep`: a pooled one if available,
/// else a new connection in state `connecting`.
pub fn acquire(w: *Worker, ep: *const snapshot.Endpoint, c: *const snapshot.Cluster) !u32 {
    const st = try w.eps.get(w.gpa, ep.id);
    const key: u32 = if (c.tls != null) c.id else plain_key;
    var it = st.idle_head;
    while (it) |ui| {
        const u = get(w, ui);
        it = u.idle_next;
        if (u.pool_key != key or u.state != .idle) continue;
        unlinkIdle(w, ui);
        w.wheel.cancel(&u.timer);
        u.state = .busy;
        u.reused = true;
        u.idle_timeout_ms = c.idle_timeout_ms;
        u.max_idle = c.max_idle_per_endpoint;
        u.share = c.share_idle;
        w.stats.inc(.upstream_cx_pool_hit);
        return ui;
    }
    const load = try w.cluster_load.get(w.gpa, c.id);
    if (load.active_cx >= breaker.share(c.breakers.max_connections, w.shared.stats.len)) return error.CircuitOpen;
    if (c.share_idle) if (w.shared.conn_pool) |sp| if (adopt(w, sp, ep, c, key, load)) |ui| return ui;
    const fd = try socket.connectSocket(&ep.addr);
    const ui = w.ups.alloc() orelse {
        socket.closeFd(fd);
        return error.TooManyUpstreamConnections;
    };
    const u = get(w, ui);
    u.* = .{
        .fd = fd,
        .ep_id = ep.id,
        .addr = ep.addr,
        .state = .connecting,
        .idle_timeout_ms = c.idle_timeout_ms,
        .max_idle = c.max_idle_per_endpoint,
        .pool_key = key,
        .cb_cluster = null,
        .share = c.share_idle,
    };
    if (c.tls) |t| {
        // Created now so it holds a reference on the cluster's SSL_CTX even
        // if the snapshot is replaced while connecting.
        u.tls = Tls.newClientConn(t.ctx, fd, t.sni, t.verify) orelse {
            socket.closeFd(fd);
            w.ups.release(ui);
            return error.TlsSetupFailed;
        };
        u.tls_mode = .handshake;
    }
    u.connect_ts = .{ .sec = @intCast(c.connect_timeout_ms / 1000), .nsec = @intCast((c.connect_timeout_ms % 1000) * std.time.ns_per_ms) };
    u.cb_cluster = c.id;
    load.active_cx += 1;
    w.loop.connect(fd, &u.addr.any, u.addr.len(), &u.connect_ts, udOf(w, .u_connect, ui));
    u.pending += 1;
    w.stats.inc(.upstream_cx_total);
    w.stats.inc(.upstream_cx_active);
    return ui;
}

fn unlinkIdle(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    const st = w.eps.get(w.gpa, u.ep_id) catch unreachable;
    if (u.idle_prev) |p| get(w, p).idle_next = u.idle_next else st.idle_head = u.idle_next;
    if (u.idle_next) |n| get(w, n).idle_prev = u.idle_prev;
    u.idle_prev = null;
    u.idle_next = null;
    st.idle_count -= 1;
}

/// Puts a connection that finished a response cleanly back in the pool.
/// Takes an idle connection another worker parked, after checking that the
/// upstream did not close it meanwhile.
fn adopt(w: *Worker, sp: *shared_pool.SharedPool, ep: *const snapshot.Endpoint, c: *const snapshot.Cluster, key: u32, load: *breaker.ClusterState) ?u32 {
    var tries: u8 = 0;
    while (tries < 4) : (tries += 1) {
        const e = sp.take(ep.id, key, w.now_ms) orelse return null;
        if (!shared_pool.alive(e.fd)) {
            shared_pool.discard(&e);
            w.stats.inc(.upstream_cx_handoff_stale);
            continue;
        }
        const ui = w.ups.alloc() orelse {
            _ = sp.park(ep.id, e, c.max_idle_per_endpoint) or blk: {
                shared_pool.discard(&e);
                break :blk false;
            };
            return null;
        };
        const u = get(w, ui);
        u.* = .{
            .fd = e.fd,
            .ep_id = ep.id,
            .addr = e.addr,
            .state = .busy,
            .reused = true,
            .idle_timeout_ms = c.idle_timeout_ms,
            .max_idle = c.max_idle_per_endpoint,
            .pool_key = key,
            .cb_cluster = c.id,
            .share = c.share_idle,
            .tls = e.tls,
            .tls_mode = e.tls_mode,
        };
        load.active_cx += 1;
        w.stats.inc(.upstream_cx_active);
        w.stats.inc(.upstream_cx_handoff);
        return ui;
    }
    return null;
}

/// Idle connections a worker keeps for itself per endpoint before parking
/// the rest in the shared pool.
fn keepLocal(w: *Worker, max_idle: u32) u32 {
    const workers: u32 = @intCast(@max(w.shared.stats.len, 1));
    return @max(1, (max_idle + workers - 1) / workers);
}

pub fn release(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    u.owner = null;
    const st = w.eps.get(w.gpa, u.ep_id) catch {
        close(w, ui);
        return;
    };
    if (w.draining or !u.in.isEmpty() or !u.out.isEmpty()) {
        close(w, ui);
        return;
    }
    // Over this worker's share: park it for other workers (userspace TLS
    // connections cannot move between workers).
    if (u.share and w.shared.conn_pool != null and u.tls_mode != .user and st.idle_count >= keepLocal(w, u.max_idle)) {
        u.park = true;
        close(w, ui);
        return;
    }
    if (st.idle_count >= u.max_idle) {
        close(w, ui);
        return;
    }
    u.state = .idle;
    u.scanner.reset();
    u.in.trim(&w.blocks);
    u.idle_prev = null;
    u.idle_next = st.idle_head;
    if (st.idle_head) |h| get(w, h).idle_prev = ui;
    st.idle_head = ui;
    st.idle_count += 1;
    w.schedule(&u.timer, .up, ui, w.ups.gen(ui), u.idle_timeout_ms);
    updateRecv(w, ui);
}

pub fn close(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    if (u.state == .closing) return;
    if (u.state == .idle) unlinkIdle(w, ui);
    u.state = .closing;
    u.owner = null;
    w.wheel.cancel(&u.timer);
    if (u.pending > 0) w.loop.cancelFd(u.fd);
    w.reapLater(.up, ui, w.ups.gen(ui));
}

pub fn maybeFree(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    if (u.state != .closing or u.pending > 0) return;
    u.out.clear(&w.segs, w);
    u.in.release(&w.blocks);
    const parked = u.park and u.tls_mode != .user and u.in.isEmpty() and w.shared.conn_pool != null and
        w.shared.conn_pool.?.park(u.ep_id, .{
            .fd = u.fd,
            .addr = u.addr,
            .pool_key = u.pool_key,
            .tls = u.tls,
            .tls_mode = u.tls_mode,
            .parked_ms = w.now_ms,
            .idle_timeout_ms = u.idle_timeout_ms,
        }, u.max_idle);
    if (parked) {
        w.stats.inc(.upstream_cx_parked);
    } else {
        if (u.tls) |t| Tls.freeConn(t);
        socket.closeFd(u.fd);
    }
    if (u.cb_cluster) |id| if (w.cluster_load.get(w.gpa, id)) |l| {
        l.active_cx -|= 1;
    } else |_| {};
    w.ups.release(ui);
    w.stats.dec(.upstream_cx_active);
}

pub fn onTimer(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    if (u.state == .idle) close(w, ui);
}

pub fn closeAll(w: *Worker) void {
    for (w.ups.items, 0..) |_, i| {
        const ui: u32 = @intCast(i);
        if (w.ups.live[ui] and get(w, ui).state != .closing) close(w, ui);
    }
}

/// Keeps the multishot recv armed when the connection should be read
/// (connected and the downstream is not backpressured), cancels it
/// otherwise.
pub fn wantRecv(w: *Worker, ui: u32) bool {
    const u = get(w, ui);
    return switch (u.state) {
        .idle => true,
        .busy => if (u.owner) |di| !http.downBackpressured(w, di) else true,
        .connecting, .closing => false,
    };
}

pub fn updateRecv(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    var want = switch (u.state) {
        .idle => true,
        .busy => true,
        .connecting, .closing => false,
    };
    if (want and u.state == .busy) {
        if (u.owner) |di| {
            if (http.downBackpressured(w, di)) want = false;
        }
    }
    switch (u.tls_mode) {
        .handshake => return,
        .user => {
            if (want) w.tlsKick(.up, ui, w.ups.gen(ui));
            return;
        },
        .none, .ktls => {},
    }
    if (want and !u.recv_armed) {
        w.loop.recvMultishot(u.fd, worker_mod.buffer_group, udOf(w, .u_recv, ui));
        u.recv_armed = true;
        u.recv_cancelling = false;
        u.pending += 1;
    } else if (!want and u.recv_armed and !u.recv_cancelling and u.state != .closing) {
        w.loop.cancelUd(udOf(w, .u_recv, ui));
        u.recv_cancelling = true;
    }
}

/// Queues a flush for after the current completion (coalesces writes).
pub fn flush(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    if (u.dirty) return;
    u.dirty = true;
    w.markDirty(.up, ui, w.ups.gen(ui));
}

pub fn flushNow(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    u.dirty = false;
    if (u.state != .busy or u.out.inflight or u.out.isEmpty()) return;
    if (u.tls_mode == .user) return http.tlsFlushUp(w, ui);
    if (u.out.single(&w.segs)) |bytes| {
        w.loop.send(u.fd, bytes, udOf(w, .u_send, ui));
    } else {
        const msg = u.out.prepare(&w.segs);
        w.loop.sendmsg(u.fd, msg, udOf(w, .u_send, ui));
    }
    u.pending += 1;
}
