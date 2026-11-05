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
        w.stats.inc(.upstream_cx_pool_hit);
        return ui;
    }
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
pub fn release(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    u.owner = null;
    const st = w.eps.get(w.gpa, u.ep_id) catch {
        close(w, ui);
        return;
    };
    if (st.idle_count >= u.max_idle or w.draining or !u.in.isEmpty() or !u.out.isEmpty()) {
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
    if (u.tls) |t| Tls.freeConn(t);
    socket.closeFd(u.fd);
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

pub fn flush(w: *Worker, ui: u32) void {
    const u = get(w, ui);
    if (u.state != .busy or u.out.inflight or u.out.isEmpty()) return;
    if (u.tls_mode == .user) return http.tlsFlushUp(w, ui);
    const msg = u.out.prepare(&w.segs);
    w.loop.sendmsg(u.fd, msg, udOf(w, .u_send, ui));
    u.pending += 1;
}
