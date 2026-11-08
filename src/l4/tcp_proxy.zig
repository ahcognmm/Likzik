//! TCP/L4 proxy: zero-copy passthrough with splice through a pipe pair.
//!
//! Readiness comes from the ring (a multishot POLLIN per socket, one-shot
//! POLLOUT when a destination is full). The data moves with non-blocking
//! splice(2) calls issued inline from the worker thread. We do not use
//! IORING_OP_SPLICE here: the kernel always punts it to an io-wq thread,
//! which costs a thread hop per operation and one blocked io-wq thread per
//! idle tunnel. Bytes still never enter userspace.
//!
//! Each direction is independent: on EOF from a source we shutdown(WR)
//! the destination once its pipe is drained, and the tunnel closes when
//! both directions are done.

const std = @import("std");
const linux = std.os.linux;

const worker_mod = @import("../runtime/worker.zig");
const Worker = worker_mod.Worker;
const loop_mod = @import("../runtime/loop.zig");
const Op = loop_mod.Op;
const Ud = loop_mod.Ud;
const tw = @import("../runtime/timer_wheel.zig");
const snapshot = @import("../config/snapshot.zig");
const socket = @import("../net/socket.zig");
const Address = @import("../net/addr.zig").Address;
const lb = @import("../upstream/lb.zig");
const pp = @import("../net/proxy_protocol.zig");
const client_hello = @import("../tls/client_hello.zig");

const log = std.log.scoped(.tcp);

const splice_chunk = 64 * 1024;
const pollrdhup: u32 = 0x2000;

pub const State = enum { preamble, connecting, open, closing };

pub const Tunnel = struct {
    dfd: linux.fd_t,
    ufd: linux.fd_t = -1,
    listener: u16,
    state: State = .connecting,
    /// pipes[dir] = {read end, write end}; dir 0 = client->upstream.
    pipes: [2][2]linux.fd_t = .{ .{ -1, -1 }, .{ -1, -1 } },
    buffered: [2]usize = .{ 0, 0 },
    eof: [2]bool = .{ false, false },
    shut: [2]bool = .{ false, false },
    poll_in: [2]bool = .{ false, false },
    poll_out: [2]bool = .{ false, false },
    pending: u16 = 0,
    timer: tw.Timer = .{},
    last_activity_ms: u64 = 0,
    idle_timeout_ms: u32 = 0,
    // Connect phase.
    snap: ?*snapshot.Snapshot = null,
    cluster: ?*const snapshot.Cluster = null,
    ep_id: ?u32 = null,
    attempts: u8 = 0,
    addr: Address = undefined,
    connect_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 },
    // Preamble: bytes read before connecting (PROXY header stripped, then
    // the ClientHello for SNI routing), replayed to the upstream.
    pre_blk: ?u32 = null,
    pre_len: u32 = 0,
    need_pp: bool = false,
    need_sni: bool = false,
    /// Client and local address, from the PROXY header when there is one.
    client: ?Address = null,
    local: ?Address = null,
};

inline fn get(w: *Worker, ti: u32) *Tunnel {
    return w.tunnels.get(ti);
}

inline fn udOf(w: *Worker, op: Op, ti: u32) u64 {
    return Worker.ud(op, ti, w.tunnels.gen(ti));
}

pub fn accept(w: *Worker, fd: linux.fd_t, slot: u16) void {
    const lcfg = w.listenerCfg(slot) orelse {
        socket.closeFd(fd);
        return;
    };
    const ti = w.tunnels.alloc() orelse {
        w.stats.inc(.downstream_cx_overflow);
        socket.closeFd(fd);
        return;
    };
    const t = get(w, ti);
    t.* = .{ .dfd = fd, .listener = slot, .idle_timeout_ms = lcfg.idle_timeout_ms, .last_activity_ms = w.now_ms };
    w.listeners[slot].conns += 1;
    w.stats.inc(.tcp_cx_total);
    w.stats.inc(.tcp_cx_active);
    t.snap = w.pinCurrent() orelse return close(w, ti);
    t.cluster = lcfg.cluster;
    if (lcfg.proxy_protocol or lcfg.sni_routes.len > 0) {
        t.need_pp = lcfg.proxy_protocol;
        t.need_sni = lcfg.sni_routes.len > 0;
        t.state = .preamble;
        t.pre_blk = w.blocks.alloc() orelse return close(w, ti);
        w.schedule(&t.timer, .tunnel, ti, w.tunnels.gen(ti), w.cur.limits.header_timeout_ms);
        return armPre(w, ti);
    }
    connectNext(w, ti, null);
}

fn armPre(w: *Worker, ti: u32) void {
    const t = get(w, ti);
    w.loop.pollOnce(t.dfd, linux.POLL.IN | pollrdhup, udOf(w, .t_pre, ti));
    t.pending += 1;
}

/// Reads what the client sent so far and decides where the tunnel goes.
fn onPreamble(w: *Worker, ti: u32) void {
    const t = get(w, ti);
    const buf = w.blocks.bytes(t.pre_blk.?);
    while (t.pre_len < buf.len) {
        const n = socket.recvNb(t.dfd, buf[t.pre_len..], false) catch |e| switch (e) {
            error.WouldBlock => break,
            error.SyscallFailed => return close(w, ti),
        };
        if (n == 0) return close(w, ti);
        t.pre_len += @intCast(n);
    }
    if (t.need_pp) switch (pp.parse(buf[0..t.pre_len])) {
        .incomplete => return if (t.pre_len == buf.len) rejectPre(w, ti) else armPre(w, ti),
        .invalid => return rejectPre(w, ti),
        .done => |h| {
            t.client = h.src;
            t.local = h.dst;
            std.mem.copyForwards(u8, buf[0 .. t.pre_len - h.len], buf[h.len..t.pre_len]);
            t.pre_len -= @intCast(h.len);
            t.need_pp = false;
        },
    };
    if (t.need_sni) {
        const lcfg = w.listenerCfg(t.listener) orelse return close(w, ti);
        var scratch: [client_hello.max_hello]u8 = undefined;
        const name: ?[]const u8 = switch (client_hello.parse(buf[0..t.pre_len], &scratch)) {
            .incomplete => if (t.pre_len == buf.len) null else return armPre(w, ti),
            .invalid => null, // not TLS (or too large): the default cluster, if any
            .done => |sni| sni,
        };
        t.cluster = lcfg.clusterForSni(name);
        t.need_sni = false;
        if (t.cluster == null) {
            w.stats.inc(.tcp_sni_unmatched);
            return close(w, ti);
        }
    }
    w.wheel.cancel(&t.timer);
    t.state = .connecting;
    connectNext(w, ti, null);
}

fn rejectPre(w: *Worker, ti: u32) void {
    w.stats.inc(.proxy_protocol_rejected);
    close(w, ti);
}

/// Queues the PROXY header (if the cluster wants one) and the preamble
/// bytes into the client-to-upstream pipe, ahead of everything else.
fn replayPreamble(w: *Worker, ti: u32, c: *const snapshot.Cluster) bool {
    const t = get(w, ti);
    if (c.proxy_protocol) |ver| {
        const src = t.client orelse socket.peerAddress(t.dfd);
        const dst = t.local orelse socket.localAddress(t.dfd);
        var hb: [pp.max_len]u8 = undefined;
        const h = pp.write(ver, &src, &dst, &hb);
        if (!fillPipe(t, h)) return false;
    }
    if (t.pre_blk) |blk| {
        const ok = fillPipe(t, w.blocks.bytes(blk)[0..t.pre_len]);
        w.blocks.unref(blk);
        t.pre_blk = null;
        if (!ok) return false;
    }
    return true;
}

/// Writes into the empty client-to-upstream pipe (64 KiB, so a preamble
/// of at most one block plus a header always fits).
fn fillPipe(t: *Tunnel, bytes: []const u8) bool {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = socket.writeNb(t.pipes[0][1], bytes[off..]) catch return false;
        off += n;
    }
    t.buffered[0] += bytes.len;
    return true;
}

fn connectNext(w: *Worker, ti: u32, exclude: ?u32) void {
    const t = get(w, ti);
    const c = t.cluster.?;
    var ctx: lb.Ctx = .{ .gpa = w.gpa, .eps = &w.eps, .rng = w.prng.random(), .now_ms = w.now_ms };
    var excl = exclude;
    while (t.attempts < c.max_connect_attempts) {
        const ep = (lb.pick(&ctx, c, excl) catch null) orelse break;
        t.attempts += 1;
        const fd = socket.connectSocket(&ep.addr) catch {
            excl = ep.id;
            continue;
        };
        t.ufd = fd;
        t.ep_id = ep.id;
        t.addr = ep.addr;
        t.connect_ts = .{ .sec = @intCast(c.connect_timeout_ms / 1000), .nsec = @intCast((c.connect_timeout_ms % 1000) * std.time.ns_per_ms) };
        w.loop.connect(fd, &t.addr.any, t.addr.len(), &t.connect_ts, udOf(w, .t_connect, ti));
        t.pending += 1;
        w.stats.inc(.upstream_cx_total);
        return;
    }
    close(w, ti);
}

fn onConnect(w: *Worker, ti: u32, res: i32) void {
    const t = get(w, ti);
    if (t.state == .closing) return;
    const c = t.cluster.?;
    if (res != 0) {
        w.stats.inc(.upstream_cx_connect_fail);
        if (res == -@as(i32, @intFromEnum(linux.E.CANCELED))) w.stats.inc(.upstream_cx_connect_timeout);
        w.endpointFailed(c, t.ep_id.?, .connect);
        socket.closeFd(t.ufd);
        t.ufd = -1;
        connectNext(w, ti, t.ep_id);
        return;
    }
    if (w.eps.get(w.gpa, t.ep_id.?)) |st| st.recordSuccess() else |_| {}
    t.pipes[0] = socket.pipe() catch return close(w, ti);
    t.pipes[1] = socket.pipe() catch return close(w, ti);
    if (!replayPreamble(w, ti, c)) return close(w, ti);
    // The snapshot is only needed to pick an endpoint.
    w.unpin(t.snap.?);
    t.snap = null;
    t.cluster = null;
    t.state = .open;
    t.last_activity_ms = w.now_ms;
    w.schedule(&t.timer, .tunnel, ti, w.tunnels.gen(ti), t.idle_timeout_ms);
    armIn(w, ti, 0);
    armIn(w, ti, 1);
    if (t.buffered[0] > 0) pump(w, ti, 0);
}

fn srcFd(t: *const Tunnel, dir: u1) linux.fd_t {
    return if (dir == 0) t.dfd else t.ufd;
}

fn dstFd(t: *const Tunnel, dir: u1) linux.fd_t {
    return if (dir == 0) t.ufd else t.dfd;
}

fn inOp(dir: u1) Op {
    return if (dir == 0) .t_in_d else .t_in_u;
}

/// POLLOUT on the destination of `dir`.
fn outOp(dir: u1) Op {
    return if (dir == 0) .t_out_u else .t_out_d;
}

fn armIn(w: *Worker, ti: u32, dir: u1) void {
    const t = get(w, ti);
    if (t.poll_in[dir] or t.eof[dir]) return;
    w.loop.pollMultishot(srcFd(t, dir), linux.POLL.IN | pollrdhup, udOf(w, inOp(dir), ti));
    t.poll_in[dir] = true;
    t.pending += 1;
}

fn armOut(w: *Worker, ti: u32, dir: u1) void {
    const t = get(w, ti);
    if (t.poll_out[dir]) return;
    w.loop.pollOnce(dstFd(t, dir), linux.POLL.OUT, udOf(w, outOp(dir), ti));
    t.poll_out[dir] = true;
    t.pending += 1;
}

pub fn onEvent(w: *Worker, u: Ud, cqe: *const linux.io_uring_cqe) void {
    const ti: u32 = u.idx;
    const t = get(w, ti);
    const more = cqe.flags & linux.IORING_CQE_F_MORE != 0;
    defer if (t.state == .closing and t.pending == 0) w.reapLater(.tunnel, ti, w.tunnels.gen(ti));
    switch (u.op) {
        .t_connect => {
            t.pending -= 1;
            onConnect(w, ti, cqe.res);
        },
        .t_pre => {
            t.pending -= 1;
            if (t.state != .preamble) return;
            if (cqe.res < 0 and cqe.res != -@as(i32, @intFromEnum(linux.E.CANCELED))) return close(w, ti);
            onPreamble(w, ti);
        },
        .t_in_d, .t_in_u => {
            const dir: u1 = if (u.op == .t_in_d) 0 else 1;
            if (!more) {
                t.poll_in[dir] = false;
                t.pending -= 1;
            }
            if (t.state != .open) return;
            if (cqe.res < 0 and cqe.res != -@as(i32, @intFromEnum(linux.E.CANCELED))) return close(w, ti);
            pump(w, ti, dir);
            if (!more and t.state == .open) armIn(w, ti, dir);
        },
        .t_out_d, .t_out_u => {
            const dir: u1 = if (u.op == .t_out_u) 0 else 1;
            t.poll_out[dir] = false;
            t.pending -= 1;
            if (t.state != .open) return;
            if (cqe.res < 0 and cqe.res != -@as(i32, @intFromEnum(linux.E.CANCELED))) return close(w, ti);
            pump(w, ti, dir);
        },
        else => unreachable,
    }
}

/// Moves bytes for one direction until the source is empty or the
/// destination is full.
fn pump(w: *Worker, ti: u32, dir: u1) void {
    const t = get(w, ti);
    const pipe = t.pipes[dir];
    while (t.state == .open) {
        if (t.buffered[dir] > 0) {
            const n = socket.splice(pipe[0], dstFd(t, dir), t.buffered[dir]) catch |e| switch (e) {
                error.WouldBlock => return armOut(w, ti, dir),
                error.SyscallFailed => return close(w, ti),
            };
            t.buffered[dir] -= n;
            t.last_activity_ms = w.now_ms;
            w.stats.add(.tcp_bytes, n);
            continue;
        }
        if (t.eof[dir]) {
            if (!t.shut[dir]) {
                socket.shutdownWrite(dstFd(t, dir));
                t.shut[dir] = true;
            }
            if (t.shut[0] and t.shut[1]) close(w, ti);
            return;
        }
        const n = socket.splice(srcFd(t, dir), pipe[1], splice_chunk) catch |e| switch (e) {
            error.WouldBlock => return,
            error.SyscallFailed => return close(w, ti),
        };
        if (n == 0) {
            t.eof[dir] = true;
            // Stop the multishot poll: an EOF socket stays readable.
            if (t.poll_in[dir]) w.loop.cancelUd(udOf(w, inOp(dir), ti));
            continue;
        }
        t.buffered[dir] += n;
    }
}

pub fn onTimer(w: *Worker, ti: u32) void {
    const t = get(w, ti);
    if (t.state == .preamble) return close(w, ti); // header/ClientHello too slow
    if (t.state != .open) return;
    const idle_for = w.now_ms -| t.last_activity_ms;
    if (idle_for >= t.idle_timeout_ms) return close(w, ti);
    w.schedule(&t.timer, .tunnel, ti, w.tunnels.gen(ti), t.idle_timeout_ms - idle_for);
}

pub fn close(w: *Worker, ti: u32) void {
    const t = get(w, ti);
    if (t.state == .closing) return;
    t.state = .closing;
    w.wheel.cancel(&t.timer);
    if (t.snap) |s| {
        w.unpin(s);
        t.snap = null;
    }
    if (t.pending > 0) {
        w.loop.cancelFd(t.dfd);
        if (t.ufd >= 0) w.loop.cancelFd(t.ufd);
    }
    w.reapLater(.tunnel, ti, w.tunnels.gen(ti));
}

pub fn maybeFree(w: *Worker, ti: u32) void {
    const t = get(w, ti);
    if (t.state != .closing or t.pending > 0) return;
    if (t.pre_blk) |blk| {
        w.blocks.unref(blk);
        t.pre_blk = null;
    }
    socket.closeFd(t.dfd);
    if (t.ufd >= 0) socket.closeFd(t.ufd);
    for (t.pipes) |p| for (p) |fd| if (fd >= 0) socket.closeFd(fd);
    w.listeners[t.listener].conns -= 1;
    w.tunnels.release(ti);
    w.stats.dec(.tcp_cx_active);
}

pub fn closeAll(w: *Worker) void {
    for (w.tunnels.items, 0..) |_, i| {
        if (w.tunnels.live[i]) close(w, @intCast(i));
    }
}
