//! HTTP/1.1 reverse proxy state machine (one per downstream connection).
//!
//! Data path:
//!   * Downstream bytes arrive in provided buffers via a multishot recv.
//!     When a request head lies entirely inside one buffer (the common
//!     case) it is parsed in place. Otherwise bytes are accumulated in a
//!     per-connection block and parsed there.
//!   * The head is re-serialized into a fresh block and queued to the
//!     upstream. Body bytes are forwarded zero-copy: the send queue holds a
//!     reference on the provided buffer until the send completes.
//!   * The response takes the mirror path back.
//!
//! Requests on one connection are handled strictly in order, one at a
//! time; pipelined bytes wait in the accumulation block.
//!
//! Backpressure: when the peer's send queue passes `high_water`, the
//! source's multishot recv is cancelled, and re-armed when it drains.

const std = @import("std");
const linux = std.os.linux;

const worker_mod = @import("../runtime/worker.zig");
const Worker = worker_mod.Worker;
const Op = @import("../runtime/loop.zig").Op;
const tw = @import("../runtime/timer_wheel.zig");
const sq = @import("../runtime/send_queue.zig");
const blocks_mod = @import("../mem/blocks.zig");
const InBuf = blocks_mod.InBuf;
const parser = @import("../http1/parser.zig");
const rules = @import("../http1/smuggling_rules.zig");
const codec = @import("../http1/codec.zig");
const chunked = @import("../http1/chunked.zig");
const snapshot = @import("../config/snapshot.zig");
const socket = @import("../net/socket.zig");
const upool = @import("../upstream/pool.zig");
const lb = @import("../upstream/lb.zig");
const filter = @import("filter.zig");
const tls_backend = @import("../tls/backend.zig");
const Tls = tls_backend.Tls;

const log = std.log.scoped(.http);
const access_log = @import("../observe/access_log.zig");
const pp = @import("../net/proxy_protocol.zig");
const breaker = @import("../upstream/breaker.zig");
const mirror = @import("mirror.zig");

/// Longest request target kept for the access log (longer ones are cut).
const log_target_max = 512;

/// Send-queue size at which the source side stops reading.
pub const high_water = 128 * 1024;
/// Pipelined bytes buffered before downstream reads pause.
const pipeline_cap = 8 * 1024;
const linger_ms = 2_000;

pub const Body = struct {
    kind: Kind = .none,
    remaining: u64 = 0,
    dec: chunked.Decoder = .{},
    done: bool = true,

    pub const Kind = enum { none, length, chunked, close };

    fn init(f: rules.Framing) Body {
        return switch (f) {
            .none => .{},
            .length => |n| .{ .kind = .length, .remaining = n, .done = false },
            .chunked => .{ .kind = .chunked, .done = false },
            .close_delimited => .{ .kind = .close, .done = false },
        };
    }
};

pub const Phase = enum { head, exchange, closing };

pub const Down = struct {
    fd: linux.fd_t,
    listener: u16,
    ip_buf: [64]u8 = undefined,
    ip_len: u8 = 0,
    phase: Phase = .head,
    in: InBuf = .{},
    scanner: parser.HeadScanner = .{},
    out: sq.SendQueue = .{},
    timer: tw.Timer = .{},
    pending: u16 = 0,
    recv_armed: bool = false,
    recv_cancelling: bool = false,
    pumping: bool = false,
    close_after_flush: bool = false,
    lingering: bool = false,
    peer_eof: bool = false,
    requests: u32 = 0,

    // Current exchange.
    snap: ?*snapshot.Snapshot = null,
    cluster: ?*const snapshot.Cluster = null,
    ep_id: ?u32 = null,
    up: ?u32 = null,
    attempts: u8 = 0,
    /// Serialized upstream request head, kept until the response starts so
    /// a request can be retried on another connection.
    head_block: ?u32 = null,
    head_len: u32 = 0,
    method: parser.Method = .GET,
    client10: bool = false,
    keep_alive: bool = true,
    retryable: bool = false,
    /// Request body bytes were handed to an upstream connection.
    body_sent: bool = false,
    /// A replay on a fresh connection already happened.
    replayed: bool = false,
    timeout_ms: u32 = 0,
    req: Body = .{},
    resp_head_done: bool = false,
    /// Any response bytes (including 1xx) were queued to the client.
    resp_started: bool = false,
    resp_bytes_seen: bool = false,
    resp: Body = .{},
    resp_dechunk: bool = false,
    resp_keep_alive: bool = false,
    up_poisoned: bool = false,

    // TLS termination.
    tls: ?*Tls.Conn = null,
    tls_mode: tls_backend.Mode = .none,
    tls_poll_in: bool = false,
    tls_poll_out: bool = false,
    tls_flushing: bool = false,
    tls_reading: bool = false,
    dirty: bool = false,
    /// Wait for the client's FIN before closing (unread input possible).
    linger_needed: bool = true,
    /// The connection closes because of an error response: the rest of a
    /// bad request may still be unread, so always linger.
    error_close: bool = false,
    /// The extension handled this request: call onResponse with the token.
    ext_active: bool = false,
    ext_token: usize = 0,

    // Circuit breaker and retry accounting for the current exchange.
    cb_on: bool = false,
    in_retry: bool = false,
    retries: u8 = 0,
    cb_id: u32 = 0,

    // PROXY protocol header still expected (consumed before anything else).
    pp_pending: bool = false,
    pre_blk: ?u32 = null,
    pre_len: u16 = 0,

    // Access log for the current exchange (only filled when enabled).
    log_on: bool = false,
    log_status: u16 = 0,
    log_method_len: u8 = 0,
    log_target_len: u16 = 0,
    log_start_wall: i64 = 0,
    log_start_ms: u64 = 0,
    log_bytes: u64 = 0,
    /// Last endpoint tried (points into the pinned snapshot).
    log_ep: []const u8 = "",
    log_method: [16]u8 = undefined,
    log_target: [log_target_max]u8 = undefined,

    fn ip(self: *const Down) []const u8 {
        return self.ip_buf[0..self.ip_len];
    }
};

inline fn get(w: *Worker, di: u32) *Down {
    return w.downs.get(di);
}

inline fn udOf(w: *Worker, op: Op, di: u32) u64 {
    return Worker.ud(op, di, w.downs.gen(di));
}

fn gen(w: *Worker, di: u32) u32 {
    return w.downs.gen(di);
}

// ---------------------------------------------------------------- accept

pub fn accept(w: *Worker, fd: linux.fd_t, slot: u16) void {
    const di = w.downs.alloc() orelse {
        w.stats.inc(.downstream_cx_overflow);
        socket.closeFd(fd);
        return;
    };
    const d = get(w, di);
    d.* = .{ .fd = fd, .listener = slot };
    // TCP_NODELAY is inherited from the listening socket.
    const peer = socket.peerAddress(fd);
    d.ip_len = @intCast(peer.formatIp(&d.ip_buf).len);
    w.listeners[slot].conns += 1;
    w.stats.inc(.downstream_cx_total);
    w.stats.inc(.downstream_cx_active);
    // The header timeout also bounds the PROXY header and TLS handshake.
    w.schedule(&d.timer, .down, di, gen(w, di), w.cur.limits.header_timeout_ms);
    if (w.listenerCfg(slot)) |lcfg| if (lcfg.proxy_protocol) {
        d.pp_pending = true;
        d.pre_blk = w.blocks.alloc() orelse return closeDown(w, di);
        return armDownPre(w, di);
    };
    startDown(w, di);
}

/// Starts TLS or HTTP on an accepted (and PROXY-unwrapped) connection.
fn startDown(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (w.listenerCfg(d.listener)) |lcfg| if (lcfg.tls) |srv| {
        d.tls = Tls.newServerConn(srv.defaultCtx(), d.fd) orelse return closeDown(w, di);
        d.tls_mode = .handshake;
        // The SNI callback reads the snapshot's certificate table: keep the
        // snapshot alive until the handshake is over.
        d.snap = w.pinCurrent() orelse return closeDown(w, di);
        armDownTlsIn(w, di);
        return;
    };
    updateDownRecv(w, di);
}

// ---------------------------------------------------------------- PROXY protocol

fn armDownPre(w: *Worker, di: u32) void {
    const d = get(w, di);
    w.loop.pollOnce(d.fd, linux.POLL.IN | 0x2000, udOf(w, .d_pre, di));
    d.pending += 1;
}

/// Reads the PROXY header without touching the bytes after it: peek, and
/// consume only bytes that are certainly part of the header (the TLS
/// handshake reads the socket directly afterwards).
pub fn onDownPreamble(w: *Worker, di: u32, cqe: *const linux.io_uring_cqe) void {
    const d = get(w, di);
    d.pending -= 1;
    defer if (d.phase == .closing and d.pending == 0) w.reapLater(.down, di, gen(w, di));
    if (d.phase == .closing) return;
    if (cqe.res < 0) return closeDown(w, di);
    const b = w.blocks.bytes(d.pre_blk.?)[0..pp.max_len];
    const n = socket.recvNb(d.fd, b[d.pre_len..], true) catch |e| switch (e) {
        error.WouldBlock => return armDownPre(w, di),
        error.SyscallFailed => return closeDown(w, di),
    };
    if (n == 0) return closeDown(w, di);
    const view = b[0 .. d.pre_len + n];
    switch (pp.parse(view)) {
        .invalid => return rejectPreamble(w, di),
        .incomplete => {
            if (view.len == b.len) return rejectPreamble(w, di);
            // Everything seen is a strict prefix of the header: consume it.
            if (!consume(d.fd, b[d.pre_len..][0..n])) return closeDown(w, di);
            d.pre_len += @intCast(n);
            return armDownPre(w, di);
        },
        .done => |h| {
            if (!consume(d.fd, b[d.pre_len..h.len])) return closeDown(w, di);
            if (h.src) |src| d.ip_len = @intCast(src.formatIp(&d.ip_buf).len);
            w.blocks.unref(d.pre_blk.?);
            d.pre_blk = null;
            d.pp_pending = false;
            startDown(w, di);
        },
    }
}

/// Reads exactly `into.len` bytes that a peek showed are there.
fn consume(fd: linux.fd_t, into: []u8) bool {
    if (into.len == 0) return true;
    const n = socket.recvNb(fd, into, false) catch return false;
    return n == into.len;
}

fn rejectPreamble(w: *Worker, di: u32) void {
    w.stats.inc(.proxy_protocol_rejected);
    closeDown(w, di);
}

// ---------------------------------------------------------------- TLS (downstream)

fn armDownTlsIn(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.tls_poll_in or d.phase == .closing) return;
    w.loop.pollMultishot(d.fd, linux.POLL.IN, udOf(w, .d_tls_in, di));
    d.tls_poll_in = true;
    d.pending += 1;
}

fn armDownTlsOut(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.tls_poll_out or d.phase == .closing) return;
    w.loop.pollOnce(d.fd, linux.POLL.OUT, udOf(w, .d_tls_out, di));
    d.tls_poll_out = true;
    d.pending += 1;
}

pub fn onDownTlsEvent(w: *Worker, di: u32, in: bool, cqe: *const linux.io_uring_cqe) void {
    const d = get(w, di);
    const more = cqe.flags & linux.IORING_CQE_F_MORE != 0;
    if (in) {
        if (!more) {
            d.tls_poll_in = false;
            d.pending -= 1;
        }
    } else {
        d.tls_poll_out = false;
        d.pending -= 1;
    }
    defer if (d.phase == .closing and d.pending == 0) w.reapLater(.down, di, gen(w, di));
    if (d.phase == .closing) return;
    if (cqe.res < 0) {
        if (cqe.res == -@as(i32, @intFromEnum(linux.E.CANCELED))) return;
        return closeDown(w, di);
    }
    switch (d.tls_mode) {
        .handshake => downHandshake(w, di),
        .user => {
            if (!in) tlsFlushDown(w, di);
            tlsReadDown(w, di);
        },
        .none, .ktls => {},
    }
    if (in and !more and d.phase != .closing and (d.tls_mode == .handshake or d.tls_mode == .user)) armDownTlsIn(w, di);
}

fn downHandshake(w: *Worker, di: u32) void {
    const d = get(w, di);
    w.flush_now = true;
    switch (Tls.handshake(d.tls.?)) {
        .n => {},
        .want_read => return armDownTlsIn(w, di),
        .want_write => return armDownTlsOut(w, di),
        .eof, .err => {
            w.stats.inc(.tls_handshake_errors);
            return closeDown(w, di);
        },
    }
    w.stats.inc(.tls_handshakes);
    if (d.snap) |s| {
        w.unpin(s);
        d.snap = null;
    }
    const off = Tls.ktlsStatus(d.tls.?);
    if (off.tx and off.rx) {
        // The socket now carries plaintext: use the zero-copy data path.
        d.tls_mode = .ktls;
        w.stats.inc(.tls_ktls);
        if (d.tls_poll_in) w.loop.cancelUd(udOf(w, .d_tls_in, di));
        updateDownRecv(w, di);
    } else {
        d.tls_mode = .user;
        w.stats.inc(.tls_userspace);
        // Application data may already sit decrypted inside OpenSSL.
        tlsReadDown(w, di);
    }
}

/// Userspace TLS: decrypts into blocks and feeds the HTTP state machine.
pub fn tlsReadDown(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.tls_mode != .user or d.tls_reading) return;
    d.tls_reading = true;
    defer d.tls_reading = false;
    while (d.phase != .closing and wantDownRecv(w, d)) {
        const blk = w.blocks.alloc() orelse return outOfBlocks(w, di);
        const buf = w.blocks.bytes(blk);
        switch (Tls.read(d.tls.?, buf)) {
            .n => |n| {
                w.stats.add(.bytes_received, n);
                if (!d.lingering) handleDownData(w, di, .{ .block = blk }, buf[0..n]);
                w.blocks.unref(blk);
            },
            .want_read => {
                w.blocks.unref(blk);
                return armDownTlsIn(w, di);
            },
            .want_write => {
                w.blocks.unref(blk);
                return armDownTlsOut(w, di);
            },
            .eof => {
                w.blocks.unref(blk);
                return onDownEof(w, di);
            },
            .err => {
                w.blocks.unref(blk);
                return closeDown(w, di);
            },
        }
    }
}

fn tlsFlushDown(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.tls_flushing or d.tls_poll_out) return;
    d.tls_flushing = true;
    defer d.tls_flushing = false;
    while (d.phase != .closing) {
        const head = d.out.head orelse return;
        const seg = w.segs.segs[head];
        switch (Tls.write(d.tls.?, seg.ptr[0..seg.len])) {
            .n => |n| downSent(w, di, n),
            .want_write => return armDownTlsOut(w, di),
            .want_read => return armDownTlsIn(w, di),
            .eof, .err => return closeDown(w, di),
        }
    }
}

/// kTLS receive: a non-data record (alert, KeyUpdate, NewSessionTicket)
/// makes recv fail with EIO; OpenSSL reads it with the record-type cmsg
/// and processes it. Untested in CI: needs a kernel with the tls module.
fn ktlsControlDown(w: *Worker, di: u32) void {
    const d = get(w, di);
    const blk = w.blocks.alloc() orelse return outOfBlocks(w, di);
    defer w.blocks.unref(blk);
    const buf = w.blocks.bytes(blk);
    switch (Tls.read(d.tls.?, buf)) {
        .n => |n| handleDownData(w, di, .{ .block = blk }, buf[0..n]),
        .want_read, .want_write => {},
        .eof => return onDownEof(w, di),
        .err => return closeDown(w, di),
    }
    if (d.phase != .closing) updateDownRecv(w, di);
}

// ---------------------------------------------------------------- recv

/// True when the downstream's outgoing queue is too full to accept more
/// response bytes (the upstream should stop reading).
pub fn downBackpressured(w: *Worker, di: u32) bool {
    return get(w, di).out.bytes > high_water;
}

fn wantDownRecv(w: *Worker, d: *Down) bool {
    if (d.phase == .closing or d.pp_pending) return false;
    if (d.lingering) return true;
    if (d.close_after_flush) return false;
    if (d.phase == .exchange) {
        if (d.up) |ui| {
            if (upool.get(w, ui).out.bytes > high_water) return false;
        }
        if (d.req.done and d.in.len() >= pipeline_cap) return false;
    }
    return true;
}

pub fn updateDownRecv(w: *Worker, di: u32) void {
    const d = get(w, di);
    const want = wantDownRecv(w, d);
    switch (d.tls_mode) {
        .handshake => return,
        .user => {
            if (want and !d.tls_reading) w.tlsKick(.down, di, gen(w, di));
            return;
        },
        .none, .ktls => {},
    }
    if (want and !d.recv_armed) {
        w.loop.recvMultishot(d.fd, worker_mod.buffer_group, udOf(w, .d_recv, di));
        d.recv_armed = true;
        d.recv_cancelling = false;
        d.pending += 1;
    } else if (!want and d.recv_armed and !d.recv_cancelling and d.phase != .closing) {
        w.loop.cancelUd(udOf(w, .d_recv, di));
        d.recv_cancelling = true;
    }
}

pub fn onDownRecv(w: *Worker, di: u32, cqe: *const linux.io_uring_cqe) void {
    const d = get(w, di);
    const more = cqe.flags & linux.IORING_CQE_F_MORE != 0;
    if (!more) {
        d.recv_armed = false;
        d.recv_cancelling = false;
        d.pending -= 1;
    }
    defer if (d.phase == .closing and d.pending == 0) w.reapLater(.down, di, gen(w, di));

    if (cqe.res < 0) {
        switch (@as(linux.E, @enumFromInt(-cqe.res))) {
            .NOBUFS => {
                w.stats.inc(.buffer_ring_enobufs);
                w.needRearm(.down, di, gen(w, di));
            },
            .CANCELED => if (d.phase != .closing) updateDownRecv(w, di),
            .IO, .KEYEXPIRED => if (d.tls_mode == .ktls and d.phase != .closing) ktlsControlDown(w, di) else closeDown(w, di),
            else => closeDown(w, di),
        }
        return;
    }
    if (cqe.res == 0) {
        onDownEof(w, di);
        return;
    }
    const data = w.bufs.take(cqe) catch {
        closeDown(w, di);
        return;
    };
    const bid = w.bufs.idOf(cqe);
    w.stats.add(.bytes_received, data.len);
    if (d.phase != .closing and !d.lingering) handleDownData(w, di, .{ .pbuf = bid }, data);
    w.bufs.unref(bid);
    if (!more and d.phase != .closing) updateDownRecv(w, di);
}

fn onDownEof(w: *Worker, di: u32) void {
    const d = get(w, di);
    d.peer_eof = true;
    if (d.lingering or d.phase == .head) {
        closeDown(w, di);
        return;
    }
    if (d.phase == .exchange) {
        if (!d.req.done) {
            // Client went away mid-request.
            closeDown(w, di);
            return;
        }
        // Client half-closed after sending complete request(s): answer
        // everything it already sent, then close (endExchange decides).
    }
}

fn handleDownData(w: *Worker, di: u32, owner: sq.Owner, data: []const u8) void {
    const d = get(w, di);
    const limits = &w.cur.limits;
    var rest = data;
    while (rest.len > 0) {
        switch (d.phase) {
            .closing => return,
            .head => {
                if (d.close_after_flush) return;
                if (d.in.isEmpty()) {
                    if (d.scanner.feed(rest)) |r| {
                        if (r.end > limits.max_head_bytes) return localError(w, di, 431, true);
                        d.scanner.reset();
                        startRequest(w, di, rest[r.start..r.end]);
                        rest = rest[r.end..];
                        continue;
                    }
                    if (rest.len > limits.max_head_bytes) return localError(w, di, 431, true);
                    // Partial head: continue in the accumulation block.
                    // The scanner's offsets stay valid: the block starts
                    // with exactly these bytes.
                    d.in.append(&w.blocks, rest) catch return outOfBlocks(w, di);
                    return;
                }
                d.in.append(&w.blocks, rest) catch |e| switch (e) {
                    error.NoSpace => return localError(w, di, 431, true),
                    error.OutOfBlocks => return outOfBlocks(w, di),
                };
                pumpIn(w, di);
                return;
            },
            .exchange => {
                if (!d.req.done) {
                    const n = forwardReqBody(w, di, rest, owner) orelse return;
                    rest = rest[n..];
                    continue;
                }
                // Pipelined request: hold it until this exchange ends.
                d.in.append(&w.blocks, rest) catch return closeDown(w, di);
                return;
            },
        }
    }
}

fn outOfBlocks(w: *Worker, di: u32) void {
    w.stats.inc(.blocks_exhausted);
    localError(w, di, 503, true);
}

/// Parses and starts requests from the accumulation block.
fn pumpIn(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.pumping) return;
    d.pumping = true;
    defer d.pumping = false;
    const limits = &w.cur.limits;
    while (d.phase == .head and !d.close_after_flush and !d.in.isEmpty()) {
        const buf = d.in.slice(&w.blocks);
        const r = d.scanner.feed(buf) orelse {
            if (buf.len > limits.max_head_bytes) localError(w, di, 431, true);
            break;
        };
        if (r.end > limits.max_head_bytes) {
            localError(w, di, 431, true);
            break;
        }
        d.scanner.reset();
        // startRequest copies everything it needs out of `buf`.
        startRequest(w, di, buf[r.start..r.end]);
        if (d.phase == .closing) return;
        d.in.consume(r.end);
        if (d.phase == .exchange and !d.req.done and !d.in.isEmpty()) {
            const blk = d.in.block.?;
            const n = forwardReqBody(w, di, d.in.slice(&w.blocks), .{ .block = blk }) orelse return;
            d.in.consume(n);
        }
    }
    if (d.phase != .closing) d.in.trim(&w.blocks);
}

// ---------------------------------------------------------------- requests

fn startRequest(w: *Worker, di: u32, head: []const u8) void {
    const d = get(w, di);
    w.stats.inc(.downstream_rq_total);
    w.wheel.cancel(&d.timer);
    logBegin(w, d);

    var hs: [parser.max_headers]parser.Header = undefined;
    const req = parser.parseRequest(head, &hs) catch |e| {
        w.stats.inc(.downstream_rq_bad_request);
        return localError(w, di, parser.statusFor(e), true);
    };
    if (d.log_on) logRequest(d, &req);
    const info = rules.analyzeRequest(&req) catch |e| {
        w.stats.inc(.downstream_rq_bad_request);
        return localError(w, di, parser.statusFor(e), true);
    };
    const limits = &w.cur.limits;
    d.method = req.method;
    d.client10 = req.version == .http10;
    d.keep_alive = info.keep_alive and !w.draining and d.requests + 1 < limits.max_requests_per_connection;
    d.req = Body.init(info.framing);
    d.phase = .exchange;
    d.resp_head_done = false;
    d.resp_started = false;
    d.resp_bytes_seen = false;
    d.up_poisoned = false;
    d.attempts = 0;
    d.ep_id = null;
    d.body_sent = false;
    d.replayed = false;

    const lcfg = w.listenerCfg(d.listener) orelse return localError(w, di, 503, true);
    d.ext_active = false;

    // Extension (API gateway) first: it may route, edit or answer.
    var ext_out: filter.RequestOut = .{};
    if (filter.registered) |ext| if (w.cur.ext_state) |st| if (w.ext_ws) |ws| {
        const ctx: filter.RequestCtx = .{
            .worker = w.id,
            .workers = @intCast(w.shared.stats.len),
            .now_ms = w.now_ms,
            .req = &req,
            .host = info.host,
            .client_ip = d.ip(),
            .tls = d.tls != null,
            .listener = lcfg,
            .snapshot = w.cur,
        };
        switch (ext.onRequest(ws, st, &ctx, &ext_out)) {
            .proceed => {},
            .respond => |r| return localResponse(w, di, r.status, info.framing != .none, r.content_type, r.headers, r.body),
        }
        d.ext_active = ext.onResponse != null;
        d.ext_token = ext_out.token;
    };

    var target_buf: [8192]u8 = undefined;
    var target: ?[]const u8 = null;
    var route_rewrite: ?[]const u8 = null;
    var route_path_len: usize = 0;
    var route_mirror: ?snapshot.RouteMirror = null;
    if (ext_out.cluster) |c| {
        d.cluster = c;
        d.timeout_ms = if (ext_out.timeout_ms != 0) ext_out.timeout_ms else 60_000;
        target = ext_out.target;
    } else {
        const route = lcfg.routes.?.select(info.host, req.target, req.method) orelse {
            w.stats.inc(.downstream_rq_no_route);
            return localError(w, di, 404, info.framing != .none);
        };
        d.cluster = route.cluster;
        d.timeout_ms = route.timeout_ms;
        route_rewrite = route.prefix_rewrite;
        route_path_len = route.path.len;
        route_mirror = route.mirror;
        if (ext_out.target) |t| target = t;
    }
    d.snap = w.pinCurrent() orelse return localError(w, di, 503, true);
    d.retryable = req.method.idempotent() and info.framing == .none;
    if (!admit(w, d)) {
        w.stats.inc(.upstream_rq_overflow);
        return localError(w, di, 503, info.framing != .none);
    }

    // Path rewrite.
    if (route_rewrite) |pr| {
        const tail = req.target[route_path_len..];
        if (pr.len + tail.len > target_buf.len) return localError(w, di, 414, true);
        @memcpy(target_buf[0..pr.len], pr);
        // Avoid "//" when both the rewrite ends and the tail starts with '/'.
        const skip: usize = if (pr.len > 0 and pr[pr.len - 1] == '/' and tail.len > 0 and tail[0] == '/') 1 else 0;
        @memcpy(target_buf[pr.len .. pr.len + tail.len - skip], tail[skip..]);
        target = target_buf[0 .. pr.len + tail.len - skip];
    }

    const blk = w.blocks.alloc() orelse return outOfBlocks(w, di);
    var out: codec.Out = .{ .buf = w.blocks.bytes(blk) };
    codec.writeRequest(&out, &req, &info, .{
        .client_ip = d.ip(),
        .proto = if (d.tls != null) "https" else "http",
        .trusted_client = lcfg.trust_forwarded_headers,
        .target = target,
        .remove = ext_out.remove,
        .add = ext_out.add,
    }) catch {
        w.blocks.unref(blk);
        return localError(w, di, 431, true);
    };
    d.head_block = blk;
    d.head_len = @intCast(out.len);
    if (route_mirror) |m| if (info.framing == .none and (m.methods & snapshot.methodBit(req.method)) != 0 and
        (m.percent >= 100 or w.prng.random().uintLessThan(u8, 100) < m.percent))
    {
        startMirror(w, di, m.cluster, &req, &info, target, lcfg.trust_forwarded_headers, ext_out.remove, ext_out.add);
    };
    w.schedule(&d.timer, .down, di, gen(w, di), d.timeout_ms);
    startUpstream(w, di, null);
}

/// Serializes the shadow copy (marked, Connection: close) and hands it to
/// the mirror. Any shortage drops the copy, never the request.
fn startMirror(w: *Worker, di: u32, c: *const snapshot.Cluster, req: *const parser.Request, info: *const rules.RequestInfo, target: ?[]const u8, trusted: bool, remove: []const []const u8, add: []const codec.Edit) void {
    const d = get(w, di);
    var edits: [34]codec.Edit = undefined;
    if (add.len + 2 > edits.len) return w.stats.inc(.mirror_dropped);
    @memcpy(edits[0..add.len], add);
    edits[add.len] = .{ .name = "X-Likzik-Shadow", .value = "1" };
    edits[add.len + 1] = .{ .name = "Connection", .value = "close" };
    const blk = w.blocks.alloc() orelse return w.stats.inc(.mirror_dropped);
    var out: codec.Out = .{ .buf = w.blocks.bytes(blk) };
    codec.writeRequest(&out, req, info, .{
        .client_ip = d.ip(),
        .proto = if (d.tls != null) "https" else "http",
        .trusted_client = trusted,
        .target = target,
        .remove = remove,
        .add = edits[0 .. add.len + 2],
    }) catch {
        w.blocks.unref(blk);
        return w.stats.inc(.mirror_dropped);
    };
    mirror.start(w, c, blk, out.len);
}

/// Picks an endpoint and binds an upstream connection to the exchange.
fn startUpstream(w: *Worker, di: u32, exclude_first: ?u32) void {
    const d = get(w, di);
    const c = d.cluster.?;
    var exclude = exclude_first;
    var ctx = w.lbCtx();
    while (d.attempts < c.max_connect_attempts) {
        const ep = (lb.pick(&ctx, c, exclude) catch null) orelse break;
        d.attempts += 1;
        if (d.attempts > 1) w.stats.inc(.upstream_rq_retry);
        const ui = upool.acquire(w, ep, c) catch {
            recordConnectFailure(w, ep.id, c);
            exclude = ep.id;
            continue;
        };
        const st = w.eps.get(w.gpa, ep.id) catch unreachable;
        st.active += 1;
        d.ep_id = ep.id;
        d.log_ep = ep.text;
        d.up = ui;
        const u = upool.get(w, ui);
        u.owner = di;
        u.owner_gen = gen(w, di);
        w.blocks.ref(d.head_block.?);
        u.out.push(&w.segs, .{ .ptr = w.blocks.bytes(d.head_block.?), .len = d.head_len, .owner = .{ .block = d.head_block.? } }) catch {
            w.blocks.unref(d.head_block.?);
            return localError(w, di, 503, true);
        };
        w.stats.inc(.upstream_rq_total);
        if (u.state == .busy) {
            upool.flush(w, ui);
            upool.updateRecv(w, ui);
        }
        return;
    }
    localError(w, di, 503, true);
}

fn recordConnectFailure(w: *Worker, ep_id: u32, c: *const snapshot.Cluster) void {
    w.stats.inc(.upstream_cx_connect_fail);
    w.endpointFailed(c, ep_id, .connect);
}

/// Forwards request body bytes to the upstream. Returns bytes consumed,
/// or null when the connection was closed because of an error.
fn forwardReqBody(w: *Worker, di: u32, data: []const u8, owner: sq.Owner) ?usize {
    const d = get(w, di);
    const n: usize = switch (d.req.kind) {
        .none, .close => 0,
        .length => blk: {
            const n: usize = @intCast(@min(d.req.remaining, data.len));
            d.req.remaining -= n;
            if (d.req.remaining == 0) d.req.done = true;
            break :blk n;
        },
        .chunked => blk: {
            var off: usize = 0;
            while (off < data.len) {
                const s = d.req.dec.step(data[off..]) catch {
                    w.stats.inc(.downstream_rq_bad_request);
                    localError(w, di, 400, true);
                    return null;
                };
                off += s.consumed;
                if (s.done) {
                    d.req.done = true;
                    break;
                }
            }
            break :blk off;
        },
    };
    if (n > 0) {
        d.body_sent = true;
        w.schedule(&d.timer, .down, di, gen(w, di), d.timeout_ms);
        if (d.up) |ui| {
            const u = upool.get(w, ui);
            if (tryCoalesce(w, &u.out, data[0..n])) {
                upool.flush(w, ui);
                updateDownRecv(w, di);
                return n;
            }
            const held = holdForQueue(w, data[0..n], owner) orelse {
                closeDown(w, di);
                return null;
            };
            u.out.push(&w.segs, .{ .ptr = held.bytes.ptr, .len = @intCast(n), .owner = held.owner }) catch {
                w.releaseOwner(held.owner);
                closeDown(w, di);
                return null;
            };
            upool.flush(w, ui);
        }
    }
    updateDownRecv(w, di);
    return n;
}

fn holdOwner(w: *Worker, o: sq.Owner) void {
    switch (o) {
        .none => {},
        .pbuf => |id| w.bufs.ref(id),
        .block => |id| w.blocks.ref(id),
    }
}

/// Takes a reference for a send-queue segment covering `bytes`. When the
/// provided-buffer ring is running low, the bytes are copied into a block
/// instead, so a slow peer cannot pin the shared ring and starve every
/// other connection on this worker. Returns the (possibly new) owner and
/// slice, or null when out of memory.
/// Small bytes are copied into the free space after the queue's tail
/// segment when that segment is a block only the queue references (a
/// head we just serialized). The pair then goes out as one plain send and
/// the source buffer is not held at all.
const coalesce_max = 2048;

/// Runtime switches for A/B testing the send and close paths
/// (--no-coalesce, --always-linger). Set once before workers start.
pub var coalesce_enabled: bool = true;
pub var direct_close_enabled: bool = true;

fn tryCoalesce(w: *Worker, q: *sq.SendQueue, bytes: []const u8) bool {
    if (!coalesce_enabled or bytes.len > coalesce_max or q.inflight) return false;
    const t = q.tailSeg(&w.segs) orelse return false;
    const b = switch (t.owner) {
        .block => |id| id,
        else => return false,
    };
    if (w.blocks.refs[b] != 1) return false;
    const base = @intFromPtr(w.blocks.bytes(b));
    const end = @intFromPtr(t.ptr) + t.len;
    if (end < base or end + bytes.len > base + blocks_mod.block_size) return false;
    const dst: [*]u8 = @ptrFromInt(end);
    @memcpy(dst[0..bytes.len], bytes);
    t.len += @intCast(bytes.len);
    q.grewTail(bytes.len);
    return true;
}

fn holdForQueue(w: *Worker, bytes: []const u8, o: sq.Owner) ?struct { owner: sq.Owner, bytes: []const u8 } {
    if (o == .pbuf and w.bufs.out * 4 > @as(u32, w.bufs.count) * 3) {
        var copied: ?sq.Owner = null;
        if (bytes.len <= blocks_mod.block_size) {
            if (w.blocks.alloc()) |blk| {
                const dst = w.blocks.bytes(blk)[0..bytes.len];
                @memcpy(dst, bytes);
                w.stats.inc(.buffer_ring_copies);
                copied = .{ .block = blk };
                return .{ .owner = copied.?, .bytes = dst };
            }
        }
    }
    holdOwner(w, o);
    return .{ .owner = o, .bytes = bytes };
}

// ---------------------------------------------------------------- responses

fn ownerOf(w: *Worker, ui: u32) ?u32 {
    const u = upool.get(w, ui);
    const di = u.owner orelse return null;
    if (!w.downs.valid(di, u.owner_gen)) return null;
    const d = get(w, di);
    if (d.up == null or d.up.? != ui) return null;
    return di;
}

pub fn onUpConnect(w: *Worker, ui: u32, cqe: *const linux.io_uring_cqe) void {
    const u = upool.get(w, ui);
    u.pending -= 1;
    defer if (u.state == .closing and u.pending == 0) w.reapLater(.up, ui, w.ups.gen(ui));
    if (u.state == .closing) return;
    if (cqe.res == 0) {
        if (u.tls != null) return upHandshake(w, ui);
        return upReady(w, ui);
    }
    const timed_out = cqe.res == -@as(i32, @intFromEnum(linux.E.CANCELED));
    if (timed_out) w.stats.inc(.upstream_cx_connect_timeout);
    upConnectFailed(w, ui, timed_out);
}

/// Connected (and TLS established, if configured).
fn upReady(w: *Worker, ui: u32) void {
    const u = upool.get(w, ui);
    u.state = .busy;
    if (w.eps.get(w.gpa, u.ep_id)) |st| st.recordSuccess() else |_| {}
    if (ownerOf(w, ui) == null) {
        // Downstream went away while connecting: keep the connection.
        upool.release(w, ui);
        return;
    }
    upool.flush(w, ui);
    upool.updateRecv(w, ui);
}

fn upConnectFailed(w: *Worker, ui: u32, timed_out: bool) void {
    const u = upool.get(w, ui);
    const di = ownerOf(w, ui);
    const ep_id = u.ep_id;
    upool.close(w, ui);
    const d_i = di orelse return;
    const d = get(w, d_i);
    if (d.cluster) |c| recordConnectFailure(w, ep_id, c);
    detachUp(w, d_i, false);
    // Nothing reached the upstream, so a connect failure is safe to retry
    // unless request body bytes were already consumed from the client.
    if (d.attempts < d.cluster.?.max_connect_attempts and !d.body_sent) {
        startUpstream(w, d_i, ep_id);
    } else {
        localError(w, d_i, if (timed_out) 504 else 503, !d.req.done);
    }
}

// ---------------------------------------------------------------- TLS (upstream)

fn armUpTlsIn(w: *Worker, ui: u32) void {
    const u = upool.get(w, ui);
    if (u.tls_poll_in or u.state == .closing) return;
    w.loop.pollMultishot(u.fd, linux.POLL.IN, upool.udOf(w, .u_tls_in, ui));
    u.tls_poll_in = true;
    u.pending += 1;
}

fn armUpTlsOut(w: *Worker, ui: u32) void {
    const u = upool.get(w, ui);
    if (u.tls_poll_out or u.state == .closing) return;
    w.loop.pollOnce(u.fd, linux.POLL.OUT, upool.udOf(w, .u_tls_out, ui));
    u.tls_poll_out = true;
    u.pending += 1;
}

pub fn onUpTlsEvent(w: *Worker, ui: u32, in: bool, cqe: *const linux.io_uring_cqe) void {
    const u = upool.get(w, ui);
    const more = cqe.flags & linux.IORING_CQE_F_MORE != 0;
    if (in) {
        if (!more) {
            u.tls_poll_in = false;
            u.pending -= 1;
        }
    } else {
        u.tls_poll_out = false;
        u.pending -= 1;
    }
    defer if (u.state == .closing and u.pending == 0) w.reapLater(.up, ui, w.ups.gen(ui));
    if (u.state == .closing) return;
    if (cqe.res < 0) {
        if (cqe.res == -@as(i32, @intFromEnum(linux.E.CANCELED))) return;
        if (u.tls_mode == .handshake) return upConnectFailed(w, ui, false);
        const di = ownerOf(w, ui);
        upool.close(w, ui);
        if (di) |d_i| upstreamFailed(w, d_i);
        return;
    }
    switch (u.tls_mode) {
        .handshake => upHandshake(w, ui),
        .user => {
            if (!in) tlsFlushUp(w, ui);
            tlsReadUp(w, ui);
        },
        .none, .ktls => {},
    }
    if (in and !more and u.state != .closing and (u.tls_mode == .handshake or u.tls_mode == .user)) armUpTlsIn(w, ui);
}

fn upHandshake(w: *Worker, ui: u32) void {
    const u = upool.get(w, ui);
    w.flush_now = true;
    switch (Tls.handshake(u.tls.?)) {
        .n => {},
        .want_read => return armUpTlsIn(w, ui),
        .want_write => return armUpTlsOut(w, ui),
        .eof, .err => {
            w.stats.inc(.upstream_tls_handshake_errors);
            var ebuf: [160]u8 = undefined;
            log.warn("upstream TLS handshake failed: {s}", .{Tls.lastError(&ebuf)});
            return upConnectFailed(w, ui, false);
        },
    }
    w.stats.inc(.upstream_tls_handshakes);
    const off = Tls.ktlsStatus(u.tls.?);
    if (off.tx and off.rx) {
        u.tls_mode = .ktls;
        w.stats.inc(.tls_ktls);
        if (u.tls_poll_in) w.loop.cancelUd(upool.udOf(w, .u_tls_in, ui));
    } else {
        u.tls_mode = .user;
        w.stats.inc(.tls_userspace);
    }
    upReady(w, ui);
}

pub fn tlsReadUp(w: *Worker, ui: u32) void {
    const u = upool.get(w, ui);
    if (u.tls_mode != .user or u.tls_reading) return;
    u.tls_reading = true;
    defer u.tls_reading = false;
    while (u.state != .closing and upool.wantRecv(w, ui)) {
        const blk = w.blocks.alloc() orelse {
            w.stats.inc(.blocks_exhausted);
            return;
        };
        const buf = w.blocks.bytes(blk);
        switch (Tls.read(u.tls.?, buf)) {
            .n => |n| {
                deliverUpData(w, ui, .{ .block = blk }, buf[0..n]);
                w.blocks.unref(blk);
            },
            .want_read => {
                w.blocks.unref(blk);
                return armUpTlsIn(w, ui);
            },
            .want_write => {
                w.blocks.unref(blk);
                return armUpTlsOut(w, ui);
            },
            .eof => {
                w.blocks.unref(blk);
                return onUpEof(w, ui);
            },
            .err => {
                w.blocks.unref(blk);
                const di = ownerOf(w, ui);
                upool.close(w, ui);
                if (di) |d_i| upstreamFailed(w, d_i);
                return;
            },
        }
    }
}

pub fn tlsFlushUp(w: *Worker, ui: u32) void {
    const u = upool.get(w, ui);
    if (u.tls_flushing or u.tls_poll_out) return;
    u.tls_flushing = true;
    defer u.tls_flushing = false;
    while (u.state == .busy) {
        const head = u.out.head orelse return;
        const seg = w.segs.segs[head];
        switch (Tls.write(u.tls.?, seg.ptr[0..seg.len])) {
            .n => |n| upSent(w, ui, n),
            .want_write => return armUpTlsOut(w, ui),
            .want_read => return armUpTlsIn(w, ui),
            .eof, .err => {
                const di = ownerOf(w, ui);
                upool.close(w, ui);
                if (di) |d_i| upstreamFailed(w, d_i);
                return;
            },
        }
    }
}

fn ktlsControlUp(w: *Worker, ui: u32) void {
    const u = upool.get(w, ui);
    const blk = w.blocks.alloc() orelse return upool.close(w, ui);
    defer w.blocks.unref(blk);
    const buf = w.blocks.bytes(blk);
    switch (Tls.read(u.tls.?, buf)) {
        .n => |n| deliverUpData(w, ui, .{ .block = blk }, buf[0..n]),
        .want_read, .want_write => {},
        .eof => return onUpEof(w, ui),
        .err => {
            const di = ownerOf(w, ui);
            upool.close(w, ui);
            if (di) |d_i| upstreamFailed(w, d_i);
            return;
        },
    }
    if (u.state != .closing) upool.updateRecv(w, ui);
}

fn upSent(w: *Worker, ui: u32, n: usize) void {
    const u = upool.get(w, ui);
    u.out.complete(&w.segs, n, w);
    if (ownerOf(w, ui)) |di| updateDownRecv(w, di);
}

pub fn onUpSend(w: *Worker, ui: u32, cqe: *const linux.io_uring_cqe) void {
    const u = upool.get(w, ui);
    u.pending -= 1;
    defer if (u.state == .closing and u.pending == 0) w.reapLater(.up, ui, w.ups.gen(ui));
    if (cqe.res < 0) {
        u.out.inflight = false;
        const di = ownerOf(w, ui);
        upool.close(w, ui);
        if (di) |d_i| upstreamFailed(w, d_i);
        return;
    }
    if (u.state == .closing) {
        u.out.complete(&w.segs, @intCast(cqe.res), w);
        return;
    }
    upSent(w, ui, @intCast(cqe.res));
    upool.flush(w, ui);
}

pub fn onUpRecv(w: *Worker, ui: u32, cqe: *const linux.io_uring_cqe) void {
    const u = upool.get(w, ui);
    const more = cqe.flags & linux.IORING_CQE_F_MORE != 0;
    if (!more) {
        u.recv_armed = false;
        u.recv_cancelling = false;
        u.pending -= 1;
    }
    defer if (u.state == .closing and u.pending == 0) w.reapLater(.up, ui, w.ups.gen(ui));
    // Anything but the cancellation while parking: the socket is not clean.
    if (u.state == .closing and cqe.res != -@as(i32, @intFromEnum(linux.E.CANCELED))) u.park = false;

    if (cqe.res < 0) {
        switch (@as(linux.E, @enumFromInt(-cqe.res))) {
            .NOBUFS => {
                w.stats.inc(.buffer_ring_enobufs);
                w.needRearm(.up, ui, w.ups.gen(ui));
            },
            .CANCELED => if (u.state != .closing) upool.updateRecv(w, ui),
            .IO, .KEYEXPIRED => if (u.tls_mode == .ktls and u.state != .closing) ktlsControlUp(w, ui) else {
                const di = ownerOf(w, ui);
                upool.close(w, ui);
                if (di) |d_i| upstreamFailed(w, d_i);
            },
            else => {
                const di = ownerOf(w, ui);
                upool.close(w, ui);
                if (di) |d_i| upstreamFailed(w, d_i);
            },
        }
        return;
    }
    if (cqe.res == 0) {
        onUpEof(w, ui);
        return;
    }
    const data = w.bufs.take(cqe) catch {
        upool.close(w, ui);
        return;
    };
    const bid = w.bufs.idOf(cqe);
    defer w.bufs.unref(bid);
    deliverUpData(w, ui, .{ .pbuf = bid }, data);
    if (!more and u.state != .closing) upool.updateRecv(w, ui);
}

fn deliverUpData(w: *Worker, ui: u32, owner: sq.Owner, data: []const u8) void {
    const u = upool.get(w, ui);
    if (u.state == .closing) return;
    const di = ownerOf(w, ui) orelse {
        // Bytes on an idle connection: the upstream is broken.
        w.stats.inc(.upstream_cx_protocol_error);
        upool.close(w, ui);
        return;
    };
    handleUpData(w, di, ui, owner, data);
}

fn handleUpData(w: *Worker, di: u32, ui: u32, owner: sq.Owner, data: []const u8) void {
    const d = get(w, di);
    const u = upool.get(w, ui);
    d.resp_bytes_seen = true;
    // Activity: push the response deadline out.
    w.schedule(&d.timer, .down, di, gen(w, di), d.timeout_ms);
    var rest = data;
    while (rest.len > 0) {
        if (d.phase != .exchange or d.up == null or d.up.? != ui) return;
        if (!d.resp_head_done) {
            if (u.in.isEmpty()) {
                if (u.scanner.feed(rest)) |r| {
                    u.scanner.reset();
                    if (!onRespHead(w, di, ui, rest[r.start..r.end])) return;
                    rest = rest[r.end..];
                    continue;
                }
                u.in.append(&w.blocks, rest) catch return respProtocolError(w, di, ui);
                return;
            }
            u.in.append(&w.blocks, rest) catch return respProtocolError(w, di, ui);
            rest = &.{};
            // Parse heads (possibly several 1xx) out of the block.
            while (!d.resp_head_done and !u.in.isEmpty()) {
                const buf = u.in.slice(&w.blocks);
                const r = u.scanner.feed(buf) orelse return;
                u.scanner.reset();
                if (!onRespHead(w, di, ui, buf[r.start..r.end])) return;
                u.in.consume(r.end);
            }
            if (d.resp_head_done and !d.resp.done and !u.in.isEmpty()) {
                const blk = u.in.block.?;
                const n = forwardRespBody(w, di, u.in.slice(&w.blocks), .{ .block = blk }) orelse return;
                u.in.consume(n);
            }
            if (!u.in.isEmpty() and d.resp_head_done and d.resp.done) d.up_poisoned = true;
            u.in.trim(&w.blocks);
            break;
        }
        if (d.resp.done) {
            // Bytes after a complete response: the connection is unusable.
            d.up_poisoned = true;
            break;
        }
        const n = forwardRespBody(w, di, rest, owner) orelse return;
        rest = rest[n..];
    }
    if (d.phase == .exchange and d.up != null and d.up.? == ui and d.resp_head_done and d.resp.done) {
        finishResponse(w, di);
    }
}

fn respProtocolError(w: *Worker, di: u32, ui: u32) void {
    w.stats.inc(.upstream_cx_protocol_error);
    _ = ui;
    upstreamFailed(w, di);
}

/// Returns false when the exchange was aborted.
fn onRespHead(w: *Worker, di: u32, ui: u32, head: []const u8) bool {
    const d = get(w, di);
    var hs: [parser.max_headers]parser.Header = undefined;
    const resp = parser.parseResponse(head, &hs) catch {
        respProtocolError(w, di, ui);
        return false;
    };
    if (resp.status < 200) {
        if (resp.status == 101) {
            respProtocolError(w, di, ui);
            return false;
        }
        // Interim response: forward to HTTP/1.1 clients, keep reading.
        if (!d.client10) {
            const blk = w.blocks.alloc() orelse {
                outOfBlocks(w, di);
                return false;
            };
            var out: codec.Out = .{ .buf = w.blocks.bytes(blk) };
            const info = rules.analyzeResponse(&resp, d.method) catch {
                w.blocks.unref(blk);
                respProtocolError(w, di, ui);
                return false;
            };
            codec.writeResponse(&out, &resp, &info, .{ .keep_alive = true, .client_http10 = false, .dechunk = false }) catch {
                w.blocks.unref(blk);
                respProtocolError(w, di, ui);
                return false;
            };
            // writeResponse never adds framing for 1xx (framing none).
            queueDown(w, di, w.blocks.bytes(blk)[0..out.len], .{ .block = blk });
            d.resp_started = true;
        }
        return true;
    }
    // Final response: outlier detection on the endpoint that answered,
    // then maybe retry a 5xx elsewhere instead of forwarding it.
    if (resp.status >= 500) w.stats.inc(.upstream_rq_5xx);
    if (d.cluster) |c| if (d.ep_id) |id| {
        if (resp.status >= 500) w.endpointFailed(c, id, .http_5xx) else if (w.eps.get(w.gpa, id)) |st| st.recordResponseOk() else |_| {}
    };
    if (resp.status >= 500 and tryRetry(w, di, .status, resp.status, d.ep_id)) return false;
    const info = rules.analyzeResponse(&resp, d.method) catch {
        respProtocolError(w, di, ui);
        return false;
    };
    d.resp_keep_alive = info.keep_alive;
    d.resp_dechunk = info.framing == .chunked and d.client10;
    if (info.framing == .close_delimited or d.resp_dechunk) d.keep_alive = false;
    if (w.draining) d.keep_alive = false;
    const blk = w.blocks.alloc() orelse {
        outOfBlocks(w, di);
        return false;
    };
    var out: codec.Out = .{ .buf = w.blocks.bytes(blk) };
    var rout: filter.ResponseOut = .{};
    if (d.ext_active) if (d.snap) |s| if (s.ext) |ext| if (ext.onResponse) |onResp| if (s.ext_state) |st| if (w.ext_ws) |ws| {
        onResp(ws, st, &.{ .status = resp.status, .headers = resp.headers, .token = d.ext_token }, &rout);
    };
    codec.writeResponse(&out, &resp, &info, .{ .keep_alive = d.keep_alive, .client_http10 = d.client10, .dechunk = d.resp_dechunk, .remove = rout.remove, .add = rout.add }) catch {
        w.blocks.unref(blk);
        respProtocolError(w, di, ui);
        return false;
    };
    // The response has started: the request can no longer be retried.
    if (d.head_block) |hb| {
        w.blocks.unref(hb);
        d.head_block = null;
    }
    queueDown(w, di, w.blocks.bytes(blk)[0..out.len], .{ .block = blk });
    d.resp_started = true;
    d.resp_head_done = true;
    d.resp = Body.init(info.framing);
    countStatus(w, resp.status);
    d.log_status = resp.status;
    return d.phase == .exchange;
}

fn countStatus(w: *Worker, status: u16) void {
    w.stats.inc(switch (status / 100) {
        1 => .downstream_rq_1xx,
        2 => .downstream_rq_2xx,
        3 => .downstream_rq_3xx,
        4 => .downstream_rq_4xx,
        else => .downstream_rq_5xx,
    });
}

/// Forwards response body bytes. Returns bytes consumed, or null when the
/// exchange was aborted.
fn forwardRespBody(w: *Worker, di: u32, data: []const u8, owner: sq.Owner) ?usize {
    const d = get(w, di);
    switch (d.resp.kind) {
        .none => return 0,
        .length => {
            const n: usize = @intCast(@min(d.resp.remaining, data.len));
            d.resp.remaining -= n;
            if (d.resp.remaining == 0) d.resp.done = true;
            if (n > 0) queueDownHeld(w, di, data[0..n], owner);
            return n;
        },
        .close => {
            queueDownHeld(w, di, data, owner);
            return data.len;
        },
        .chunked => {
            var off: usize = 0;
            while (off < data.len) {
                const s = d.resp.dec.step(data[off..]) catch {
                    w.stats.inc(.upstream_cx_protocol_error);
                    closeDown(w, di);
                    return null;
                };
                if (d.resp_dechunk and s.data_len > 0) {
                    queueDownHeld(w, di, data[off + s.data_off ..][0..s.data_len], owner);
                }
                off += s.consumed;
                if (s.done) {
                    d.resp.done = true;
                    break;
                }
            }
            if (!d.resp_dechunk and off > 0) queueDownHeld(w, di, data[0..off], owner);
            return off;
        },
    }
}

fn queueDownHeld(w: *Worker, di: u32, bytes: []const u8, owner: sq.Owner) void {
    const d = get(w, di);
    if (bytes.len > 0 and tryCoalesce(w, &d.out, bytes)) {
        d.log_bytes += bytes.len;
        markDownDirty(w, di);
        return;
    }
    const held = holdForQueue(w, bytes, owner) orelse return closeDown(w, di);
    queueDown(w, di, held.bytes, held.owner);
}

/// Queues bytes to the client; takes over one reference on `owner`.
fn queueDown(w: *Worker, di: u32, bytes: []const u8, owner: sq.Owner) void {
    const d = get(w, di);
    if (bytes.len == 0) {
        w.releaseOwner(owner);
        return;
    }
    d.log_bytes += bytes.len;
    d.out.push(&w.segs, .{ .ptr = bytes.ptr, .len = @intCast(bytes.len), .owner = owner }) catch {
        w.releaseOwner(owner);
        closeDown(w, di);
        return;
    };
    markDownDirty(w, di);
    if (d.up) |ui| if (d.out.bytes > high_water) upool.updateRecv(w, ui);
}

fn onUpEof(w: *Worker, ui: u32) void {
    const u = upool.get(w, ui);
    const di = ownerOf(w, ui);
    if (di) |d_i| {
        const d = get(w, d_i);
        if (d.resp_head_done and d.resp.kind == .close) {
            d.resp.done = true;
            d.up_poisoned = true;
            finishResponse(w, d_i);
        } else {
            upool.close(w, ui);
            upstreamFailed(w, d_i);
            return;
        }
    }
    if (u.state != .closing) upool.close(w, ui);
}

/// The upstream connection broke before the exchange completed.
fn upstreamFailed(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.phase != .exchange) return;
    const reused = if (d.up) |ui| upool.get(w, ui).reused else false;
    const prev_ep = d.ep_id;
    detachUp(w, di, true);
    if (d.resp_started) {
        // Mid-response: all we can do is close the client connection.
        closeDown(w, di);
        return;
    }
    // A pooled connection the upstream closed concurrently: retry once on
    // a fresh connection when the request is safe to replay.
    if (reused and d.retryable and !d.replayed and !d.resp_bytes_seen and d.head_block != null) {
        d.replayed = true;
        d.attempts -|= 1;
        startUpstream(w, di, null);
        return;
    }
    if (tryRetry(w, di, .reset, 0, prev_ep)) return;
    localError(w, di, 502, true);
}

fn detachUp(w: *Worker, di: u32, close_it: bool) void {
    const d = get(w, di);
    if (d.up) |ui| {
        const u = upool.get(w, ui);
        if (u.owner == di) u.owner = null;
        if (close_it) upool.close(w, ui);
        d.up = null;
    }
    if (d.ep_id) |id| {
        const st = w.eps.get(w.gpa, id) catch unreachable;
        st.active -|= 1;
        d.ep_id = null;
    }
}

fn finishResponse(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.up) |ui| {
        const u = upool.get(w, ui);
        const reusable = d.resp_keep_alive and d.req.done and !d.up_poisoned and u.in.isEmpty() and u.state == .busy;
        detachUp(w, di, false);
        if (reusable) upool.release(w, ui) else upool.close(w, ui);
    } else detachUp(w, di, false);
    if (!d.req.done) d.keep_alive = false;
    endExchange(w, di);
}

fn endExchange(w: *Worker, di: u32) void {
    const d = get(w, di);
    logEnd(w, d);
    releaseLoad(w, d);
    if (d.snap) |s| {
        w.unpin(s);
        d.snap = null;
    }
    if (d.head_block) |hb| {
        w.blocks.unref(hb);
        d.head_block = null;
    }
    d.requests += 1;
    d.cluster = null;
    d.resp_head_done = false;
    const req_fully_read = d.req.done;
    d.resp = .{};
    d.req = .{};
    if (d.phase == .closing) return;
    // After a client FIN, only requests already buffered are served.
    var probe = d.scanner; // a copy: probing must not advance the real scanner
    const nothing_more = d.peer_eof and (d.in.isEmpty() or probe.feed(d.in.slice(&w.blocks)) == null);
    if (!d.keep_alive or w.draining or nothing_more) {
        d.phase = .head;
        d.close_after_flush = true;
        w.wheel.cancel(&d.timer);
        // A complete exchange with nothing buffered: close right away (a
        // client FIN or unread bytes can't be lost). Otherwise linger.
        d.linger_needed = !req_fully_read or !d.in.isEmpty() or d.error_close;
        if (d.out.isEmpty() and !d.out.inflight) closeOrLinger(w, di) else updateDownRecv(w, di);
        return;
    }
    d.phase = .head;
    w.schedule(&d.timer, .down, di, gen(w, di), if (d.in.isEmpty()) w.cur.limits.idle_timeout_ms else w.cur.limits.header_timeout_ms);
    updateDownRecv(w, di);
    pumpIn(w, di);
}

/// Sends a locally generated response. `close` forces the connection to
/// close after it (always the case when request body bytes are unread).
fn localError(w: *Worker, di: u32, status: u16, close: bool) void {
    var body_buf: [64]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{d} {s}\n", .{ status, codec.reasonPhrase(status) }) catch "";
    localResponse(w, di, status, close, "text/plain", &.{}, body);
}

/// Sends a locally generated response (errors, or an extension's answer).
fn localResponse(w: *Worker, di: u32, status: u16, close: bool, content_type: []const u8, extra: []const codec.Edit, body: []const u8) void {
    const d = get(w, di);
    if (d.phase == .closing) return;
    if (d.resp_started) {
        closeDown(w, di);
        return;
    }
    detachUp(w, di, true);
    if (d.phase == .exchange and !d.req.done) d.keep_alive = false;
    if (close) {
        d.keep_alive = false;
        d.error_close = true;
    }
    if (w.draining) d.keep_alive = false;
    if (d.phase == .head) {
        d.phase = .exchange; // local response counts as an exchange
        if (!d.log_on) logBegin(w, d); // e.g. a timeout before a full head
    }
    const blk = w.blocks.alloc() orelse {
        closeDown(w, di);
        return;
    };
    var out: codec.Out = .{ .buf = w.blocks.bytes(blk) };
    codec.writeLocalEx(&out, status, d.keep_alive, content_type, extra, body) catch {
        // Larger than one block: an extension's body is too big.
        out.len = 0;
        codec.writeLocal(&out, 500, false, "500 Internal Server Error\n") catch unreachable;
        d.keep_alive = false;
    };
    countStatus(w, status);
    d.log_status = status;
    if (status == 408 or status == 504) w.stats.inc(.downstream_rq_timeout);
    d.resp_started = true;
    queueDown(w, di, w.blocks.bytes(blk)[0..out.len], .{ .block = blk });
    if (d.phase == .closing) return;
    endExchange(w, di);
}

// ---------------------------------------------------------------- circuit breakers and retries

/// Counts the request against its cluster; false when the cluster's
/// max_requests is reached (circuit open).
fn admit(w: *Worker, d: *Down) bool {
    const c = d.cluster.?;
    d.retries = 0;
    d.in_retry = false;
    const load = w.cluster_load.get(w.gpa, c.id) catch return true;
    if (load.active_rq >= breaker.share(c.breakers.max_requests, w.shared.stats.len)) return false;
    load.active_rq += 1;
    d.cb_on = true;
    d.cb_id = c.id;
    return true;
}

fn releaseLoad(w: *Worker, d: *Down) void {
    if (!d.cb_on) return;
    d.cb_on = false;
    const load = w.cluster_load.get(w.gpa, d.cb_id) catch return;
    load.active_rq -|= 1;
    if (d.in_retry) load.active_retries -|= 1;
    d.in_retry = false;
}

const RetryCause = enum { status, reset };

/// Retries the request on another endpoint when the cluster's policy,
/// the request (idempotent, no body, nothing sent to the client yet) and
/// the retry budget allow it. Returns true when a retry started.
fn tryRetry(w: *Worker, di: u32, cause: RetryCause, status: u16, exclude: ?u32) bool {
    const d = get(w, di);
    const c = d.cluster orelse return false;
    const r = c.retry orelse return false;
    const wanted = switch (cause) {
        .reset => r.on_reset,
        .status => r.on_5xx or (r.on_gateway_error and status >= 502 and status <= 504),
    };
    if (!wanted or !d.retryable or d.resp_started or d.head_block == null or !d.cb_on) return false;
    if (d.retries >= r.num_retries) return false;
    const load = w.cluster_load.get(w.gpa, c.id) catch return false;
    if (!d.in_retry) {
        if (!breaker.retryAllowed(load, r.budget_percent, c.breakers.max_retries, w.shared.stats.len)) {
            w.stats.inc(.upstream_rq_retry_overflow);
            return false;
        }
        load.active_retries += 1;
        d.in_retry = true;
    }
    d.retries += 1;
    w.stats.inc(.upstream_rq_retry);
    detachUp(w, di, true);
    d.attempts = 0;
    d.resp_bytes_seen = false;
    startUpstream(w, di, exclude);
    return true;
}

// ---------------------------------------------------------------- access log

fn logBegin(w: *Worker, d: *Down) void {
    d.log_on = w.cur.access_log != null;
    if (!d.log_on) return;
    d.log_start_wall = access_log.wallMs();
    d.log_start_ms = w.now_ms;
    d.log_status = 0;
    d.log_bytes = 0;
    d.log_ep = "";
    d.log_method_len = 0;
    d.log_target_len = 0;
}

fn logRequest(d: *Down, req: *const parser.Request) void {
    const m = req.method_raw[0..@min(req.method_raw.len, d.log_method.len)];
    @memcpy(d.log_method[0..m.len], m);
    d.log_method_len = @intCast(m.len);
    const t = req.target[0..@min(req.target.len, d.log_target.len)];
    @memcpy(d.log_target[0..t.len], t);
    d.log_target_len = @intCast(t.len);
}

fn logEnd(w: *Worker, d: *Down) void {
    if (!d.log_on) return;
    d.log_on = false;
    const cfg = w.cur.access_log orelse return;
    const e: access_log.Entry = .{
        .time_ms = d.log_start_wall,
        .client = d.ip(),
        .listener = w.listeners[d.listener].name(),
        .method = d.log_method[0..d.log_method_len],
        .target = d.log_target[0..d.log_target_len],
        .http10 = d.client10,
        .status = d.log_status,
        .bytes = d.log_bytes,
        .duration_ms = w.now_ms -| d.log_start_ms,
        .cluster = if (d.cluster) |c| c.name else "",
        .upstream = d.log_ep,
        .tls = d.tls != null,
    };
    var buf: [access_log.max_line]u8 = undefined;
    if (!w.shared.access_logs[w.id].write(access_log.format(cfg.format, &e, &buf)))
        w.stats.inc(.access_log_dropped);
}

// ---------------------------------------------------------------- send

fn markDownDirty(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.dirty) return;
    d.dirty = true;
    w.markDirty(.down, di, gen(w, di));
}

pub fn flushDownNow(w: *Worker, di: u32) void {
    get(w, di).dirty = false;
    flushDown(w, di);
}

fn flushDown(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.phase == .closing or d.out.inflight or d.out.isEmpty()) return;
    switch (d.tls_mode) {
        .user => return tlsFlushDown(w, di),
        .handshake => return,
        .none, .ktls => {},
    }
    if (d.out.single(&w.segs)) |bytes| {
        w.loop.send(d.fd, bytes, udOf(w, .d_send, di));
    } else {
        const msg = d.out.prepare(&w.segs);
        w.loop.sendmsg(d.fd, msg, udOf(w, .d_send, di));
    }
    d.pending += 1;
}

pub fn onDownSend(w: *Worker, di: u32, cqe: *const linux.io_uring_cqe) void {
    const d = get(w, di);
    d.pending -= 1;
    defer if (d.phase == .closing and d.pending == 0) w.reapLater(.down, di, gen(w, di));
    if (cqe.res < 0) {
        d.out.inflight = false;
        closeDown(w, di);
        return;
    }
    downSent(w, di, @intCast(cqe.res));
}

/// `n` bytes of the send queue reached the socket (or OpenSSL).
fn downSent(w: *Worker, di: u32, n: usize) void {
    const d = get(w, di);
    const was_full = d.out.bytes > high_water;
    d.out.complete(&w.segs, n, w);
    w.stats.add(.bytes_sent, n);
    if (d.phase == .closing) return;
    if (!d.out.isEmpty()) {
        flushDown(w, di);
    } else if (d.close_after_flush and !d.lingering) {
        closeOrLinger(w, di);
    }
    if (was_full and d.out.bytes <= high_water) {
        if (d.up) |ui| upool.updateRecv(w, ui);
    }
}

fn closeOrLinger(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.linger_needed or !direct_close_enabled) return beginLinger(w, di);
    if (d.tls) |t| if (d.tls_mode == .user or d.tls_mode == .ktls) Tls.shutdown(t);
    closeDown(w, di);
}

/// Graceful close: send FIN, then wait briefly for the client's FIN so
/// unread request bytes do not turn into an RST that destroys the response.
fn beginLinger(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.lingering or d.phase == .closing) return;
    d.lingering = true;
    if (d.tls) |t| if (d.tls_mode == .user or d.tls_mode == .ktls) Tls.shutdown(t);
    socket.shutdownWrite(d.fd);
    if (d.peer_eof) {
        closeDown(w, di);
        return;
    }
    w.schedule(&d.timer, .down, di, gen(w, di), linger_ms);
    updateDownRecv(w, di);
}

// ---------------------------------------------------------------- close

pub fn closeDown(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.phase == .closing) return;
    logEnd(w, d); // an exchange cut short (status "-" if nothing was sent)
    releaseLoad(w, d);
    d.phase = .closing;
    w.wheel.cancel(&d.timer);
    detachUp(w, di, true);
    if (d.snap) |s| {
        w.unpin(s);
        d.snap = null;
    }
    if (d.head_block) |hb| {
        w.blocks.unref(hb);
        d.head_block = null;
    }
    if (d.pending > 0) w.loop.cancelFd(d.fd);
    w.reapLater(.down, di, gen(w, di));
}

pub fn maybeFreeDown(w: *Worker, di: u32) void {
    const d = get(w, di);
    if (d.phase != .closing or d.pending > 0) return;
    d.out.clear(&w.segs, w);
    d.in.release(&w.blocks);
    if (d.pre_blk) |blk| w.blocks.unref(blk);
    if (d.tls) |t| Tls.freeConn(t);
    socket.closeFd(d.fd);
    w.listeners[d.listener].conns -= 1;
    w.downs.release(di);
    w.stats.dec(.downstream_cx_active);
}

pub fn onDownTimer(w: *Worker, di: u32) void {
    const d = get(w, di);
    switch (d.phase) {
        .closing => {},
        .head => {
            if (d.tls_mode == .handshake) return closeDown(w, di); // handshake timeout
            if (d.lingering or d.close_after_flush) return closeDown(w, di);
            if (d.in.isEmpty() and d.scanner.pos == 0) return closeDown(w, di); // keep-alive idle
            localError(w, di, 408, true);
        },
        .exchange => {
            if (d.up != null and !d.resp_started) {
                w.stats.inc(.upstream_rq_timeout);
                localError(w, di, 504, true);
            } else closeDown(w, di);
        },
    }
}

/// Listener removed: close idle connections now, finish in-flight
/// exchanges with `Connection: close`.
pub fn drainListener(w: *Worker, slot: u16) void {
    for (w.downs.items, 0..) |*d, i| {
        if (!w.downs.live[i] or d.listener != slot) continue;
        drainOne(w, @intCast(i));
    }
}

pub fn drainAll(w: *Worker) void {
    for (w.downs.items, 0..) |_, i| {
        if (w.downs.live[i]) drainOne(w, @intCast(i));
    }
}

fn drainOne(w: *Worker, di: u32) void {
    const d = get(w, di);
    switch (d.phase) {
        .closing => {},
        .head => if (!d.close_after_flush and d.in.isEmpty()) closeDown(w, di),
        .exchange => d.keep_alive = false,
    }
}

pub fn closeAll(w: *Worker) void {
    for (w.downs.items, 0..) |_, i| {
        if (w.downs.live[i]) closeDown(w, @intCast(i));
    }
}
