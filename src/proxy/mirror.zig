//! Request mirroring: a copy of a request goes to a shadow cluster and the
//! response is discarded. Safety rules from the plan:
//!
//! * never slow the primary: the copy uses its own fresh connection, its
//!   own ring operations and a bounded slot pool; when the worker is out of
//!   slots or blocks the copy is dropped (`mirror_dropped`), never queued;
//! * marked and safe by default: `X-Likzik-Shadow: 1` and
//!   `Connection: close` are added; only requests without a body are
//!   mirrored (GET and HEAD unless the route lists other methods);
//! * isolated: short timeout (the shadow cluster's connect timeout for
//!   connecting, `mirror_timeout_ms` overall), no retries, and the response
//!   is read only far enough to count its status class.

const std = @import("std");
const linux = std.os.linux;

const worker_mod = @import("../runtime/worker.zig");
const Worker = worker_mod.Worker;
const loop_mod = @import("../runtime/loop.zig");
const Ud = loop_mod.Ud;
const tw = @import("../runtime/timer_wheel.zig");
const snapshot = @import("../config/snapshot.zig");
const socket = @import("../net/socket.zig");
const Address = @import("../net/addr.zig").Address;
const lb = @import("../upstream/lb.zig");

/// Shadow requests in flight per worker.
pub const max_in_flight = 256;
/// Whole-exchange limit for one shadow request.
pub const mirror_timeout_ms = 2_000;

pub const State = enum { connecting, sending, reading, closing };

pub const Shadow = struct {
    fd: linux.fd_t = -1,
    state: State = .connecting,
    blk: u32 = 0,
    len: u32 = 0,
    sent: u32 = 0,
    pending: u16 = 0,
    timer: tw.Timer = .{},
    addr: Address = undefined,
    connect_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 },
    status: [12]u8 = undefined,
    got: u8 = 0,
};

inline fn get(w: *Worker, si: u32) *Shadow {
    return w.shadows.get(si);
}

inline fn udOf(w: *Worker, op: loop_mod.Op, si: u32) u64 {
    return Worker.ud(op, si, w.shadows.gen(si));
}

/// Starts a shadow exchange. `head` is a complete request head in block
/// `blk` (one reference is taken over).
pub fn start(w: *Worker, c: *const snapshot.Cluster, blk: u32, len: usize) void {
    const si = w.shadows.alloc() orelse {
        w.blocks.unref(blk);
        w.stats.inc(.mirror_dropped);
        return;
    };
    var ctx = w.lbCtx();
    const ep = (lb.pick(&ctx, c, null) catch null) orelse {
        w.shadows.release(si);
        w.blocks.unref(blk);
        w.stats.inc(.mirror_errors);
        return;
    };
    const fd = socket.connectSocket(&ep.addr) catch {
        w.shadows.release(si);
        w.blocks.unref(blk);
        w.stats.inc(.mirror_errors);
        return;
    };
    const s = get(w, si);
    s.* = .{ .fd = fd, .blk = blk, .len = @intCast(len), .addr = ep.addr };
    s.connect_ts = .{ .sec = @intCast(c.connect_timeout_ms / 1000), .nsec = @intCast((c.connect_timeout_ms % 1000) * std.time.ns_per_ms) };
    w.loop.connect(fd, &s.addr.any, s.addr.len(), &s.connect_ts, udOf(w, .m_connect, si));
    s.pending += 1;
    w.schedule(&s.timer, .shadow, si, w.shadows.gen(si), mirror_timeout_ms);
    w.stats.inc(.mirror_requests);
}

pub fn onEvent(w: *Worker, u: Ud, cqe: *const linux.io_uring_cqe) void {
    const si: u32 = u.idx;
    const s = get(w, si);
    s.pending -= 1;
    defer if (s.state == .closing and s.pending == 0) w.reapLater(.shadow, si, w.shadows.gen(si));
    if (s.state == .closing) return;
    if (cqe.res < 0) return fail(w, si);
    switch (u.op) {
        .m_connect => {
            s.state = .sending;
            sendMore(w, si);
        },
        .m_send => {
            s.sent += @intCast(cqe.res);
            if (s.sent < s.len) return sendMore(w, si);
            s.state = .reading;
            armRead(w, si);
        },
        .m_read => readSome(w, si),
        else => unreachable,
    }
}

fn sendMore(w: *Worker, si: u32) void {
    const s = get(w, si);
    w.loop.send(s.fd, w.blocks.bytes(s.blk)[s.sent..s.len], udOf(w, .m_send, si));
    s.pending += 1;
}

fn armRead(w: *Worker, si: u32) void {
    const s = get(w, si);
    w.loop.pollOnce(s.fd, linux.POLL.IN, udOf(w, .m_read, si));
    s.pending += 1;
}

/// Reads the status line, then discards the rest until the upstream
/// closes (the request asked for `Connection: close`).
fn readSome(w: *Worker, si: u32) void {
    const s = get(w, si);
    while (true) {
        if (s.got < s.status.len) {
            const n = socket.recvNb(s.fd, s.status[s.got..], false) catch |e| switch (e) {
                error.WouldBlock => return armRead(w, si),
                error.SyscallFailed => return fail(w, si),
            };
            if (n == 0) return fail(w, si);
            s.got += @intCast(n);
            if (s.got == s.status.len) {
                const class = if (std.mem.startsWith(u8, &s.status, "HTTP/1.")) s.status[9] else '0';
                if (class == '5') w.stats.inc(.mirror_5xx);
            }
            continue;
        }
        var sink: [4096]u8 = undefined;
        const n = socket.recvNb(s.fd, &sink, false) catch |e| switch (e) {
            error.WouldBlock => return armRead(w, si),
            error.SyscallFailed => return close(w, si),
        };
        if (n == 0) return close(w, si);
    }
}

fn fail(w: *Worker, si: u32) void {
    w.stats.inc(.mirror_errors);
    close(w, si);
}

pub fn onTimer(w: *Worker, si: u32) void {
    if (get(w, si).state != .closing) fail(w, si);
}

pub fn close(w: *Worker, si: u32) void {
    const s = get(w, si);
    if (s.state == .closing) return;
    s.state = .closing;
    w.wheel.cancel(&s.timer);
    if (s.pending > 0) w.loop.cancelFd(s.fd);
    w.reapLater(.shadow, si, w.shadows.gen(si));
}

pub fn maybeFree(w: *Worker, si: u32) void {
    const s = get(w, si);
    if (s.state != .closing or s.pending > 0) return;
    socket.closeFd(s.fd);
    w.blocks.unref(s.blk);
    w.shadows.release(si);
}

pub fn closeAll(w: *Worker) void {
    for (w.shadows.items, 0..) |_, i| {
        if (w.shadows.live[i]) close(w, @intCast(i));
    }
}
