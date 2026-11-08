//! Thin `Loop` layer over one io_uring: user_data encoding and SQE
//! helpers. Everything above this file talks in terms of Op + object
//! index + generation, which is what a simulated loop (tests) or an epoll
//! backend would need to provide as well.

const std = @import("std");
const linux = std.os.linux;
const IoUring = linux.IoUring;

pub const IORING_TIMEOUT_MULTISHOT: u32 = 1 << 6;

pub const Op = enum(u8) {
    /// Completions we do not care about (cancels, link timeouts, closes).
    ignore = 0,
    accept,
    d_recv,
    d_send,
    u_connect,
    u_recv,
    u_send,
    /// TCP tunnel: readiness on the downstream / upstream socket.
    t_in_d,
    t_in_u,
    t_out_d,
    t_out_u,
    t_connect,
    /// Connection preamble (PROXY protocol header, TLS ClientHello peek).
    t_pre,
    d_pre,
    /// Mirrored (shadow) requests.
    m_connect,
    m_send,
    m_read,
    /// TLS readiness (handshake and userspace-TLS data path).
    d_tls_in,
    d_tls_out,
    u_tls_in,
    u_tls_out,
    tick,
    wake,
};

pub const Ud = packed struct(u64) {
    idx: u24,
    op: Op,
    gen: u32,

    pub inline fn encode(op: Op, idx: u32, gen: u32) u64 {
        return @bitCast(Ud{ .idx = @intCast(idx), .op = op, .gen = gen });
    }

    pub inline fn decode(v: u64) Ud {
        return @bitCast(v);
    }
};

pub const ignore_ud: u64 = 0;

pub const Loop = struct {
    ring: IoUring,

    pub fn init(entries: u16) !Loop {
        var params = std.mem.zeroInit(linux.io_uring_params, .{
            .flags = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_DEFER_TASKRUN |
                linux.IORING_SETUP_COOP_TASKRUN | linux.IORING_SETUP_SUBMIT_ALL | linux.IORING_SETUP_CQSIZE,
            .cq_entries = @as(u32, entries) * 4,
        });
        return .{ .ring = try IoUring.init_params(entries, &params) };
    }

    pub fn deinit(self: *Loop) void {
        self.ring.deinit();
    }

    /// Never fails for lack of SQ space: flushes to the kernel instead.
    pub fn sqe(self: *Loop) *linux.io_uring_sqe {
        while (true) {
            return self.ring.get_sqe() catch {
                _ = self.ring.submit() catch {};
                continue;
            };
        }
    }

    pub fn acceptMultishot(self: *Loop, fd: linux.fd_t, ud: u64) void {
        const s = self.sqe();
        s.prep_multishot_accept(fd, null, null, linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK);
        s.user_data = ud;
    }

    pub fn recvMultishot(self: *Loop, fd: linux.fd_t, group: u16, ud: u64) void {
        const s = self.sqe();
        s.prep_rw(.RECV, fd, 0, 0, 0);
        s.flags |= linux.IOSQE_BUFFER_SELECT;
        s.buf_index = group;
        s.ioprio |= linux.IORING_RECV_MULTISHOT;
        s.user_data = ud;
    }

    pub fn send(self: *Loop, fd: linux.fd_t, bytes: []const u8, ud: u64) void {
        const s = self.sqe();
        s.prep_send(fd, bytes, linux.MSG.NOSIGNAL);
        s.user_data = ud;
    }

    pub fn sendmsg(self: *Loop, fd: linux.fd_t, msg: *const linux.msghdr_const, ud: u64) void {
        const s = self.sqe();
        s.prep_sendmsg(fd, msg, linux.MSG.NOSIGNAL);
        s.user_data = ud;
    }

    /// connect with a linked timeout: the kernel cancels the connect when
    /// the timeout fires (the connect CQE then carries -ECANCELED).
    pub fn connect(self: *Loop, fd: linux.fd_t, addr: *const linux.sockaddr, len: linux.socklen_t, ts: *const linux.kernel_timespec, ud: u64) void {
        const s = self.sqe();
        s.prep_connect(fd, addr, len);
        s.flags |= linux.IOSQE_IO_LINK;
        s.user_data = ud;
        const t = self.sqe();
        t.prep_link_timeout(ts, 0);
        t.user_data = ignore_ud;
    }

    pub fn pollMultishot(self: *Loop, fd: linux.fd_t, mask: u32, ud: u64) void {
        const s = self.sqe();
        s.prep_poll_add(fd, mask);
        s.len = linux.IORING_POLL_ADD_MULTI;
        s.user_data = ud;
    }

    pub fn pollOnce(self: *Loop, fd: linux.fd_t, mask: u32, ud: u64) void {
        const s = self.sqe();
        s.prep_poll_add(fd, mask);
        s.user_data = ud;
    }

    /// Cancels the operation(s) with this user_data.
    pub fn cancelUd(self: *Loop, target: u64) void {
        const s = self.sqe();
        s.prep_cancel(target, linux.IORING_ASYNC_CANCEL_ALL);
        s.user_data = ignore_ud;
    }

    /// Cancels every operation on `fd`.
    pub fn cancelFd(self: *Loop, fd: linux.fd_t) void {
        const s = self.sqe();
        s.prep_cancel_fd(fd, linux.IORING_ASYNC_CANCEL_ALL);
        s.user_data = ignore_ud;
    }

    pub fn tickTimer(self: *Loop, ts: *const linux.kernel_timespec, ud: u64) void {
        const s = self.sqe();
        s.prep_timeout(ts, 0, IORING_TIMEOUT_MULTISHOT);
        s.user_data = ud;
    }

    pub fn submitAndWait(self: *Loop, n: u32) !void {
        _ = self.ring.submit_and_wait(n) catch |e| switch (e) {
            error.SignalInterrupt => return,
            else => return e,
        };
    }
};

/// Posts a CQE carrying `ud` and `res` into another ring (IORING_OP_MSG_RING).
pub fn msgRing(from: *IoUring, target_ring_fd: linux.fd_t, res: u32, ud: u64) !void {
    const s = try from.get_sqe();
    s.prep_rw(.MSG_RING, target_ring_fd, 0, res, ud);
    s.user_data = ignore_ud;
}

test "user data round trip" {
    const v = Ud.encode(.u_send, 0xabcdef, 0xdeadbeef);
    const d = Ud.decode(v);
    try std.testing.expectEqual(Op.u_send, d.op);
    try std.testing.expectEqual(@as(u24, 0xabcdef), d.idx);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), d.gen);
    try std.testing.expect(v != ignore_ud);
}
