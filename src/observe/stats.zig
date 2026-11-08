//! Per-worker counters. Each worker writes only its own block with plain
//! (relaxed, non-RMW) stores, so the hot path has no locked instructions.
//! The control thread sums all blocks when /metrics or /stats is scraped.

const std = @import("std");

pub const Counter = enum {
    downstream_cx_total,
    downstream_cx_active,
    downstream_rq_total,
    downstream_rq_1xx,
    downstream_rq_2xx,
    downstream_rq_3xx,
    downstream_rq_4xx,
    downstream_rq_5xx,
    downstream_rq_bad_request,
    downstream_rq_no_route,
    downstream_rq_timeout,
    downstream_cx_overflow,
    upstream_cx_total,
    upstream_cx_active,
    upstream_cx_connect_fail,
    upstream_cx_connect_timeout,
    upstream_cx_pool_hit,
    upstream_cx_idle,
    upstream_rq_total,
    upstream_rq_retry,
    /// Requests answered 503 because a cluster's circuit breaker was open.
    upstream_rq_overflow,
    /// Retries refused by the retry budget or max_retries.
    upstream_rq_retry_overflow,
    /// Shadow requests sent, dropped (no slot), failed, and answered 5xx.
    mirror_requests,
    mirror_dropped,
    mirror_errors,
    mirror_5xx,
    upstream_rq_5xx,
    upstream_rq_timeout,
    upstream_cx_protocol_error,
    endpoint_ejections,
    tls_handshakes,
    tls_handshake_errors,
    /// Connections whose TLS runs in the kernel (kTLS, both directions).
    tls_ktls,
    /// Connections that fell back to userspace TLS.
    tls_userspace,
    upstream_tls_handshakes,
    upstream_tls_handshake_errors,
    tcp_cx_total,
    tcp_cx_active,
    tcp_bytes,
    /// TCP connections closed because no SNI route (and no default) matched.
    tcp_sni_unmatched,
    /// Connections closed for a missing or malformed PROXY protocol header.
    proxy_protocol_rejected,
    bytes_received,
    bytes_sent,
    buffer_ring_enobufs,
    /// Bytes copied out of the provided-buffer ring under pressure.
    buffer_ring_copies,
    blocks_exhausted,
    /// Access log lines dropped because the worker's log ring was full.
    access_log_dropped,
    snapshot_generation,
    snapshot_swaps,
    draining,
};

pub const n_counters = @typeInfo(Counter).@"enum".field_names.len;

/// Counters that are gauges in Prometheus terms.
pub fn isGauge(c: Counter) bool {
    return switch (c) {
        .downstream_cx_active, .upstream_cx_active, .upstream_cx_idle, .tcp_cx_active, .snapshot_generation, .draining => true,
        else => false,
    };
}

pub const WorkerStats = struct {
    v: [n_counters]u64 align(std.atomic.cache_line) = @splat(0),

    pub inline fn add(self: *WorkerStats, c: Counter, n: u64) void {
        const p = &self.v[@intFromEnum(c)];
        @atomicStore(u64, p, @atomicLoad(u64, p, .monotonic) +% n, .monotonic);
    }

    pub inline fn inc(self: *WorkerStats, c: Counter) void {
        self.add(c, 1);
    }

    pub inline fn dec(self: *WorkerStats, c: Counter) void {
        const p = &self.v[@intFromEnum(c)];
        @atomicStore(u64, p, @atomicLoad(u64, p, .monotonic) -% 1, .monotonic);
    }

    pub inline fn set(self: *WorkerStats, c: Counter, n: u64) void {
        @atomicStore(u64, &self.v[@intFromEnum(c)], n, .monotonic);
    }

    pub inline fn get(self: *const WorkerStats, c: Counter) u64 {
        return @atomicLoad(u64, &self.v[@intFromEnum(c)], .monotonic);
    }
};

pub fn sum(all: []const WorkerStats, c: Counter) u64 {
    var s: u64 = 0;
    for (all) |*w| s +%= w.get(c);
    return s;
}

test "counters" {
    var w: [2]WorkerStats = .{ .{}, .{} };
    w[0].inc(.downstream_rq_total);
    w[1].add(.downstream_rq_total, 4);
    try std.testing.expectEqual(@as(u64, 5), sum(&w, .downstream_rq_total));
}
