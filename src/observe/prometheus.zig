//! Prometheus text exposition of the summed per-worker counters.

const std = @import("std");
const stats = @import("stats.zig");

pub fn write(out: *std.ArrayList(u8), gpa: std.mem.Allocator, all: []const stats.WorkerStats) !void {
    const info = @typeInfo(stats.Counter).@"enum";
    inline for (info.field_names, info.field_values) |fname, value| {
        const c: stats.Counter = @enumFromInt(value);
        if (c == .snapshot_generation) continue;
        const kind = if (stats.isGauge(c)) "gauge" else "counter";
        const suffix = if (stats.isGauge(c) or comptime std.mem.endsWith(u8, fname, "_total")) "" else "_total";
        try out.print(gpa, "# TYPE likzik_{s}{s} {s}\nlikzik_{s}{s} {d}\n", .{ fname, suffix, kind, fname, suffix, stats.sum(all, c) });
    }
    try out.appendSlice(gpa, "# TYPE likzik_worker_snapshot_generation gauge\n");
    for (all, 0..) |*w, i| {
        try out.print(gpa, "likzik_worker_snapshot_generation{{worker=\"{d}\"}} {d}\n", .{ i, w.get(.snapshot_generation) });
    }
}

test "prometheus output" {
    var w: [1]stats.WorkerStats = .{.{}};
    w[0].add(.downstream_rq_total, 7);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try write(&out, std.testing.allocator, &w);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "likzik_downstream_rq_total 7\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "likzik_tcp_bytes_total 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "# TYPE likzik_downstream_cx_active gauge\n") != null);
}
