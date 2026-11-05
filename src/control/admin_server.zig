//! Local admin endpoint (Envoy-style), served on the control thread.
//!
//!   GET  /ready        200 while serving, 503 while draining
//!   GET  /stats        counters, one "name: value" per line
//!   GET  /metrics      Prometheus text format
//!   GET  /server_info  JSON: build, config version, generation, reload status
//!   POST /reload       re-read the config file now
//!   POST /drain        graceful shutdown: stop accepting, finish in-flight
//!
//! It is meant to be bound to localhost or a private interface; there is
//! no authentication yet (an open question in the plan).

const std = @import("std");
const linux = std.os.linux;
const socket = @import("../net/socket.zig");
const stats = @import("../observe/stats.zig");
const prometheus = @import("../observe/prometheus.zig");
const Control = @import("thread.zig").Control;

const log = std.log.scoped(.admin);

pub fn serveOne(c: *Control, listen_fd: linux.fd_t) void {
    const rc = linux.accept4(listen_fd, null, null, linux.SOCK.CLOEXEC);
    const fd: linux.fd_t = @intCast(socket.check(rc) catch return);
    defer socket.closeFd(fd);
    // Bound how long a slow client can stall the control thread.
    const tv: linux.timeval = .{ .sec = 1, .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));

    var buf: [4096]u8 = undefined;
    var len: usize = 0;
    while (len < buf.len) {
        const n = socket.check(linux.read(fd, buf[len..].ptr, buf.len - len)) catch return;
        if (n == 0) break;
        len += n;
        if (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n") != null) break;
    }
    const line_end = std.mem.indexOf(u8, buf[0..len], "\r\n") orelse return;
    var it = std.mem.splitScalar(u8, buf[0..line_end], ' ');
    const method = it.next() orelse return;
    const target = it.next() orelse return;
    const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(c.gpa);
    var status: u16 = 200;
    var ctype: []const u8 = "text/plain";
    handle(c, method, path, &body, &status, &ctype) catch {
        status = 500;
        body.clearRetainingCapacity();
    };
    var head: [256]u8 = undefined;
    const h = std.fmt.bufPrint(&head, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, if (status == 200) "OK" else "Error", ctype, body.items.len }) catch return;
    writeAll(fd, h);
    writeAll(fd, body.items);
}

fn writeAll(fd: linux.fd_t, data: []const u8) void {
    var off: usize = 0;
    while (off < data.len) {
        const n = socket.check(linux.write(fd, data[off..].ptr, data.len - off)) catch return;
        off += n;
    }
}

fn handle(c: *Control, method: []const u8, path: []const u8, body: *std.ArrayList(u8), status: *u16, ctype: *[]const u8) !void {
    const gpa = c.gpa;
    const get = std.mem.eql(u8, method, "GET");
    const post = std.mem.eql(u8, method, "POST");
    if (get and std.mem.eql(u8, path, "/ready")) {
        if (c.draining) {
            status.* = 503;
            try body.appendSlice(gpa, "DRAINING\n");
        } else try body.appendSlice(gpa, "LIVE\n");
    } else if (get and std.mem.eql(u8, path, "/stats")) {
        inline for (@typeInfo(stats.Counter).@"enum".fields) |f| {
            try body.print(gpa, "{s}: {d}\n", .{ f.name, stats.sum(c.shared.stats, @enumFromInt(f.value)) });
        }
    } else if (get and std.mem.eql(u8, path, "/metrics")) {
        ctype.* = "text/plain; version=0.0.4";
        try prometheus.write(body, gpa, c.shared.stats);
    } else if (get and std.mem.eql(u8, path, "/server_info")) {
        ctype.* = "application/json";
        const snap = c.shared.rcu.load();
        try body.print(gpa,
            \\{{"name":"likzik","build":"{s}","state":"{s}","uptime_ms":{d},"workers":{d},
            \\"config":{{"version":"{s}","generation":{d},"reloads_ok":{d},"reloads_failed":{d},"last_error":"
        , .{ Control.buildVersion(), if (c.draining) "draining" else "live", c.uptimeMs(), c.shared.stats.len, c.version(), snap.generation, c.reloads_ok, c.reloads_failed });
        for (c.lastError()) |ch| switch (ch) {
            '"', '\\' => {
                try body.append(gpa, '\\');
                try body.append(gpa, ch);
            },
            0...0x1f => try body.append(gpa, ' '),
            else => try body.append(gpa, ch),
        };
        try body.appendSlice(gpa, "\"},\"worker_generations\":[");
        for (c.shared.stats, 0..) |*w, i| {
            try body.print(gpa, "{s}{d}", .{ if (i == 0) "" else ",", w.get(.snapshot_generation) });
        }
        try body.appendSlice(gpa, "]}\n");
    } else if (post and std.mem.eql(u8, path, "/reload")) {
        if (c.reload("admin")) {
            try body.print(gpa, "applied generation {d}\n", .{c.shared.rcu.load().generation});
        } else {
            status.* = 400;
            try body.print(gpa, "rejected: {s}\n", .{c.lastError()});
        }
    } else if (post and std.mem.eql(u8, path, "/drain")) {
        c.drain();
        try body.appendSlice(gpa, "draining\n");
    } else {
        status.* = 404;
        try body.appendSlice(gpa, "not found\n");
    }
}
