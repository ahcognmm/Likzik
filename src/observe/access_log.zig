//! Access logs. Each worker formats one line per finished exchange into its
//! own single-producer/single-consumer byte ring; the control thread drains
//! all rings into the log file a few times per second. A full ring drops
//! the line (counted as `access_log_dropped`) instead of stalling a worker.

const std = @import("std");
const linux = std.os.linux;
const region = @import("../mem/region.zig");

pub const Format = enum { text, json };

/// Bytes per worker ring. Lazily committed: idle rings cost nothing.
pub const ring_bytes: usize = 4 << 20;

pub const Ring = struct {
    buf: []u8 = &.{},
    /// Total bytes written (producer) and consumed (consumer); the ring
    /// position is the value modulo buf.len (a power of two).
    head: std.atomic.Value(usize) = .init(0),
    tail: std.atomic.Value(usize) = .init(0),

    pub fn init(size: usize) !Ring {
        std.debug.assert(std.math.isPowerOfTwo(size));
        return .{ .buf = try region.alloc(u8, size) };
    }

    pub fn deinit(self: *Ring) void {
        if (self.buf.len > 0) region.free(u8, self.buf);
        self.buf = &.{};
    }

    /// Producer side. Returns false (and writes nothing) when full.
    pub fn write(self: *Ring, line: []const u8) bool {
        const h = self.head.raw;
        const t = self.tail.load(.acquire);
        if (line.len > self.buf.len - (h - t)) return false;
        const mask = self.buf.len - 1;
        const at = h & mask;
        const first = @min(line.len, self.buf.len - at);
        @memcpy(self.buf[at .. at + first], line[0..first]);
        @memcpy(self.buf[0 .. line.len - first], line[first..]);
        self.head.store(h + line.len, .release);
        return true;
    }

    /// Consumer side: writes everything buffered to `fd` (or discards it
    /// when fd < 0). Returns the bytes consumed.
    pub fn drain(self: *Ring, fd: linux.fd_t) usize {
        const h = self.head.load(.acquire);
        const t = self.tail.raw;
        if (h == t) return 0;
        if (fd >= 0) {
            const mask = self.buf.len - 1;
            const at = t & mask;
            const n = h - t;
            const first = @min(n, self.buf.len - at);
            writeAll(fd, self.buf[at .. at + first]);
            if (n > first) writeAll(fd, self.buf[0 .. n - first]);
        }
        self.tail.store(h, .release);
        return h - t;
    }
};

fn writeAll(fd: linux.fd_t, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => {},
            else => return, // disk full or similar: the lines are lost
        }
    }
}

/// Opens (creating, appending) the log file. Returns -1 on failure.
pub fn open(path: []const u8) linux.fd_t {
    var z: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len >= z.len) return -1;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const rc = linux.open(@ptrCast(&z), .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true }, 0o640);
    if (linux.errno(rc) != .SUCCESS) return -1;
    return @intCast(rc);
}

pub const Entry = struct {
    /// Wall-clock time the request started, in ms since the Unix epoch.
    time_ms: i64,
    client: []const u8,
    listener: []const u8,
    /// Empty when the request head could not be parsed.
    method: []const u8,
    target: []const u8,
    http10: bool,
    /// 0 when no response was sent (the client went away first).
    status: u16,
    bytes: u64,
    duration_ms: u64,
    cluster: []const u8,
    upstream: []const u8,
    tls: bool,
};

pub const max_line = 1024;

/// Formats one line (with the trailing newline) into `out`.
pub fn format(fmt: Format, e: *const Entry, out: *[max_line]u8) []const u8 {
    var w: Writer = .{ .buf = out };
    var ts: [24]u8 = undefined;
    const time = isoTime(e.time_ms, &ts);
    switch (fmt) {
        .text => {
            // 2026-11-08T17:40:00.123Z 10.0.0.1 web "GET /x HTTP/1.1" 200 1234 12ms api 10.0.0.2:80
            w.raw(time);
            w.raw(" ");
            w.raw(orDash(e.client));
            w.raw(" ");
            w.raw(e.listener);
            w.raw(" \"");
            if (e.method.len > 0) {
                w.raw(e.method);
                w.raw(" ");
                w.esc(e.target);
                w.raw(if (e.http10) " HTTP/1.0" else " HTTP/1.1");
            } else w.raw("-");
            w.raw("\" ");
            if (e.status == 0) w.raw("-") else w.num(e.status);
            w.raw(" ");
            w.num(e.bytes);
            w.raw(" ");
            w.num(e.duration_ms);
            w.raw("ms ");
            w.raw(orDash(e.cluster));
            w.raw(" ");
            w.raw(orDash(e.upstream));
        },
        .json => {
            w.raw("{\"time\":\"");
            w.raw(time);
            w.raw("\",\"client\":\"");
            w.esc(e.client);
            w.raw("\",\"listener\":\"");
            w.esc(e.listener);
            w.raw("\",\"tls\":");
            w.raw(if (e.tls) "true" else "false");
            w.raw(",\"method\":");
            w.strOrNull(e.method);
            w.raw(",\"target\":");
            w.strOrNull(if (e.method.len > 0) e.target else "");
            w.raw(",\"protocol\":\"");
            w.raw(if (e.http10) "HTTP/1.0" else "HTTP/1.1");
            w.raw("\",\"status\":");
            if (e.status == 0) w.raw("null") else w.num(e.status);
            w.raw(",\"bytes\":");
            w.num(e.bytes);
            w.raw(",\"duration_ms\":");
            w.num(e.duration_ms);
            w.raw(",\"cluster\":");
            w.strOrNull(e.cluster);
            w.raw(",\"upstream\":");
            w.strOrNull(e.upstream);
            w.raw("}");
        },
    }
    return w.finish();
}

fn orDash(s: []const u8) []const u8 {
    return if (s.len == 0) "-" else s;
}

/// Bounded writer: a line that would overflow is cut and still ends with
/// a newline (JSON lines are cut before the target grows that long, see
/// the target cap in proxy/http.zig).
const Writer = struct {
    buf: *[max_line]u8,
    len: usize = 0,

    fn raw(self: *Writer, s: []const u8) void {
        const n = @min(s.len, max_line - 1 - self.len);
        @memcpy(self.buf[self.len .. self.len + n], s[0..n]);
        self.len += n;
    }
    fn byte(self: *Writer, c: u8) void {
        if (self.len < max_line - 1) {
            self.buf[self.len] = c;
            self.len += 1;
        }
    }
    fn num(self: *Writer, v: u64) void {
        var b: [20]u8 = undefined;
        self.raw(std.fmt.bufPrint(&b, "{d}", .{v}) catch unreachable);
    }
    /// Escapes quotes, backslashes and control bytes (JSON-compatible).
    fn esc(self: *Writer, s: []const u8) void {
        for (s) |c| switch (c) {
            '"', '\\' => {
                self.byte('\\');
                self.byte(c);
            },
            0...0x1f, 0x7f => {
                const hex = "0123456789abcdef";
                self.raw("\\u00");
                self.byte(hex[c >> 4]);
                self.byte(hex[c & 15]);
            },
            else => self.byte(c),
        };
    }
    fn strOrNull(self: *Writer, s: []const u8) void {
        if (s.len == 0) return self.raw("null");
        self.byte('"');
        self.esc(s);
        self.byte('"');
    }
    fn finish(self: *Writer) []const u8 {
        self.buf[self.len] = '\n';
        return self.buf[0 .. self.len + 1];
    }
};

/// "2026-11-08T17:40:00.123Z"
fn isoTime(ms: i64, out: *[24]u8) []const u8 {
    const secs: u64 = @intCast(@divFloor(ms, 1000));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(out, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        day.year,                   md.month.numeric(),         md.day_index + 1,
        ds.getHoursIntoDay(),       ds.getMinutesIntoHour(),    ds.getSecondsIntoMinute(),
        @as(u64, @intCast(@mod(ms, 1000))),
    }) catch unreachable;
}

pub fn wallMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "ring wraps and refuses when full" {
    var r = try Ring.init(16);
    defer r.deinit();
    try testing.expect(r.write("0123456789"));
    try testing.expect(!r.write("0123456789")); // 10 + 10 > 16
    try testing.expectEqual(@as(usize, 10), r.drain(-1));
    try testing.expect(r.write("abcdefghij")); // wraps around the end
    var p: [2]linux.fd_t = undefined;
    try testing.expectEqual(@as(usize, 0), linux.pipe(&p));
    defer _ = linux.close(p[0]);
    defer _ = linux.close(p[1]);
    try testing.expectEqual(@as(usize, 10), r.drain(p[1]));
    var got: [16]u8 = undefined;
    const n = linux.read(p[0], &got, got.len);
    try testing.expectEqualStrings("abcdefghij", got[0..n]);
}

test "text and json lines" {
    const e: Entry = .{
        .time_ms = 1_794_159_600_123, // 2026-11-08T17:40:00.123Z
        .client = "10.0.0.1",
        .listener = "web",
        .method = "GET",
        .target = "/a\"b",
        .http10 = false,
        .status = 200,
        .bytes = 1234,
        .duration_ms = 12,
        .cluster = "api",
        .upstream = "10.0.0.2:80",
        .tls = true,
    };
    var buf: [max_line]u8 = undefined;
    try testing.expectEqualStrings(
        "2026-11-08T17:40:00.123Z 10.0.0.1 web \"GET /a\\\"b HTTP/1.1\" 200 1234 12ms api 10.0.0.2:80\n",
        format(.text, &e, &buf),
    );
    const j = format(.json, &e, &buf);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, j, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("/a\"b", parsed.value.object.get("target").?.string);
    try testing.expectEqual(@as(i64, 200), parsed.value.object.get("status").?.integer);

    var bad = e;
    bad.method = "";
    bad.status = 0;
    bad.cluster = "";
    bad.upstream = "";
    try testing.expectEqualStrings(
        "2026-11-08T17:40:00.123Z 10.0.0.1 web \"-\" - 1234 12ms - -\n",
        format(.text, &bad, &buf),
    );
}
