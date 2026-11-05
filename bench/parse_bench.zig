//! Parser throughput on a set of realistic request heads.
//! `zig build bench-parse` (ReleaseFast).

const std = @import("std");
const likzik = @import("likzik");
const parser = likzik.http1.parser;
const rules = likzik.http1.rules;

const requests = [_][]const u8{
    "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
    "GET /api/v1/users/12345/orders?limit=50&offset=100 HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\nAccept: application/json, text/plain, */*\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\r\nCookie: session=abc123def456; theme=dark; _ga=GA1.2.123456789.1234567890\r\nReferer: https://example.com/dashboard\r\nX-Request-Id: 9f8e7d6c-5b4a-3c2d-1e0f-a9b8c7d6e5f4\r\nConnection: keep-alive\r\n\r\n",
    "POST /graphql HTTP/1.1\r\nHost: gw.example.com\r\nContent-Type: application/json\r\nContent-Length: 1234\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nX-Forwarded-For: 203.0.113.7\r\n\r\n",
};

pub fn main() !void {
    var hs: [parser.max_headers]parser.Header = undefined;
    const iters: usize = 2_000_000;
    var total_bytes: usize = 0;
    var sink: usize = 0;
    var t: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &t);
    const start = @as(u64, @intCast(t.sec)) * std.time.ns_per_s + @as(u64, @intCast(t.nsec));
    for (0..iters) |i| {
        const r = requests[i % requests.len];
        var sc: parser.HeadScanner = .{};
        const res = sc.feed(r).?;
        const req = try parser.parseRequest(r[res.start..res.end], &hs);
        const info = try rules.analyzeRequest(&req);
        sink +%= req.headers.len + @intFromBool(info.keep_alive);
        total_bytes += r.len;
    }
    _ = std.os.linux.clock_gettime(.MONOTONIC, &t);
    const end = @as(u64, @intCast(t.sec)) * std.time.ns_per_s + @as(u64, @intCast(t.nsec));
    const secs = @as(f64, @floatFromInt(end - start)) / std.time.ns_per_s;
    std.debug.print("parsed {d} requests in {d:.3}s: {d:.1} M req/s, {d:.2} GB/s (sink {d})\n", .{
        iters, secs, @as(f64, @floatFromInt(iters)) / secs / 1e6, @as(f64, @floatFromInt(total_bytes)) / secs / 1e9, sink,
    });
}
