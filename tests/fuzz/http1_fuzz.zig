//! Fuzz tests for the HTTP/1.1 parser.
//!
//!   zig build fuzz            runs every target once over its corpus
//!   zig build fuzz --fuzz     runs the coverage-guided fuzzer
//!
//! Properties checked:
//!   * no crash, no out-of-bounds slice, on any input;
//!   * the resumable head scanner gives the same answer however the
//!     input is split;
//!   * a parsed request re-serializes into a head that parses again to
//!     the same method, target and framing (round trip);
//!   * the chunked decoder consumes the same number of bytes and yields
//!     the same data whatever the feed size.

const std = @import("std");
const likzik = @import("likzik");
const parser = likzik.http1.parser;
const rules = likzik.http1.rules;
const codec = likzik.http1.codec;
const chunked = likzik.http1.chunked;

const corpus = [_][]const u8{
    "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
    "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc",
    "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n",
    "GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive, X-Y\r\nX-Y: 1\r\n\r\n",
    "\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
};

fn oneShot(buf: []const u8) ?parser.HeadScanner.Result {
    var s: parser.HeadScanner = .{};
    return s.feed(buf);
}

fn testParser(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [4096]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];
    const cut = if (input.len > 1) smith.indexWithHash(input.len, 0x51ce) else 0;
    try checkParser(input, cut);
}

fn checkParser(input: []const u8, cut: usize) anyerror!void {
    const whole = oneShot(input);
    // Split feeding must agree with one-shot feeding.
    if (input.len > 1) {
        var s: parser.HeadScanner = .{};
        var r = s.feed(input[0..cut]);
        if (r == null) r = s.feed(input);
        if (whole) |w| {
            const got = r orelse return error.ScannerDisagrees;
            if (got.end != w.end or got.start != w.start) {
                // Feeding a prefix may legitimately finish earlier only if
                // the prefix itself contains a complete head.
                if (oneShot(input[0..cut]) == null) return error.ScannerDisagrees;
            }
        } else if (r != null) return error.ScannerDisagrees;
    }

    const res = whole orelse return;
    var hs: [parser.max_headers]parser.Header = undefined;
    const req = parser.parseRequest(input[res.start..res.end], &hs) catch return;
    const info = rules.analyzeRequest(&req) catch return;

    // Round trip through the serializer.
    var out_buf: [16 * 1024]u8 = undefined;
    var out: codec.Out = .{ .buf = &out_buf };
    codec.writeRequest(&out, &req, &info, .{ .client_ip = "10.0.0.1", .proto = "http" }) catch return;
    var hs2: [parser.max_headers + 4]parser.Header = undefined;
    const r2 = oneShot(out.slice()) orelse return error.RoundTripNoHead;
    if (r2.end != out.len) return error.RoundTripLength;
    const req2 = try parser.parseRequest(out.slice(), &hs2);
    const info2 = try rules.analyzeRequest(&req2);
    if (!std.mem.eql(u8, req.method_raw, req2.method_raw)) return error.RoundTripMethod;
    if (!std.mem.eql(u8, req.target, req2.target)) return error.RoundTripTarget;
    if (std.meta.activeTag(info.framing) != std.meta.activeTag(info2.framing)) return error.RoundTripFraming;
}

test "fuzz request parser" {
    try std.testing.fuzz({}, testParser, .{ .corpus = &corpus });
}

fn decode(in: []const u8, piece: usize, out: []u8) struct { consumed: usize, len: usize, ok: bool, done: bool } {
    var d: chunked.Decoder = .{};
    var o: usize = 0;
    var off: usize = 0;
    while (off < in.len) {
        const end = @min(in.len, off + piece);
        var chunk = in[off..end];
        while (chunk.len > 0) {
            const s = d.step(chunk) catch return .{ .consumed = off, .len = o, .ok = false, .done = false };
            if (o + s.data_len <= out.len) @memcpy(out[o .. o + s.data_len], chunk[s.data_off..][0..s.data_len]);
            o += s.data_len;
            off += s.consumed;
            chunk = chunk[s.consumed..];
            if (s.done) return .{ .consumed = off, .len = o, .ok = true, .done = true };
        }
    }
    return .{ .consumed = off, .len = o, .ok = true, .done = false };
}

fn testChunked(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [2048]u8 = undefined;
    const input = buf[0..smith.slice(&buf)];
    try checkChunked(input, 1 + smith.indexWithHash(16, 0xc4c4));
}

fn checkChunked(input: []const u8, piece: usize) anyerror!void {
    var o1: [4096]u8 = undefined;
    var o2: [4096]u8 = undefined;
    const a = decode(input, input.len + 1, &o1);
    const b = decode(input, piece, &o2);
    if (a.ok != b.ok or a.done != b.done) return error.ChunkedDisagrees;
    if (a.ok and a.done) {
        if (a.consumed != b.consumed or a.len != b.len) return error.ChunkedDisagrees;
        if (!std.mem.eql(u8, o1[0..@min(a.len, o1.len)], o2[0..@min(b.len, o2.len)])) return error.ChunkedDisagrees;
    }
}

test "fuzz chunked decoder" {
    try std.testing.fuzz({}, testChunked, .{ .corpus = &.{ "3\r\nabc\r\n0\r\n\r\n", "1;a=b\r\nx\r\n0\r\nT: 1\r\n\r\n" } });
}

// Published request-smuggling patterns (from the PortSwigger and
// "HTTP Desync" research). Every one must be rejected outright.
test "smuggling corpus is rejected" {
    const attacks = [_][]const u8{
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: x\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\tchunked\r\nContent-Length: 4\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\n Transfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nX: X\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding\r\n : chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nContent-Length: 5\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 2\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \"chunked\"\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\rX: y\r\n\r\n",
        "GET / HTTP/1.1\r\nHo st: a\r\n\r\n",
        "GET /\x00 HTTP/1.1\r\nHost: a\r\n\r\n",
        "POST / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
    };
    for (attacks) |a| {
        var s: parser.HeadScanner = .{};
        const r = s.feed(a) orelse continue; // no complete head: never forwarded
        var hs: [parser.max_headers]parser.Header = undefined;
        const req = parser.parseRequest(a[r.start..r.end], &hs) catch continue;
        if (rules.analyzeRequest(&req)) |_| {
            std.debug.print("accepted smuggling attempt: {s}\n", .{a});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

// ---------------------------------------------------------------- mutation fuzzer
//
// Zig's coverage-guided fuzzer is not usable yet (0.16.0 does not compile
// it, 0.17.0 aborts with a corrupted coverage file), so this
// self-contained mutation fuzzer drives the same property checks. It runs
// a fixed number of iterations as part of `zig build test`; use
// `zig build fuzz -Dfuzz-iters=10000000` for longer runs.

const tokens = [_][]const u8{
    "\r\n", "\r\n\r\n", "\n", "\r", ":", " ", "\t", "chunked", "Transfer-Encoding", "Content-Length",
    "Host", "0", "1", "ffffffff", ";", ",", "\x00", "\x7f", "\xff", "HTTP/1.1", "HTTP/1.0", "GET", "POST", "/", "*",
    "Connection: close", "keep-alive", "Expect: 100-continue",
};

fn mutate(rng: std.Random, out: []u8, seed: []const u8) []u8 {
    var len = @min(seed.len, out.len);
    @memcpy(out[0..len], seed[0..len]);
    const n_mut = 1 + rng.uintLessThan(u8, 8);
    for (0..n_mut) |_| {
        switch (rng.uintLessThan(u8, 6)) {
            0 => if (len > 0) {
                out[rng.uintLessThan(usize, len)] ^= @as(u8, 1) << rng.int(u3);
            },
            1 => if (len > 0) {
                out[rng.uintLessThan(usize, len)] = rng.int(u8);
            },
            2 => if (len > 1) { // delete a range
                const at = rng.uintLessThan(usize, len);
                const n = @min(len - at, 1 + rng.uintLessThan(usize, 8));
                std.mem.copyForwards(u8, out[at .. len - n], out[at + n .. len]);
                len -= n;
            },
            3, 4 => { // insert a token
                const t = tokens[rng.uintLessThan(usize, tokens.len)];
                if (len + t.len <= out.len) {
                    const at = rng.uintLessThan(usize, len + 1);
                    std.mem.copyBackwards(u8, out[at + t.len .. len + t.len], out[at..len]);
                    @memcpy(out[at .. at + t.len], t);
                    len += t.len;
                }
            },
            else => if (len > 0) { // duplicate a range
                const at = rng.uintLessThan(usize, len);
                const n = @min(len - at, 1 + rng.uintLessThan(usize, 32));
                if (len + n <= out.len) {
                    std.mem.copyBackwards(u8, out[at + n .. len + n], out[at..len]);
                    len += n;
                }
            },
        }
    }
    return out[0..len];
}

fn fuzzIters() usize {
    return @import("fuzz_options").iterations;
}

test "mutation fuzz: parser and chunked decoder properties" {
    var prng = std.Random.DefaultPrng.init(0x11c2_2026);
    const rng = prng.random();
    var buf: [4096]u8 = undefined;
    const chunk_corpus = [_][]const u8{ "3\r\nabc\r\n0\r\n\r\n", "1;a=b\r\nx\r\n0\r\nT: 1\r\n\r\n", "10\r\n0123456789abcdef\r\n0\r\n\r\n" };
    const iters = fuzzIters();
    for (0..iters) |_| {
        const seed = corpus[rng.uintLessThan(usize, corpus.len)];
        const input = mutate(rng, &buf, seed);
        const cut = if (input.len > 1) rng.uintLessThan(usize, input.len) else 0;
        checkParser(input, cut) catch |e| {
            std.debug.print("parser property failed ({s}) on: {any}\n", .{ @errorName(e), input });
            return e;
        };
        const cs = chunk_corpus[rng.uintLessThan(usize, chunk_corpus.len)];
        const cin = mutate(rng, &buf, cs);
        checkChunked(cin, 1 + rng.uintLessThan(usize, 16)) catch |e| {
            std.debug.print("chunked property failed ({s}) on: {any}\n", .{ @errorName(e), cin });
            return e;
        };
    }
}
