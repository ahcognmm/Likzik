//! Streaming, strictly validating chunked transfer-coding decoder.
//!
//! The proxy forwards chunked bodies byte-for-byte after validating them,
//! so the decoder's main job is to find exactly where the body ends. It also
//! reports data spans, which is used when de-chunking for HTTP/1.0 clients.
//!
//! Strict rules: chunk-size is 1..16 hex digits with no whitespace; chunk
//! extensions are capped in size and may not contain control bytes; lines
//! end in CRLF only; trailer section size is capped.

const std = @import("std");
const chars = @import("chars.zig");

pub const max_ext_len = 256;
pub const max_trailer_len = 4096;

pub const Error = error{BadChunk};

pub const Decoder = struct {
    state: State = .size_first,
    size: u64 = 0,
    digits: u8 = 0,
    ext_len: u16 = 0,
    trailer_len: u16 = 0,
    remaining: u64 = 0,

    const State = enum {
        size_first,
        size,
        ext,
        size_lf,
        data,
        data_cr,
        data_lf,
        trailer_line_start,
        trailer_line,
        trailer_cr_seen,
        final_lf,
        done,
    };

    pub const Step = struct {
        /// Bytes of input consumed in this step.
        consumed: usize,
        /// Data span inside the consumed input (offset, len). len may be 0.
        data_off: usize = 0,
        data_len: usize = 0,
        done: bool = false,
    };

    pub fn isDone(self: *const Decoder) bool {
        return self.state == .done;
    }

    /// Consumes input up to and including at most one data span. Call in a
    /// loop until all input is consumed or `done` is set.
    pub fn step(self: *Decoder, in: []const u8) Error!Step {
        var i: usize = 0;
        while (i < in.len) {
            const c = in[i];
            switch (self.state) {
                .size_first, .size => {
                    if (chars.isHex(c)) {
                        if (self.digits == 16) return error.BadChunk;
                        self.size = (self.size << 4) | chars.hexVal(c);
                        self.digits += 1;
                        self.state = .size;
                    } else if (self.state == .size_first) {
                        return error.BadChunk;
                    } else if (c == ';') {
                        self.ext_len = 0;
                        self.state = .ext;
                    } else if (c == '\r') {
                        self.state = .size_lf;
                    } else return error.BadChunk;
                    i += 1;
                },
                .ext => {
                    if (c == '\r') {
                        self.state = .size_lf;
                    } else {
                        if (!chars.isFieldValue(c)) return error.BadChunk;
                        self.ext_len += 1;
                        if (self.ext_len > max_ext_len) return error.BadChunk;
                    }
                    i += 1;
                },
                .size_lf => {
                    if (c != '\n') return error.BadChunk;
                    i += 1;
                    if (self.size == 0) {
                        self.state = .trailer_line_start;
                        self.trailer_len = 0;
                    } else {
                        self.remaining = self.size;
                        self.state = .data;
                    }
                },
                .data => {
                    const avail: u64 = in.len - i;
                    const n: usize = @intCast(@min(avail, self.remaining));
                    self.remaining -= n;
                    if (self.remaining == 0) self.state = .data_cr;
                    return .{ .consumed = i + n, .data_off = i, .data_len = n };
                },
                .data_cr => {
                    if (c != '\r') return error.BadChunk;
                    self.state = .data_lf;
                    i += 1;
                },
                .data_lf => {
                    if (c != '\n') return error.BadChunk;
                    self.size = 0;
                    self.digits = 0;
                    self.state = .size_first;
                    i += 1;
                },
                .trailer_line_start => {
                    if (c == '\r') {
                        self.state = .final_lf;
                    } else {
                        // A trailer field: name must start with a tchar.
                        if (!chars.isTchar(c)) return error.BadChunk;
                        self.state = .trailer_line;
                        try self.countTrailer();
                    }
                    i += 1;
                },
                .trailer_line => {
                    if (c == '\r') {
                        self.state = .trailer_cr_seen;
                    } else if (!chars.isFieldValue(c)) {
                        return error.BadChunk;
                    }
                    try self.countTrailer();
                    i += 1;
                },
                .trailer_cr_seen => {
                    if (c != '\n') return error.BadChunk;
                    self.state = .trailer_line_start;
                    try self.countTrailer();
                    i += 1;
                },
                .final_lf => {
                    if (c != '\n') return error.BadChunk;
                    self.state = .done;
                    return .{ .consumed = i + 1, .done = true };
                },
                .done => return .{ .consumed = i, .done = true },
            }
        }
        return .{ .consumed = i, .done = self.state == .done };
    }

    fn countTrailer(self: *Decoder) Error!void {
        self.trailer_len += 1;
        if (self.trailer_len > max_trailer_len) return error.BadChunk;
    }
};

const testing = std.testing;

/// Decodes everything, feeding the input in pieces of `piece` bytes.
fn decodeAll(in: []const u8, piece: usize, out: []u8) !struct { len: usize, consumed: usize } {
    var d: Decoder = .{};
    var o: usize = 0;
    var off: usize = 0;
    while (off < in.len) {
        const end = @min(in.len, off + piece);
        var chunk = in[off..end];
        var base = off;
        while (chunk.len > 0) {
            const s = try d.step(chunk);
            @memcpy(out[o .. o + s.data_len], chunk[s.data_off .. s.data_off + s.data_len]);
            o += s.data_len;
            base += s.consumed;
            chunk = chunk[s.consumed..];
            if (s.done) return .{ .len = o, .consumed = base };
        }
        off = end;
    }
    return error.Incomplete;
}

test "chunked decode, all piece sizes" {
    const body = "4\r\nWiki\r\n5;ext=1\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nX-T: 1\r\n\r\nNEXT";
    for (1..body.len) |p| {
        var out: [64]u8 = undefined;
        const r = try decodeAll(body, p, &out);
        try testing.expectEqualStrings("Wikipedia in\r\n\r\nchunks.", out[0..r.len]);
        try testing.expectEqual(body.len - 4, r.consumed);
    }
}

test "chunked rejects" {
    const bad = [_][]const u8{
        "\r\n",
        " 4\r\nWiki\r\n0\r\n\r\n",
        "4 \r\nWiki\r\n0\r\n\r\n",
        "4\nWiki\r\n0\r\n\r\n",
        "4\r\nWikiX\r\n0\r\n\r\n",
        "-1\r\n",
        "0x4\r\nWiki\r\n0\r\n\r\n",
        "11111111111111111\r\n",
        "4;a\x01b\r\nWiki\r\n0\r\n\r\n",
        "0\r\n:bad\r\n\r\n",
        "0\r\nX: a\rb\r\n\r\n",
    };
    for (bad) |b| {
        var out: [64]u8 = undefined;
        if (decodeAll(b, 3, &out)) |_| {
            std.debug.print("accepted: {any}\n", .{b});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "chunk extension cap" {
    var buf: [600]u8 = undefined;
    buf[0] = '1';
    buf[1] = ';';
    @memset(buf[2..400], 'a');
    @memcpy(buf[400..405], "\r\nx\r\n");
    var d: Decoder = .{};
    try testing.expectError(error.BadChunk, d.step(buf[0..405]));
}
