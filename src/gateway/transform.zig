//! Templates for rewrites, redirects and header values.
//!
//! Placeholders: {name} for a path parameter, {consumer}, {client_ip},
//! {host} (without port), {path} (original path), {query} (original query
//! string, without '?'), {scheme}. Unknown placeholders are config errors,
//! caught when the snapshot is compiled.

const std = @import("std");
const Params = @import("router_trie.zig").Params;

pub const Vars = struct {
    params: *const Params,
    consumer: []const u8 = "",
    client_ip: []const u8 = "",
    host: []const u8 = "",
    path: []const u8 = "",
    query: []const u8 = "",
    scheme: []const u8 = "http",
};

const builtins = [_][]const u8{ "consumer", "client_ip", "host", "path", "query", "scheme" };

/// Checks a template against the parameter names a route path defines.
pub fn validate(tmpl: []const u8, param_names: []const []const u8) ?[]const u8 {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, tmpl, i, '{')) |open| {
        const close = std.mem.indexOfScalarPos(u8, tmpl, open, '}') orelse return "unclosed '{'";
        const name = tmpl[open + 1 .. close];
        var ok = false;
        for (builtins) |b| if (std.mem.eql(u8, b, name)) {
            ok = true;
        };
        for (param_names) |p| if (std.mem.eql(u8, p, name)) {
            ok = true;
        };
        if (!ok) return name;
        i = close + 1;
    }
    return null;
}

pub fn render(tmpl: []const u8, v: Vars, out: []u8) ?[]const u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i < tmpl.len) {
        if (tmpl[i] == '{') {
            const close = std.mem.indexOfScalarPos(u8, tmpl, i, '}') orelse return null;
            const name = tmpl[i + 1 .. close];
            const val: []const u8 = if (v.params.get(name)) |p| p else if (std.mem.eql(u8, name, "consumer")) v.consumer else if (std.mem.eql(u8, name, "client_ip")) v.client_ip else if (std.mem.eql(u8, name, "host")) v.host else if (std.mem.eql(u8, name, "path")) v.path else if (std.mem.eql(u8, name, "query")) v.query else if (std.mem.eql(u8, name, "scheme")) v.scheme else "";
            if (o + val.len > out.len) return null;
            @memcpy(out[o .. o + val.len], val);
            o += val.len;
            i = close + 1;
        } else {
            if (o == out.len) return null;
            out[o] = tmpl[i];
            o += 1;
            i += 1;
        }
    }
    return out[0..o];
}

/// True when a rendered header value is safe to send (no CR/LF/NUL).
pub fn safeHeaderValue(s: []const u8) bool {
    for (s) |c| if (c == '\r' or c == '\n' or c == 0) return false;
    return true;
}

test "render and validate" {
    var p: Params = .{};
    p.items[0] = .{ .name = "id", .value = "42" };
    p.len = 1;
    var buf: [128]u8 = undefined;
    const v: Vars = .{ .params = &p, .consumer = "alice", .host = "api.test", .path = "/old/42", .query = "a=1", .scheme = "https" };
    try std.testing.expectEqualStrings("/v2/users/42?a=1", render("/v2/users/{id}?{query}", v, &buf).?);
    try std.testing.expectEqualStrings("https://api.test/old/42", render("{scheme}://{host}{path}", v, &buf).?);
    try std.testing.expectEqualStrings("alice", render("{consumer}", v, &buf).?);
    try std.testing.expect(validate("/x/{id}/{consumer}", &.{"id"}) == null);
    try std.testing.expectEqualStrings("nope", validate("/x/{nope}", &.{"id"}).?);
    try std.testing.expect(!safeHeaderValue("a\r\nb"));
}
