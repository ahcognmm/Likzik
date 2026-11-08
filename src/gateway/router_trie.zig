//! Route matching: a segment trie compiled per config snapshot.
//!
//! Priority at every level: static segment > `:param` > `*wildcard`, with
//! backtracking, so "/users/me" beats "/users/:id" beats "/users/*rest".
//! Routes that end on the same node are tried in config order; each must
//! also pass its host, method, header and query checks. Matching allocates
//! nothing: parameters are slices of the (normalized) path.
//!
//! Paths are normalized for matching only (see `normalize`): unreserved
//! percent-escapes are decoded, "." and ".." segments resolved and empty
//! segments dropped, so "/admin/../public" cannot be used to reach a route
//! by a path that only looks different.

const std = @import("std");

pub const max_params = 16;

pub const Param = struct { name: []const u8, value: []const u8 };

pub const Params = struct {
    items: [max_params]Param = undefined,
    len: usize = 0,

    pub fn get(self: *const Params, name: []const u8) ?[]const u8 {
        for (self.items[0..self.len]) |p| if (std.mem.eql(u8, p.name, name)) return p.value;
        return null;
    }
};

const Node = struct {
    statics: std.ArrayList(Edge) = .empty,
    param: ?*Node = null,
    param_name: []const u8 = "",
    wildcard_name: ?[]const u8 = null,
    /// Routes ending here.
    routes: std.ArrayList(u32) = .empty,
    /// Routes ending in a wildcard here.
    wildcard_routes: std.ArrayList(u32) = .empty,
};

const Edge = struct { seg: []const u8, node: *Node };

pub const Trie = struct {
    root: *Node,
    arena: std.mem.Allocator,

    pub fn init(arena: std.mem.Allocator) !Trie {
        const r = try arena.create(Node);
        r.* = .{};
        return .{ .root = r, .arena = arena };
    }

    pub const InsertError = error{ InvalidPath, ConflictingParam, OutOfMemory };

    pub fn insert(self: *Trie, path: []const u8, route: u32) InsertError!void {
        if (path.len == 0 or path[0] != '/') return error.InvalidPath;
        var node = self.root;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        while (it.next()) |seg| {
            if (seg[0] == '*') {
                if (it.peek() != null) return error.InvalidPath; // wildcard must be last
                const name = seg[1..];
                if (node.wildcard_name) |n| {
                    if (!std.mem.eql(u8, n, name)) return error.ConflictingParam;
                } else node.wildcard_name = name;
                try node.wildcard_routes.append(self.arena, route);
                return;
            }
            if (seg[0] == ':') {
                const name = seg[1..];
                if (name.len == 0) return error.InvalidPath;
                if (node.param) |p| {
                    if (!std.mem.eql(u8, node.param_name, name)) return error.ConflictingParam;
                    node = p;
                } else {
                    const n = try self.arena.create(Node);
                    n.* = .{};
                    node.param = n;
                    node.param_name = name;
                    node = n;
                }
                continue;
            }
            var next: ?*Node = null;
            for (node.statics.items) |e| if (std.mem.eql(u8, e.seg, seg)) {
                next = e.node;
            };
            if (next == null) {
                const n = try self.arena.create(Node);
                n.* = .{};
                try node.statics.append(self.arena, .{ .seg = seg, .node = n });
                next = n;
            }
            node = next.?;
        }
        try node.routes.append(self.arena, route);
    }

    /// Calls `accept(ctx, route, params)` on candidates in priority order
    /// and returns the first route it accepts.
    pub fn match(self: *const Trie, path: []const u8, params: *Params, ctx: anytype, comptime accept: fn (@TypeOf(ctx), u32, *const Params) bool) ?u32 {
        var segs: [64][]const u8 = undefined;
        var n: usize = 0;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        while (it.next()) |s| {
            if (n == segs.len) return null;
            segs[n] = s;
            n += 1;
        }
        params.len = 0;
        return walk(self.root, segs[0..n], path, params, ctx, accept);
    }

    fn walk(node: *const Node, segs: []const []const u8, path: []const u8, params: *Params, ctx: anytype, comptime accept: fn (@TypeOf(ctx), u32, *const Params) bool) ?u32 {
        if (segs.len == 0) {
            for (node.routes.items) |r| if (accept(ctx, r, params)) return r;
        } else {
            for (node.statics.items) |e| if (std.mem.eql(u8, e.seg, segs[0])) {
                if (walk(e.node, segs[1..], path, params, ctx, accept)) |r| return r;
            };
            if (node.param) |p| if (params.len < max_params) {
                params.items[params.len] = .{ .name = node.param_name, .value = segs[0] };
                params.len += 1;
                if (walk(p, segs[1..], path, params, ctx, accept)) |r| return r;
                params.len -= 1;
            };
        }
        if (node.wildcard_name) |name| if (params.len < max_params) {
            // The rest of the path from this segment on (may be empty).
            const rest = if (segs.len == 0) "" else blk: {
                const start = @intFromPtr(segs[0].ptr) - @intFromPtr(path.ptr);
                break :blk path[start..];
            };
            params.items[params.len] = .{ .name = name, .value = rest };
            params.len += 1;
            for (node.wildcard_routes.items) |r| if (accept(ctx, r, params)) return r;
            params.len -= 1;
        };
        return null;
    }
};

/// Path normalization is shared with core routing (likzik.http1.path).
pub const normalize = @import("likzik").http1.path.normalize;

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn acceptAll(_: void, _: u32, _: *const Params) bool {
    return true;
}

test "priority: static > param > wildcard, with backtracking" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var t = try Trie.init(arena.allocator());
    try t.insert("/users/me", 0);
    try t.insert("/users/:id", 1);
    try t.insert("/users/:id/orders/:order", 2);
    try t.insert("/users/*rest", 3);
    try t.insert("/", 4);
    try t.insert("/static/*file", 5);
    var p: Params = .{};
    try testing.expectEqual(@as(?u32, 0), t.match("/users/me", &p, {}, acceptAll));
    try testing.expectEqual(@as(?u32, 1), t.match("/users/42", &p, {}, acceptAll));
    try testing.expectEqualStrings("42", p.get("id").?);
    try testing.expectEqual(@as(?u32, 2), t.match("/users/42/orders/7", &p, {}, acceptAll));
    try testing.expectEqualStrings("7", p.get("order").?);
    try testing.expectEqual(@as(?u32, 3), t.match("/users/42/profile", &p, {}, acceptAll));
    try testing.expectEqualStrings("42/profile", p.get("rest").?);
    try testing.expectEqual(@as(?u32, 4), t.match("/", &p, {}, acceptAll));
    try testing.expectEqual(@as(?u32, 5), t.match("/static/css/a.css", &p, {}, acceptAll));
    try testing.expectEqualStrings("css/a.css", p.get("file").?);
    try testing.expectEqual(@as(?u32, 5), t.match("/static", &p, {}, acceptAll));
    try testing.expectEqual(@as(?u32, null), t.match("/nope", &p, {}, acceptAll));
}

fn rejectOne(_: void, r: u32, _: *const Params) bool {
    return r != 1;
}

test "rejected candidates fall back to the next priority" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var t = try Trie.init(arena.allocator());
    try t.insert("/a/:x", 1);
    try t.insert("/a/*rest", 2);
    var p: Params = .{};
    try testing.expectEqual(@as(?u32, 2), t.match("/a/b", &p, {}, rejectOne));
    try testing.expectEqual(@as(usize, 1), p.len);
}

test "insert errors" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var t = try Trie.init(arena.allocator());
    try testing.expectError(error.InvalidPath, t.insert("users", 0));
    try testing.expectError(error.InvalidPath, t.insert("/a/*x/b", 0));
    try t.insert("/u/:id", 0);
    try testing.expectError(error.ConflictingParam, t.insert("/u/:name/x", 1));
}

