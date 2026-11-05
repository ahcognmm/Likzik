//! Immutable, compiled configuration. A Snapshot owns one arena; it is
//! built on the control thread, published through rcu.zig and read by
//! workers without locks.

const std = @import("std");
const model = @import("model.zig");
const validate_mod = @import("validate.zig");
const Address = @import("../net/addr.zig").Address;
const Method = @import("../http1/parser.zig").Method;

pub const Diag = validate_mod.Diag;

pub const Endpoint = struct {
    addr: Address,
    weight: u32,
    /// Stable across snapshots for the same address (see Registry).
    id: u32,
    text: []const u8,
};

pub const Cluster = struct {
    name: []const u8,
    /// Stable across snapshots for the same name.
    id: u32,
    lb: model.LbPolicy,
    connect_timeout_ms: u32,
    idle_timeout_ms: u32,
    max_idle_per_endpoint: u32,
    max_connect_attempts: u8,
    eject_after_failures: u8,
    eject_ms: u32,
    endpoints: []Endpoint,
    total_weight: u32,
};

pub const MatchKind = enum { prefix, exact };

pub const Route = struct {
    kind: MatchKind,
    path: []const u8,
    /// Bit per parser.Method; 0 = any method.
    methods: u16,
    cluster: *Cluster,
    prefix_rewrite: ?[]const u8,
    timeout_ms: u32,

    pub fn matches(self: *const Route, path: []const u8, method: Method) bool {
        if (self.methods != 0 and (self.methods & methodBit(method)) == 0) return false;
        return switch (self.kind) {
            .exact => std.mem.eql(u8, path, self.path),
            .prefix => std.mem.startsWith(u8, path, self.path),
        };
    }
};

pub fn methodBit(m: Method) u16 {
    return @as(u16, 1) << @intFromEnum(m);
}

pub const VirtualHost = struct {
    name: []const u8,
    exact: [][]const u8,
    /// Suffixes for "*.example.com" entries, stored as ".example.com".
    suffixes: [][]const u8,
    any: bool,
    routes: []Route,
};

pub const RouteTable = struct {
    name: []const u8,
    vhosts: []VirtualHost,

    pub fn findHost(self: *const RouteTable, host_header: []const u8) ?*const VirtualHost {
        const host = stripPort(host_header);
        var best_suffix: ?*const VirtualHost = null;
        var best_len: usize = 0;
        var fallback: ?*const VirtualHost = null;
        for (self.vhosts) |*vh| {
            for (vh.exact) |d| if (std.ascii.eqlIgnoreCase(d, host)) return vh;
            for (vh.suffixes) |s| {
                if (host.len > s.len and std.ascii.endsWithIgnoreCase(host, s) and s.len > best_len) {
                    best_suffix = vh;
                    best_len = s.len;
                }
            }
            if (vh.any and fallback == null) fallback = vh;
        }
        return best_suffix orelse fallback;
    }

    pub fn select(self: *const RouteTable, host: []const u8, path: []const u8, method: Method) ?*const Route {
        const vh = self.findHost(host) orelse return null;
        // Match against the path without the query string.
        const p = if (std.mem.indexOfScalar(u8, path, '?')) |q| path[0..q] else path;
        for (vh.routes) |*r| if (r.matches(p, method)) return r;
        return null;
    }
};

fn stripPort(h: []const u8) []const u8 {
    if (h.len > 0 and h[0] == '[') {
        const close = std.mem.indexOfScalar(u8, h, ']') orelse return h;
        return h[0 .. close + 1];
    }
    if (std.mem.lastIndexOfScalar(u8, h, ':')) |c| return h[0..c];
    return h;
}

pub const Listener = struct {
    name: []const u8,
    addr: Address,
    protocol: model.Protocol,
    routes: ?*RouteTable,
    cluster: ?*Cluster,
    trust_forwarded_headers: bool,
    idle_timeout_ms: u32,
};

pub const Snapshot = struct {
    arena: std.heap.ArenaAllocator,
    generation: u64 = 0,
    version: []const u8,
    workers: u16,
    limits: model.Limits,
    admin: ?Address,
    listeners: []Listener,
    route_tables: []RouteTable,
    clusters: []Cluster,

    pub fn destroy(self: *Snapshot) void {
        var a = self.arena;
        a.deinit();
    }

    pub fn findListener(self: *const Snapshot, name: []const u8) ?*const Listener {
        for (self.listeners) |*l| if (std.mem.eql(u8, l.name, name)) return l;
        return null;
    }
};

/// Hands out stable numeric ids for endpoints (by address) and clusters
/// (by name), so workers can keep per-endpoint state in flat arrays across
/// config generations. Owned by the control thread.
pub const Registry = struct {
    gpa: std.mem.Allocator,
    endpoints: std.StringHashMapUnmanaged(u32) = .empty,
    clusters: std.StringHashMapUnmanaged(u32) = .empty,

    pub fn init(gpa: std.mem.Allocator) Registry {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Registry) void {
        var it = self.endpoints.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        var it2 = self.clusters.keyIterator();
        while (it2.next()) |k| self.gpa.free(k.*);
        self.endpoints.deinit(self.gpa);
        self.clusters.deinit(self.gpa);
    }

    fn idFor(self: *Registry, map: *std.StringHashMapUnmanaged(u32), key: []const u8) !u32 {
        if (map.get(key)) |id| return id;
        const owned = try self.gpa.dupe(u8, key);
        errdefer self.gpa.free(owned);
        const id: u32 = map.count();
        try map.put(self.gpa, owned, id);
        return id;
    }

    pub fn endpointCount(self: *const Registry) u32 {
        return self.endpoints.count();
    }
    pub fn clusterCount(self: *const Registry) u32 {
        return self.clusters.count();
    }
};

/// Validates `cfg` and compiles it into a new Snapshot. `cfg` may be freed
/// afterwards; everything is copied into the snapshot's arena.
pub fn build(gpa: std.mem.Allocator, cfg: *const model.Config, reg: *Registry, diag: *Diag) !*Snapshot {
    try validate_mod.validate(cfg, diag);

    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const clusters = try a.alloc(Cluster, cfg.clusters.len);
    for (cfg.clusters, clusters) |src, *dst| {
        const eps = try a.alloc(Endpoint, src.endpoints.len);
        var total: u32 = 0;
        for (src.endpoints, eps) |e, *de| {
            var buf: [64]u8 = undefined;
            const addr = Address.parse(e.address) catch unreachable;
            const key = addr.format(&buf);
            de.* = .{ .addr = addr, .weight = e.weight, .id = try reg.idFor(&reg.endpoints, key), .text = try a.dupe(u8, key) };
            total += e.weight;
        }
        dst.* = .{
            .name = try a.dupe(u8, src.name),
            .id = try reg.idFor(&reg.clusters, src.name),
            .lb = src.lb_policy,
            .connect_timeout_ms = src.connect_timeout_ms,
            .idle_timeout_ms = src.idle_timeout_ms,
            .max_idle_per_endpoint = src.max_idle_per_endpoint,
            .max_connect_attempts = src.max_connect_attempts,
            .eject_after_failures = src.eject_after_failures,
            .eject_ms = src.eject_ms,
            .endpoints = eps,
            .total_weight = total,
        };
    }

    const findC = struct {
        fn f(cs: []Cluster, name: []const u8) *Cluster {
            for (cs) |*c| if (std.mem.eql(u8, c.name, name)) return c;
            unreachable; // validated
        }
    }.f;

    const tables = try a.alloc(RouteTable, cfg.route_configs.len);
    for (cfg.route_configs, tables) |src, *dst| {
        const vhs = try a.alloc(VirtualHost, src.virtual_hosts.len);
        for (src.virtual_hosts, vhs) |svh, *dvh| {
            var exact: std.ArrayList([]const u8) = .empty;
            var suffixes: std.ArrayList([]const u8) = .empty;
            var any = false;
            for (svh.domains) |d| {
                if (std.mem.eql(u8, d, "*")) {
                    any = true;
                } else if (d[0] == '*') {
                    try suffixes.append(a, try a.dupe(u8, d[1..]));
                } else {
                    try exact.append(a, try a.dupe(u8, d));
                }
            }
            const routes = try a.alloc(Route, svh.routes.len);
            for (svh.routes, routes) |sr, *drt| {
                var mask: u16 = 0;
                if (sr.match.methods) |ms| for (ms) |m| {
                    mask |= methodBit(Method.parse(m));
                };
                drt.* = .{
                    .kind = if (sr.match.prefix != null) .prefix else .exact,
                    .path = try a.dupe(u8, sr.match.prefix orelse sr.match.path.?),
                    .methods = mask,
                    .cluster = findC(clusters, sr.route.cluster),
                    .prefix_rewrite = if (sr.route.prefix_rewrite) |p| try a.dupe(u8, p) else null,
                    .timeout_ms = sr.route.timeout_ms,
                };
            }
            dvh.* = .{ .name = try a.dupe(u8, svh.name), .exact = exact.items, .suffixes = suffixes.items, .any = any, .routes = routes };
        }
        dst.* = .{ .name = try a.dupe(u8, src.name), .vhosts = vhs };
    }

    const listeners = try a.alloc(Listener, cfg.listeners.len);
    for (cfg.listeners, listeners) |src, *dst| {
        var rt: ?*RouteTable = null;
        if (src.route_config) |name| {
            for (tables) |*t| if (std.mem.eql(u8, t.name, name)) {
                rt = t;
            };
        }
        dst.* = .{
            .name = try a.dupe(u8, src.name),
            .addr = Address.parse(src.address) catch unreachable,
            .protocol = src.protocol,
            .routes = rt,
            .cluster = if (src.cluster) |c| findC(clusters, c) else null,
            .trust_forwarded_headers = src.trust_forwarded_headers,
            .idle_timeout_ms = src.idle_timeout_ms,
        };
    }

    const snap = try a.create(Snapshot);
    snap.* = .{
        .arena = undefined,
        .version = try a.dupe(u8, cfg.version),
        .workers = cfg.workers,
        .limits = cfg.limits,
        .admin = if (cfg.admin) |ad| Address.parse(ad.address) catch unreachable else null,
        .listeners = listeners,
        .route_tables = tables,
        .clusters = clusters,
    };
    // Move the arena into the snapshot last, after all allocations.
    snap.arena = arena;
    return snap;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn buildFrom(text: []const u8, reg: *Registry, diag: *Diag) !*Snapshot {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var d: [256]u8 = undefined;
    const cfg = try model.parseJson(arena.allocator(), text, &d);
    return build(testing.allocator, &cfg, reg, diag);
}

const sample =
    \\{"listeners":[{"name":"web","address":"127.0.0.1:8080","route_config":"main"},
    \\               {"name":"db","address":"127.0.0.1:5433","protocol":"tcp","cluster":"pg"}],
    \\ "route_configs":[{"name":"main","virtual_hosts":[
    \\   {"name":"api","domains":["api.example.com","*.api.example.com"],"routes":[
    \\      {"match":{"prefix":"/v1/","methods":["GET"]},"route":{"cluster":"api","prefix_rewrite":"/"}},
    \\      {"match":{"path":"/health"},"route":{"cluster":"api"}}]},
    \\   {"name":"default","domains":["*"],"routes":[{"match":{"prefix":"/"},"route":{"cluster":"web"}}]}]}],
    \\ "clusters":[
    \\   {"name":"api","endpoints":[{"address":"10.0.0.1:80"},{"address":"10.0.0.2:80","weight":3}]},
    \\   {"name":"web","lb_policy":"round_robin","endpoints":[{"address":"10.0.0.3:80"}]},
    \\   {"name":"pg","endpoints":[{"address":"10.0.0.4:5432"}]}]}
;

test "build and route" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var diag: Diag = .{};
    const s = try buildFrom(sample, &reg, &diag);
    defer s.destroy();
    const rt = s.listeners[0].routes.?;
    try testing.expectEqualStrings("api", rt.select("api.example.com", "/v1/users?x", .GET).?.cluster.name);
    try testing.expectEqualStrings("api", rt.select("API.example.com:8080", "/health", .POST).?.cluster.name);
    try testing.expectEqualStrings("api", rt.select("eu.api.example.com", "/health", .GET).?.cluster.name);
    try testing.expect(rt.select("api.example.com", "/v1/users", .POST) == null);
    try testing.expect(rt.select("api.example.com", "/healthz", .GET) == null);
    try testing.expectEqualStrings("web", rt.select("other.com", "/anything", .GET).?.cluster.name);
    try testing.expectEqual(@as(u32, 4), s.clusters[0].total_weight);
    try testing.expectEqualStrings("pg", s.listeners[1].cluster.?.name);
}

test "registry ids are stable across builds" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    var diag: Diag = .{};
    const s1 = try buildFrom(sample, &reg, &diag);
    defer s1.destroy();
    const s2 = try buildFrom(sample, &reg, &diag);
    defer s2.destroy();
    try testing.expectEqual(s1.clusters[0].endpoints[1].id, s2.clusters[0].endpoints[1].id);
    try testing.expectEqual(s1.clusters[2].id, s2.clusters[2].id);
    try testing.expectEqual(@as(u32, 4), reg.endpointCount());
}

test "validation errors" {
    var reg = Registry.init(testing.allocator);
    defer reg.deinit();
    const cases = [_]struct { cfg: []const u8, msg: []const u8 }{
        .{ .cfg = 
        \\{"listeners":[{"name":"a","address":"127.0.0.1:1","route_config":"nope"}]}
        , .msg = "unknown route_config" },
        .{ .cfg = 
        \\{"listeners":[{"name":"a","address":"127.0.0.1:1","protocol":"tcp","cluster":"c"}],"clusters":[{"name":"c","endpoints":[]}]}
        , .msg = "no endpoints" },
        .{ .cfg = 
        \\{"listeners":[{"name":"a","address":"127.0.0.1:1","protocol":"tcp","cluster":"c"},{"name":"b","address":"127.0.0.1:1","protocol":"tcp","cluster":"c"}],"clusters":[{"name":"c","endpoints":[{"address":"1.1.1.1:1"}]}]}
        , .msg = "share address" },
        .{ .cfg = 
        \\{"listeners":[{"name":"a","address":"bad","protocol":"tcp","cluster":"c"}],"clusters":[{"name":"c","endpoints":[{"address":"1.1.1.1:1"}]}]}
        , .msg = "invalid address" },
    };
    for (cases) |c| {
        var diag: Diag = .{};
        try testing.expectError(error.InvalidConfig, buildFrom(c.cfg, &reg, &diag));
        if (std.mem.indexOf(u8, diag.message(), c.msg) == null) {
            std.debug.print("got: {s}\n", .{diag.message()});
            return error.TestUnexpectedResult;
        }
    }
}
