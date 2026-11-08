//! The likzik API gateway: an extension (see core proxy/filter.zig) that
//! adds, per route: a radix-trie router with params and matchers, API-key
//! and JWT authentication, local rate limiting, request/response header
//! transforms, path rewrites, redirects and fixed responses.
//!
//! Per request (onRequest):
//!   1. match a gateway route (host, path, method, headers, query);
//!   2. authenticate (any of the route's api-key sets / JWT providers);
//!   3. apply rate limits;
//!   4. forward (cluster, rewrite, header edits), redirect, or respond.
//! Client-supplied copies of the identity headers the gateway sets (the
//! consumer header and claim headers) are always removed.

const std = @import("std");
const likzik = @import("likzik");
const filter = likzik.proxy.filter;
const parser = likzik.http1.parser;
const snapshot = likzik.config.snapshot;
const Diag = likzik.config.validate.Diag;
const file_watch = likzik.config.file_watch;

pub const config = @import("config.zig");
pub const router_trie = @import("router_trie.zig");
pub const jwt = @import("auth/jwt.zig");
pub const apikey = @import("auth/apikey.zig");
pub const ratelimit = @import("ratelimit/local.zig");
pub const transform = @import("transform.zig");

const Trie = router_trie.Trie;
const Params = router_trie.Params;
const Edit = filter.HeaderEdit;

// ---------------------------------------------------------------- compiled state

const HostPat = union(enum) { any, exact: []const u8, suffix: []const u8 };

const AuthRef = union(enum) { key: *const apikey.Set, jwt: *const jwt.Provider };

const LimitKey = union(enum) { client_ip, consumer, route, header: []const u8 };

const LimitDef = struct {
    name: []const u8,
    limit: ratelimit.Table.Limit,
    key: LimitKey,
};

const Action = union(enum) {
    cluster: *const snapshot.Cluster,
    redirect: struct { status: u16, location: []const u8 },
    respond: config.Respond,
};

const Route = struct {
    name: []const u8,
    hosts: []const HostPat,
    /// Bit per parser.Method; 0 = any.
    methods: u16,
    headers: []const config.HeaderMatch,
    query: []const config.QueryMatch,
    auth: []const AuthRef,
    auth_optional: bool,
    uses_jwt: bool,
    limits: []const u16,
    action: Action,
    rewrite: ?[]const u8,
    timeout_ms: u32,
    req_set: []const config.NameValue,
    req_add: []const config.NameValue,
    req_remove: []const []const u8,
    resp_add: []const Edit,
    resp_remove: []const []const u8,
};

const State = struct {
    listeners: ?[]const []const u8,
    fallthrough: bool,
    consumer_header: []const u8,
    key_sets: []apikey.Set,
    providers: []jwt.Provider,
    limits: []LimitDef,
    routes: []Route,
    trie: Trie,
    /// Headers clients may never supply (the gateway sets them).
    identity_headers: []const []const u8,
};

fn methodBit(m: parser.Method) u16 {
    return @as(u16, 1) << @intFromEnum(m);
}

fn findCluster(snap: *const snapshot.Snapshot, name: []const u8) ?*const snapshot.Cluster {
    for (snap.clusters) |*c| if (std.mem.eql(u8, c.name, name)) return c;
    return null;
}

fn compile(arena: std.mem.Allocator, value: std.json.Value, snap: *const snapshot.Snapshot, d: *Diag) anyerror!*anyopaque {
    const root = config.parse(arena, value) catch |e| return d.set("extensions.gateway: {s} (unknown or mistyped field?)", .{@errorName(e)});
    const g = root.gateway;
    const st = try arena.create(State);

    if (g.listeners) |ls| for (ls) |name| {
        if (snap.findListener(name) == null) return d.set("gateway: unknown listener '{s}'", .{name});
    };

    // API key sets.
    const sets = try arena.alloc(apikey.Set, g.api_keys.len);
    for (g.api_keys, sets) |src, *dst| {
        dst.* = .{ .name = src.name, .header = src.header, .query = src.query, .strip = src.strip, .keys = .empty };
        if (src.keys.len == 0) return d.set("gateway api_keys '{s}': no keys", .{src.name});
        for (src.keys) |k| {
            const h = if (k.sha256) |hex| apikey.parseHexHash(hex) orelse
                return d.set("gateway api_keys '{s}': sha256 for '{s}' must be 64 hex characters", .{ src.name, k.consumer }) else if (k.key) |plain| apikey.hashKey(plain) else return d.set("gateway api_keys '{s}': key for '{s}' needs 'sha256' or 'key'", .{ src.name, k.consumer });
            try dst.keys.put(arena, h, k.consumer);
        }
    }

    // JWT providers.
    const provs = try arena.alloc(jwt.Provider, g.jwt.len);
    var identity: std.ArrayList([]const u8) = .empty;
    try identity.append(arena, g.consumer_header);
    for (g.jwt, provs) |src, *dst| {
        var algs: jwt.AlgSet = .empty;
        if (src.algorithms.len == 0) return d.set("gateway jwt '{s}': 'algorithms' is required", .{src.name});
        for (src.algorithms) |a| algs.insert(jwt.parseAlg(a) orelse return d.set("gateway jwt '{s}': unsupported algorithm '{s}'", .{ src.name, a }));
        var keys: std.ArrayList(jwt.Key) = .empty;
        var why: []const u8 = "";
        if (src.jwks_file) |path| {
            const text = file_watch.readFile(arena, path) catch return d.set("gateway jwt '{s}': cannot read jwks_file '{s}'", .{ src.name, path });
            const doc = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch return d.set("gateway jwt '{s}': jwks_file is not valid JSON", .{src.name});
            jwt.loadJwks(arena, doc, &keys, &why) catch return d.set("gateway jwt '{s}': {s}", .{ src.name, why });
        }
        if (src.jwks) |doc| jwt.loadJwks(arena, doc, &keys, &why) catch return d.set("gateway jwt '{s}': {s}", .{ src.name, why });
        if (src.hs_secret) |sec| {
            if (sec.len < 32) return d.set("gateway jwt '{s}': hs_secret must be at least 32 bytes", .{src.name});
            try keys.append(arena, .{ .kid = null, .alg = null, .material = .{ .hmac = sec } });
        }
        if (keys.items.len == 0) return d.set("gateway jwt '{s}': no keys (jwks_file, jwks or hs_secret)", .{src.name});
        const claims = try arena.alloc(jwt.ClaimHeader, src.claims_to_headers.len);
        for (src.claims_to_headers, claims) |c, *o| {
            o.* = .{ .claim = c.claim, .header = c.header };
            try identity.append(arena, c.header);
        }
        dst.* = .{
            .name = src.name,
            .algs = algs,
            .issuer = src.issuer,
            .audiences = src.audiences,
            .keys = keys.items,
            .leeway_s = src.leeway_s,
            .require_exp = src.require_exp,
            .consumer_claim = src.consumer_claim,
            .claims_to_headers = claims,
            .header = src.header,
            .query = src.query,
            .forward_token = src.forward_token,
        };
    }
    // Names are shared between api key sets and jwt providers.
    for (g.api_keys, 0..) |a, i| {
        for (g.api_keys[0..i]) |b| if (std.mem.eql(u8, a.name, b.name)) return d.set("gateway: duplicate auth name '{s}'", .{a.name});
        for (g.jwt) |b| if (std.mem.eql(u8, a.name, b.name)) return d.set("gateway: duplicate auth name '{s}'", .{a.name});
    }

    // Rate limits.
    const limits = try arena.alloc(LimitDef, g.rate_limits.len);
    for (g.rate_limits, limits, 0..) |src, *dst, i| {
        for (g.rate_limits[0..i]) |b| if (std.mem.eql(u8, src.name, b.name)) return d.set("gateway: duplicate rate limit '{s}'", .{src.name});
        if (src.requests == 0) return d.set("gateway rate limit '{s}': requests must be > 0", .{src.name});
        const period: u64 = switch (src.per) {
            .second => 1000,
            .minute => 60_000,
            .hour => 3_600_000,
        };
        const key: LimitKey = if (std.mem.eql(u8, src.key, "client_ip")) .client_ip else if (std.mem.eql(u8, src.key, "consumer")) .consumer else if (std.mem.eql(u8, src.key, "route")) .route else if (std.mem.startsWith(u8, src.key, "header:") and src.key.len > 7) .{ .header = src.key[7..] } else return d.set("gateway rate limit '{s}': key must be client_ip, consumer, route or header:<name>", .{src.name});
        dst.* = .{ .name = src.name, .limit = .init(src.requests, period, src.burst orelse src.requests), .key = key };
    }

    // Routes.
    if (g.routes.len == 0) return d.set("gateway: no routes", .{});
    if (g.routes.len > 65535) return d.set("gateway: too many routes", .{});
    var trie = try Trie.init(arena);
    const routes = try arena.alloc(Route, g.routes.len);
    for (g.routes, routes, 0..) |src, *dst, ri| {
        for (g.routes[0..ri]) |b| if (std.mem.eql(u8, src.name, b.name)) return d.set("gateway: duplicate route name '{s}'", .{src.name});
        trie.insert(src.path, @intCast(ri)) catch |e| return d.set("gateway route '{s}': path '{s}': {s}", .{ src.name, src.path, @errorName(e) });

        var pnames: std.ArrayList([]const u8) = .empty;
        var pit = std.mem.tokenizeScalar(u8, src.path, '/');
        while (pit.next()) |seg| if (seg[0] == ':' or seg[0] == '*') try pnames.append(arena, seg[1..]);

        const hosts = try arena.alloc(HostPat, @max(src.hosts.len, 1));
        if (src.hosts.len == 0) hosts[0] = .any;
        for (src.hosts, 0..) |h, i| {
            hosts[i] = if (std.mem.eql(u8, h, "*")) .any else if (std.mem.startsWith(u8, h, "*.")) .{ .suffix = h[1..] } else .{ .exact = h };
        }

        var methods: u16 = 0;
        for (src.methods) |m| {
            const pm = parser.Method.parse(m);
            if (pm == .other) return d.set("gateway route '{s}': unknown method '{s}'", .{ src.name, m });
            methods |= methodBit(pm);
        }

        const auth = try arena.alloc(AuthRef, src.auth.len);
        var uses_jwt = false;
        for (src.auth, auth) |name, *o| {
            var found = false;
            for (sets) |*s| if (std.mem.eql(u8, s.name, name)) {
                o.* = .{ .key = s };
                found = true;
            };
            for (provs) |*p| if (std.mem.eql(u8, p.name, name)) {
                o.* = .{ .jwt = p };
                found = true;
                uses_jwt = true;
            };
            if (!found) return d.set("gateway route '{s}': unknown auth '{s}'", .{ src.name, name });
        }

        const lims = try arena.alloc(u16, src.rate_limits.len);
        for (src.rate_limits, lims) |name, *o| {
            var found = false;
            for (limits, 0..) |l, li| if (std.mem.eql(u8, l.name, name)) {
                o.* = @intCast(li);
                found = true;
            };
            if (!found) return d.set("gateway route '{s}': unknown rate limit '{s}'", .{ src.name, name });
        }

        const n_actions = @as(u8, @intFromBool(src.cluster != null)) + @intFromBool(src.redirect != null) + @intFromBool(src.respond != null);
        if (n_actions != 1) return d.set("gateway route '{s}': set exactly one of cluster, redirect, respond", .{src.name});
        var action: Action = undefined;
        if (src.cluster) |cn| {
            const cl = findCluster(snap, cn) orelse return d.set("gateway route '{s}': unknown cluster '{s}'", .{ src.name, cn });
            if (cl.proxy_protocol != null) return d.set("gateway route '{s}': cluster '{s}' sends PROXY protocol, which only tcp listeners support", .{ src.name, cn });
            action = .{ .cluster = cl };
        } else if (src.redirect) |r| {
            if (r.status != 301 and r.status != 302 and r.status != 303 and r.status != 307 and r.status != 308)
                return d.set("gateway route '{s}': redirect status must be 301, 302, 303, 307 or 308", .{src.name});
            if (transform.validate(r.location, pnames.items)) |bad| return d.set("gateway route '{s}': unknown placeholder '{{{s}}}' in redirect", .{ src.name, bad });
            action = .{ .redirect = .{ .status = r.status, .location = r.location } };
        } else {
            const r = src.respond.?;
            if (r.status < 200 or r.status > 599) return d.set("gateway route '{s}': respond status out of range", .{src.name});
            if (r.body.len > 8192) return d.set("gateway route '{s}': respond body larger than 8 KiB", .{src.name});
            action = .{ .respond = r };
        }
        if (src.rewrite) |rw| {
            if (rw.len == 0 or rw[0] != '/') return d.set("gateway route '{s}': rewrite must start with '/'", .{src.name});
            if (transform.validate(rw, pnames.items)) |bad| return d.set("gateway route '{s}': unknown placeholder '{{{s}}}' in rewrite", .{ src.name, bad });
        }
        for (src.request_headers.set) |h| if (transform.validate(h.value, pnames.items)) |bad| return d.set("gateway route '{s}': unknown placeholder '{{{s}}}' in header {s}", .{ src.name, bad, h.name });
        for (src.request_headers.add) |h| if (transform.validate(h.value, pnames.items)) |bad| return d.set("gateway route '{s}': unknown placeholder '{{{s}}}' in header {s}", .{ src.name, bad, h.name });

        // Request: "set" removes existing copies, then adds.
        const req_remove = try arena.alloc([]const u8, src.request_headers.remove.len + src.request_headers.set.len);
        @memcpy(req_remove[0..src.request_headers.remove.len], src.request_headers.remove);
        for (src.request_headers.set, req_remove[src.request_headers.remove.len..]) |h, *o| o.* = h.name;
        // Response: static values only.
        const resp_add = try arena.alloc(Edit, src.response_headers.set.len + src.response_headers.add.len);
        for (src.response_headers.set, resp_add[0..src.response_headers.set.len]) |h, *o| o.* = .{ .name = h.name, .value = h.value };
        for (src.response_headers.add, resp_add[src.response_headers.set.len..]) |h, *o| o.* = .{ .name = h.name, .value = h.value };
        const resp_remove = try arena.alloc([]const u8, src.response_headers.remove.len + src.response_headers.set.len);
        @memcpy(resp_remove[0..src.response_headers.remove.len], src.response_headers.remove);
        for (src.response_headers.set, resp_remove[src.response_headers.remove.len..]) |h, *o| o.* = h.name;

        dst.* = .{
            .name = src.name,
            .hosts = hosts,
            .methods = methods,
            .headers = src.headers,
            .query = src.query,
            .auth = auth,
            .auth_optional = src.auth_optional,
            .uses_jwt = uses_jwt,
            .limits = lims,
            .action = action,
            .rewrite = src.rewrite,
            .timeout_ms = src.timeout_ms,
            .req_set = src.request_headers.set,
            .req_add = src.request_headers.add,
            .req_remove = req_remove,
            .resp_add = resp_add,
            .resp_remove = resp_remove,
        };
    }

    st.* = .{
        .listeners = g.listeners,
        .fallthrough = g.fallthrough,
        .consumer_header = g.consumer_header,
        .key_sets = sets,
        .providers = provs,
        .limits = limits,
        .routes = routes,
        .trie = trie,
        .identity_headers = identity.items,
    };
    return st;
}

// ---------------------------------------------------------------- worker state

const Counter = enum { requests, no_route, auth_missing, auth_failed, rate_limited, redirects, responds };
const n_counters = @typeInfo(Counter).@"enum".field_names.len;

const WorkerState = struct {
    counters: [n_counters]u64 = @splat(0),
    scratch: [32 * 1024]u8 = undefined,
    path_buf: [8192]u8 = undefined,
    params: Params = .{},
    edits: [64]Edit = undefined,
    n_edits: usize = 0,
    removes: [64][]const u8 = undefined,
    n_removes: usize = 0,
    resp_headers: [4]Edit = undefined,
    table: *ratelimit.Table,
    jwt_cache: jwt.Cache = .{},

    fn inc(self: *WorkerState, c: Counter) void {
        const p = &self.counters[@intFromEnum(c)];
        @atomicStore(u64, p, @atomicLoad(u64, p, .monotonic) +% 1, .monotonic);
    }

    fn addEdit(self: *WorkerState, name: []const u8, value: []const u8) void {
        if (self.n_edits == self.edits.len) return;
        self.edits[self.n_edits] = .{ .name = name, .value = value };
        self.n_edits += 1;
    }

    fn addRemove(self: *WorkerState, name: []const u8) void {
        if (self.n_removes == self.removes.len) return;
        self.removes[self.n_removes] = name;
        self.n_removes += 1;
    }
};

// The rate-limit table is shared by all workers (see ratelimit/local.zig).
var shared_table: ?*ratelimit.Table = null;
var shared_refs: std.atomic.Value(u32) = .init(0);
var shared_lock: std.atomic.Value(u32) = .init(0);

fn lockShared() void {
    while (shared_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}

fn initWorker(gpa: std.mem.Allocator, _: u16, _: u16) anyerror!*anyopaque {
    lockShared();
    defer shared_lock.store(0, .release);
    if (shared_table == null) shared_table = try ratelimit.Table.init(gpa);
    _ = shared_refs.fetchAdd(1, .acq_rel);
    const ws = try gpa.create(WorkerState);
    ws.* = .{ .table = shared_table.? };
    return ws;
}

fn deinitWorker(gpa: std.mem.Allocator, p: *anyopaque) void {
    const ws: *WorkerState = @ptrCast(@alignCast(p));
    gpa.destroy(ws);
    lockShared();
    defer shared_lock.store(0, .release);
    if (shared_refs.fetchSub(1, .acq_rel) == 1) {
        if (shared_table) |t| t.deinit(gpa);
        shared_table = null;
    }
}

// ---------------------------------------------------------------- request path

fn headerValue(req: *const parser.Request, name: []const u8) ?[]const u8 {
    for (req.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

fn queryString(target: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return "";
    return target[q + 1 ..];
}

fn queryValue(target: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, queryString(target), '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=');
        const k = if (eq) |e| kv[0..e] else kv;
        if (std.mem.eql(u8, k, name)) return if (eq) |e| kv[e + 1 ..] else "";
    }
    return null;
}

/// The target with one query parameter removed (into `out`).
fn withoutQueryParam(target: []const u8, name: []const u8, out: []u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return target;
    if (q > out.len) return null;
    @memcpy(out[0..q], target[0..q]);
    var o = q;
    var first = true;
    var it = std.mem.splitScalar(u8, target[q + 1 ..], '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=');
        const k = if (eq) |e| kv[0..e] else kv;
        if (std.mem.eql(u8, k, name) or kv.len == 0) continue;
        if (o + 1 + kv.len > out.len) return null;
        out[o] = if (first) '?' else '&';
        @memcpy(out[o + 1 .. o + 1 + kv.len], kv);
        o += 1 + kv.len;
        first = false;
    }
    return out[0..o];
}

fn stripPort(h: []const u8) []const u8 {
    if (h.len > 0 and h[0] == '[') {
        const close = std.mem.indexOfScalar(u8, h, ']') orelse return h;
        return h[0 .. close + 1];
    }
    if (std.mem.lastIndexOfScalar(u8, h, ':')) |c| return h[0..c];
    return h;
}

const MatchCtx = struct {
    st: *const State,
    req: *const parser.Request,
    host: []const u8,
};

fn accept(m: MatchCtx, ri: u32, _: *const Params) bool {
    const r = &m.st.routes[ri];
    var host_ok = false;
    for (r.hosts) |hp| switch (hp) {
        .any => host_ok = true,
        .exact => |e| if (std.ascii.eqlIgnoreCase(e, m.host)) {
            host_ok = true;
        },
        .suffix => |s| if (m.host.len > s.len and std.ascii.endsWithIgnoreCase(m.host, s)) {
            host_ok = true;
        },
    };
    if (!host_ok) return false;
    if (r.methods != 0 and (r.methods & methodBit(m.req.method)) == 0) return false;
    for (r.headers) |hm| {
        const v = headerValue(m.req, hm.name);
        if (hm.present) |want| if ((v != null) != want) return false;
        if (hm.value) |want| if (v == null or !std.mem.eql(u8, v.?, want)) return false;
        if (hm.prefix) |want| if (v == null or !std.mem.startsWith(u8, v.?, want)) return false;
    }
    for (r.query) |qm| {
        const v = queryValue(m.req.target, qm.name);
        if (qm.present) |want| if ((v != null) != want) return false;
        if (qm.value) |want| if (v == null or !std.mem.eql(u8, v.?, want)) return false;
    }
    return true;
}

fn wallSeconds() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    return @intCast(ts.sec);
}

const json_401 = "{\"error\":\"unauthorized\"}\n";
const json_401_invalid = "{\"error\":\"invalid_credentials\"}\n";
const json_404 = "{\"error\":\"no_route\"}\n";
const json_429 = "{\"error\":\"rate_limited\"}\n";

fn deny(ws: *WorkerState, status: u16, body: []const u8, headers: []const Edit) filter.Decision {
    _ = ws;
    return .{ .respond = .{ .status = status, .body = body, .content_type = "application/json", .headers = headers } };
}

const AuthOutcome = union(enum) { anonymous, consumer: []const u8, missing, invalid };

fn authenticate(ws: *WorkerState, st: *const State, r: *const Route, ctx: *const filter.RequestCtx, fba: std.mem.Allocator, target: *[]const u8, target_buf: []u8) AuthOutcome {
    const req = ctx.req;
    for (r.auth) |ref| switch (ref) {
        .key => |set| {
            var key: ?[]const u8 = headerValue(req, set.header);
            var from_query = false;
            if (key == null) if (set.query) |qn| {
                key = queryValue(req.target, qn);
                from_query = key != null;
            };
            const k = key orelse continue;
            const consumer = set.lookup(k) orelse return .invalid;
            if (set.strip) {
                if (from_query) {
                    if (withoutQueryParam(target.*, set.query.?, target_buf)) |t| target.* = t;
                } else ws.addRemove(set.header);
            }
            return .{ .consumer = consumer };
        },
        .jwt => |p| {
            var tok: ?[]const u8 = null;
            var from_query = false;
            if (headerValue(req, p.header)) |v| {
                if (v.len > 7 and std.ascii.eqlIgnoreCase(v[0..7], "Bearer ")) tok = std.mem.trim(u8, v[7..], " ");
            }
            if (tok == null) if (p.query) |qn| {
                tok = queryValue(req.target, qn);
                from_query = tok != null;
            };
            const t = tok orelse continue;
            const now_s = wallSeconds();
            const scope: jwt.Cache.Scope = .{ .generation = ctx.snapshot.generation, .provider = @intCast((@intFromPtr(p) - @intFromPtr(st.providers.ptr)) / @sizeOf(jwt.Provider)) };
            switch (jwt.verifyCached(p, t, now_s, fba, &ws.jwt_cache, scope)) {
                .fail => return .invalid,
                .ok => |v| {
                    var nb: [32]u8 = undefined;
                    const consumer = if (v.claimString(p.consumer_claim, &nb)) |c| (fba.dupe(u8, c) catch "") else "";
                    for (p.claims_to_headers) |ch| {
                        if (v.claimString(ch.claim, &nb)) |val| {
                            const copy = fba.dupe(u8, val) catch continue;
                            if (@import("transform.zig").safeHeaderValue(copy)) ws.addEdit(ch.header, copy);
                        }
                    }
                    if (!p.forward_token) {
                        if (from_query) {
                            if (withoutQueryParam(target.*, p.query.?, target_buf)) |nt| target.* = nt;
                        } else ws.addRemove(p.header);
                    }
                    return .{ .consumer = consumer };
                },
            }
        },
    };
    return if (r.auth_optional) .anonymous else .missing;
}

fn onRequest(wsp: *anyopaque, stp: *anyopaque, ctx: *const filter.RequestCtx, out: *filter.RequestOut) filter.Decision {
    const ws: *WorkerState = @ptrCast(@alignCast(wsp));
    const st: *const State = @ptrCast(@alignCast(stp));
    if (st.listeners) |ls| {
        var mine = false;
        for (ls) |n| if (std.mem.eql(u8, n, ctx.listener.name)) {
            mine = true;
        };
        if (!mine) return .proceed;
    }
    ws.inc(.requests);
    ws.n_edits = 0;
    ws.n_removes = 0;
    var fba_state: std.heap.FixedBufferAllocator = .init(&ws.scratch);
    const fba = fba_state.allocator();

    const req = ctx.req;
    const npath = router_trie.normalize(req.target, &ws.path_buf) orelse
        return deny(ws, 414, "{\"error\":\"path_too_long\"}\n", &.{});
    const host = stripPort(ctx.host);
    const ri = st.trie.match(npath, &ws.params, MatchCtx{ .st = st, .req = req, .host = host }, accept) orelse {
        if (st.fallthrough) return .proceed;
        ws.inc(.no_route);
        return deny(ws, 404, json_404, &.{});
    };
    const r = &st.routes[ri];

    // Identity headers are the gateway's to set, never the client's.
    for (st.identity_headers) |h| ws.addRemove(h);

    var target: []const u8 = req.target;
    const target_buf = fba.alloc(u8, 8192) catch return deny(ws, 500, "", &.{});

    var consumer: []const u8 = "";
    if (r.auth.len > 0) {
        switch (authenticate(ws, st, r, ctx, fba, &target, target_buf)) {
            .anonymous => {},
            .consumer => |c| {
                consumer = c;
                ws.addEdit(st.consumer_header, c);
            },
            .missing => {
                ws.inc(.auth_missing);
                ws.resp_headers[0] = .{ .name = "WWW-Authenticate", .value = if (r.uses_jwt) "Bearer realm=\"likzik\"" else "ApiKey realm=\"likzik\"" };
                return deny(ws, 401, json_401, ws.resp_headers[0..1]);
            },
            .invalid => {
                ws.inc(.auth_failed);
                ws.resp_headers[0] = .{ .name = "WWW-Authenticate", .value = if (r.uses_jwt) "Bearer realm=\"likzik\", error=\"invalid_token\"" else "ApiKey realm=\"likzik\", error=\"invalid_key\"" };
                return deny(ws, 401, json_401_invalid, ws.resp_headers[0..1]);
            },
        }
    }

    for (r.limits) |li| {
        const ld = &st.limits[li];
        const part: []const u8 = switch (ld.key) {
            .client_ip => ctx.client_ip,
            .consumer => if (consumer.len > 0) consumer else ctx.client_ip,
            .route => r.name,
            .header => |hn| headerValue(req, hn) orelse ctx.client_ip,
        };
        const res = ws.table.take(ratelimit.keyHash(li, &.{ r.name, part }), ld.limit, ctx.now_ms);
        if (!res.allowed) {
            ws.inc(.rate_limited);
            const secs = (res.retry_after_ms + 999) / 1000;
            const ra = std.fmt.allocPrint(fba, "{d}", .{@max(secs, 1)}) catch "1";
            const lim = std.fmt.allocPrint(fba, "{d}", .{ld.limit.requests}) catch "";
            ws.resp_headers[0] = .{ .name = "Retry-After", .value = ra };
            ws.resp_headers[1] = .{ .name = "X-RateLimit-Limit", .value = lim };
            return deny(ws, 429, json_429, ws.resp_headers[0..2]);
        }
    }

    const vars: transform.Vars = .{
        .params = &ws.params,
        .consumer = consumer,
        .client_ip = ctx.client_ip,
        .host = host,
        .path = if (std.mem.indexOfScalar(u8, req.target, '?')) |q| req.target[0..q] else req.target,
        .query = queryString(req.target),
        .scheme = if (ctx.tls) "https" else "http",
    };

    switch (r.action) {
        .redirect => |rd| {
            ws.inc(.redirects);
            const buf = fba.alloc(u8, 4096) catch return deny(ws, 500, "", &.{});
            const loc = transform.render(rd.location, vars, buf) orelse return deny(ws, 500, "", &.{});
            if (!transform.safeHeaderValue(loc)) return deny(ws, 400, "", &.{});
            ws.resp_headers[0] = .{ .name = "Location", .value = loc };
            return .{ .respond = .{ .status = rd.status, .headers = ws.resp_headers[0..1] } };
        },
        .respond => |rs| {
            ws.inc(.responds);
            return .{ .respond = .{ .status = rs.status, .body = rs.body, .content_type = rs.content_type } };
        },
        .cluster => |c| {
            out.cluster = c;
            out.timeout_ms = r.timeout_ms;
        },
    }

    if (r.rewrite) |rw| {
        const buf = fba.alloc(u8, 8192) catch return deny(ws, 500, "", &.{});
        var t = transform.render(rw, vars, buf) orelse return deny(ws, 414, "", &.{});
        // Keep the (possibly stripped) query unless the template has one.
        const q = queryString(target);
        if (std.mem.indexOfScalar(u8, rw, '?') == null and q.len > 0) {
            if (t.len + 1 + q.len > buf.len) return deny(ws, 414, "", &.{});
            buf[t.len] = '?';
            @memcpy(buf[t.len + 1 .. t.len + 1 + q.len], q);
            t = buf[0 .. t.len + 1 + q.len];
        }
        target = t;
    }
    if (target.ptr != req.target.ptr or target.len != req.target.len) out.target = target;

    for (r.req_remove) |h| ws.addRemove(h);
    for (r.req_set) |h| {
        const buf = fba.alloc(u8, 1024) catch continue;
        const v = transform.render(h.value, vars, buf) orelse continue;
        if (transform.safeHeaderValue(v)) ws.addEdit(h.name, v);
    }
    for (r.req_add) |h| {
        const buf = fba.alloc(u8, 1024) catch continue;
        const v = transform.render(h.value, vars, buf) orelse continue;
        if (transform.safeHeaderValue(v)) ws.addEdit(h.name, v);
    }
    out.add = ws.edits[0..ws.n_edits];
    out.remove = ws.removes[0..ws.n_removes];
    out.token = @as(usize, ri) + 1;
    return .proceed;
}

fn onResponse(_: *anyopaque, stp: *anyopaque, ctx: *const filter.ResponseCtx, out: *filter.ResponseOut) void {
    const st: *const State = @ptrCast(@alignCast(stp));
    if (ctx.token == 0 or ctx.token > st.routes.len) return;
    const r = &st.routes[ctx.token - 1];
    out.add = r.resp_add;
    out.remove = r.resp_remove;
}

fn writeMetrics(out: *std.ArrayList(u8), gpa: std.mem.Allocator, states: []const ?*anyopaque) anyerror!void {
    const names = @typeInfo(Counter).@"enum".field_names;
    inline for (names, 0..) |name, i| {
        var total: u64 = 0;
        for (states) |s| if (s) |p| {
            const ws: *const WorkerState = @ptrCast(@alignCast(p));
            total +%= @atomicLoad(u64, &ws.counters[i], .monotonic);
        };
        try out.print(gpa, "# TYPE likzik_gateway_{s}_total counter\nlikzik_gateway_{s}_total {d}\n", .{ name, name, total });
    }
    var hits: u64 = 0;
    var misses: u64 = 0;
    for (states) |s| if (s) |p| {
        const ws: *const WorkerState = @ptrCast(@alignCast(p));
        hits +%= @atomicLoad(u64, &ws.jwt_cache.hits, .monotonic);
        misses +%= @atomicLoad(u64, &ws.jwt_cache.misses, .monotonic);
    };
    try out.print(gpa, "# TYPE likzik_gateway_jwt_cache_hits_total counter\nlikzik_gateway_jwt_cache_hits_total {d}\n# TYPE likzik_gateway_jwt_cache_misses_total counter\nlikzik_gateway_jwt_cache_misses_total {d}\n", .{ hits, misses });
}

pub const extension: filter.Extension = .{
    .name = "gateway",
    .compile = compile,
    .initWorker = initWorker,
    .deinitWorker = deinitWorker,
    .onRequest = onRequest,
    .onResponse = onResponse,
    .writeMetrics = writeMetrics,
};

test {
    _ = config;
    _ = router_trie;
    _ = jwt;
    _ = apikey;
    _ = ratelimit;
    _ = transform;
}
