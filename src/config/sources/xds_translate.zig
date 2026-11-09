//! Translates xDS resources (Envoy v3 Cluster, ClusterLoadAssignment,
//! Listener, RouteConfiguration) into likzik's config JSON. The control
//! thread parses the result with the same model as the config file, so a
//! resource likzik cannot serve is rejected by the same validator, and its
//! message goes back to the control plane as a NACK.
//!
//! Unsupported features are errors, never silently dropped: a route with a
//! regex or header match, weighted clusters, DNS endpoints, more than one
//! filter chain, or a filter other than http_connection_manager/tcp_proxy.

const std = @import("std");
const c = @import("xds_c");
const Address = @import("../../net/addr.zig").Address;

pub const Kind = enum(u2) {
    cluster,
    endpoints,
    listener,
    route,

    pub fn typeUrl(k: Kind) [:0]const u8 {
        return switch (k) {
            .cluster => "type.googleapis.com/envoy.config.cluster.v3.Cluster",
            .endpoints => "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
            .listener => "type.googleapis.com/envoy.config.listener.v3.Listener",
            .route => "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
        };
    }

    pub fn fromTypeUrl(url: []const u8) ?Kind {
        inline for (std.meta.tags(Kind)) |k| if (std.mem.eql(u8, url, k.typeUrl())) return k;
        return null;
    }
};

const hcm_type = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager";
const tcp_proxy_type = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy";

/// Resource name -> serialized message, per kind.
pub const Map = std.StringArrayHashMapUnmanaged([]const u8);

pub const Diag = struct {
    buf: [512]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *Diag, comptime fmt: []const u8, args: anytype) error{Unsupported} {
        const out: []u8 = std.fmt.bufPrint(&self.buf, fmt, args) catch self.buf[0..];
        self.len = out.len;
        return error.Unsupported;
    }
    pub fn message(self: *const Diag) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Elements of a repeated protobuf-c field (null pointer when empty).
pub fn items(comptime T: type, ptr: [*c]T, n: usize) []T {
    if (n == 0 or ptr == null) return &.{};
    return ptr[0..n];
}

fn span(p: [*c]u8) []const u8 {
    if (p == null) return "";
    return std.mem.sliceTo(p, 0);
}

/// The name of a serialized resource, or null if it does not decode.
pub fn resourceName(gpa: std.mem.Allocator, kind: Kind, bytes: []const u8) ?[]u8 {
    const name: []const u8 = switch (kind) {
        .cluster => blk: {
            const m = c.likzik__xds__cluster__unpack(null, bytes.len, bytes.ptr) orelse return null;
            defer c.likzik__xds__cluster__free_unpacked(m, null);
            break :blk gpa.dupe(u8, span(m.*.name)) catch return null;
        },
        .endpoints => blk: {
            const m = c.likzik__xds__cluster_load_assignment__unpack(null, bytes.len, bytes.ptr) orelse return null;
            defer c.likzik__xds__cluster_load_assignment__free_unpacked(m, null);
            break :blk gpa.dupe(u8, span(m.*.cluster_name)) catch return null;
        },
        .listener => blk: {
            const m = c.likzik__xds__listener__unpack(null, bytes.len, bytes.ptr) orelse return null;
            defer c.likzik__xds__listener__free_unpacked(m, null);
            break :blk gpa.dupe(u8, span(m.*.name)) catch return null;
        },
        .route => blk: {
            const m = c.likzik__xds__route_configuration__unpack(null, bytes.len, bytes.ptr) orelse return null;
            defer c.likzik__xds__route_configuration__free_unpacked(m, null);
            break :blk gpa.dupe(u8, span(m.*.name)) catch return null;
        },
    };
    return @constCast(name);
}

// ---------------------------------------------------------------- JSON output

const Json = struct {
    out: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    fn raw(self: *Json, s: []const u8) !void {
        try self.out.appendSlice(self.gpa, s);
    }
    fn str(self: *Json, s: []const u8) !void {
        try self.out.append(self.gpa, '"');
        for (s) |ch| switch (ch) {
            '"' => try self.raw("\\\""),
            '\\' => try self.raw("\\\\"),
            0...0x1f => {
                var b: [6]u8 = undefined;
                try self.raw(std.fmt.bufPrint(&b, "\\u{x:0>4}", .{ch}) catch unreachable);
            },
            else => try self.out.append(self.gpa, ch),
        };
        try self.out.append(self.gpa, '"');
    }
    fn num(self: *Json, v: u64) !void {
        var b: [20]u8 = undefined;
        try self.raw(std.fmt.bufPrint(&b, "{d}", .{v}) catch unreachable);
    }
    fn key(self: *Json, k: []const u8) !void {
        try self.str(k);
        try self.out.append(self.gpa, ':');
    }
};

fn durationMs(d: ?*c.Likzik__Xds__Duration) ?u64 {
    const p = d orelse return null;
    if (p.*.seconds < 0 or p.*.nanos < 0) return 0;
    return @as(u64, @intCast(p.*.seconds)) * 1000 + @as(u64, @intCast(p.*.nanos)) / std.time.ns_per_ms;
}

/// "ip:port" for an IP socket address (DNS names are not supported).
fn addressText(a: ?*c.Likzik__Xds__Address, buf: []u8, what: []const u8, d: *Diag) ![]const u8 {
    const sa = (a orelse return d.set("{s}: missing address", .{what})).*.socket_address orelse
        return d.set("{s}: only socket addresses are supported", .{what});
    if (sa.*.protocol != 0) return d.set("{s}: only TCP addresses are supported", .{what});
    const host = span(sa.*.address);
    const text = (if (std.mem.indexOfScalar(u8, host, ':') != null)
        std.fmt.bufPrint(buf, "[{s}]:{d}", .{ host, sa.*.port_value })
    else
        std.fmt.bufPrint(buf, "{s}:{d}", .{ host, sa.*.port_value })) catch return d.set("{s}: address too long", .{what});
    _ = Address.parse(text) catch return d.set("{s}: '{s}' is not an IP address (DNS names are not supported)", .{ what, host });
    return text;
}

fn endpointsJson(j: *Json, cla: *c.Likzik__Xds__ClusterLoadAssignment, d: *Diag) !void {
    try j.raw("[");
    var first = true;
    for (items(@TypeOf(cla.endpoints[0]), cla.endpoints, cla.n_endpoints)) |loc| {
        // Only priority 0 is used (no failover between priorities yet).
        if (loc.*.priority != 0) continue;
        for (items(@TypeOf(loc.*.lb_endpoints[0]), loc.*.lb_endpoints, loc.*.n_lb_endpoints)) |le| {
            switch (le.*.health_status) {
                2, 3, 4 => continue, // UNHEALTHY, DRAINING, TIMEOUT
                else => {},
            }
            const ep = le.*.endpoint orelse continue;
            var buf: [96]u8 = undefined;
            const addr = try addressText(ep.*.address, &buf, span(cla.cluster_name), d);
            const weight: u64 = if (le.*.load_balancing_weight) |wv| wv.*.value else 1;
            if (weight == 0) continue;
            if (!first) try j.raw(",");
            first = false;
            try j.raw("{");
            try j.key("address");
            try j.str(addr);
            try j.raw(",");
            try j.key("weight");
            try j.num(weight);
            try j.raw("}");
        }
    }
    try j.raw("]");
}

fn clusterJson(j: *Json, gpa: std.mem.Allocator, bytes: []const u8, eds: *const Map, d: *Diag) !void {
    const m = c.likzik__xds__cluster__unpack(null, bytes.len, bytes.ptr) orelse return d.set("a cluster does not decode", .{});
    defer c.likzik__xds__cluster__free_unpacked(m, null);
    const name = span(m.*.name);
    try j.raw("{");
    try j.key("name");
    try j.str(name);
    try j.raw(",");
    try j.key("lb_policy");
    try j.str(switch (m.*.lb_policy) {
        0 => "round_robin",
        1 => "least_request",
        3 => "random",
        else => return d.set("cluster '{s}': lb_policy {d} is not supported (use ROUND_ROBIN, LEAST_REQUEST or RANDOM)", .{ name, m.*.lb_policy }),
    });
    if (durationMs(m.*.connect_timeout)) |ms| {
        try j.raw(",");
        try j.key("connect_timeout_ms");
        try j.num(@max(ms, 1));
    }
    try j.raw(",");
    try j.key("endpoints");
    switch (m.*.type) {
        0, 1, 2 => { // STATIC (STRICT/LOGICAL_DNS accepted only with IP addresses)
            const cla = m.*.load_assignment orelse return d.set("cluster '{s}': no load_assignment", .{name});
            try endpointsJson(j, cla, d);
        },
        3 => { // EDS
            const svc = span(if (m.*.eds_cluster_config) |e| e.*.service_name else null);
            const key = if (svc.len > 0) svc else name;
            if (eds.get(key)) |cla_bytes| {
                const cla = c.likzik__xds__cluster_load_assignment__unpack(null, cla_bytes.len, cla_bytes.ptr) orelse
                    return d.set("endpoints for '{s}' do not decode", .{key});
                defer c.likzik__xds__cluster_load_assignment__free_unpacked(cla, null);
                try endpointsJson(j, cla, d);
            } else try j.raw("[]"); // endpoints not received yet: 503 until they arrive
        },
        else => return d.set("cluster '{s}': discovery type {d} is not supported", .{ name, m.*.type }),
    }
    try j.raw("}");
    _ = gpa;
}

fn routeConfigJson(j: *Json, rc: *c.Likzik__Xds__RouteConfiguration, name: []const u8, d: *Diag) !void {
    try j.raw("{");
    try j.key("name");
    try j.str(name);
    try j.raw(",");
    try j.key("virtual_hosts");
    try j.raw("[");
    for (items(@TypeOf(rc.virtual_hosts[0]), rc.virtual_hosts, rc.n_virtual_hosts), 0..) |vh, vi| {
        if (vi > 0) try j.raw(",");
        const vname = span(vh.*.name);
        try j.raw("{");
        try j.key("name");
        try j.str(vname);
        try j.raw(",");
        try j.key("domains");
        try j.raw("[");
        for (items(@TypeOf(vh.*.domains[0]), vh.*.domains, vh.*.n_domains), 0..) |dom, di| {
            if (di > 0) try j.raw(",");
            try j.str(span(dom));
        }
        try j.raw("],");
        try j.key("routes");
        try j.raw("[");
        for (items(@TypeOf(vh.*.routes[0]), vh.*.routes, vh.*.n_routes), 0..) |r, ri| {
            if (ri > 0) try j.raw(",");
            const m = r.*.match orelse return d.set("route config '{s}', virtual host '{s}': route {d} has no match", .{ name, vname, ri });
            if (m.*.n_headers > 0 or m.*.safe_regex != null or span(m.*.path_separated_prefix).len > 0)
                return d.set("route config '{s}', virtual host '{s}': route {d} uses a header, regex or path_separated_prefix match (only prefix and path are supported)", .{ name, vname, ri });
            const a = r.*.route orelse return d.set("route config '{s}', virtual host '{s}': route {d} is not a cluster route (redirects and direct responses are not supported)", .{ name, vname, ri });
            if (a.*.weighted_clusters != null) return d.set("route config '{s}', virtual host '{s}': route {d} uses weighted_clusters (not supported)", .{ name, vname, ri });
            try j.raw("{");
            try j.key("match");
            try j.raw("{");
            const path = span(m.*.path);
            if (path.len > 0) {
                try j.key("path");
                try j.str(path);
            } else {
                try j.key("prefix");
                const p = span(m.*.prefix);
                try j.str(if (p.len == 0) "/" else p);
            }
            try j.raw("},");
            try j.key("route");
            try j.raw("{");
            try j.key("cluster");
            try j.str(span(a.*.cluster));
            const rw = span(a.*.prefix_rewrite);
            if (rw.len > 0) {
                try j.raw(",");
                try j.key("prefix_rewrite");
                try j.str(rw);
            }
            // Envoy: 15 s by default, 0 disables the timeout (capped at 1 h here).
            const t = durationMs(a.*.timeout) orelse 15_000;
            try j.raw(",");
            try j.key("timeout_ms");
            try j.num(if (t == 0) 3_600_000 else t);
            try j.raw("}}");
        }
        try j.raw("]}");
    }
    try j.raw("]}");
}

/// Builds `{"listeners":[...],"route_configs":[...],"clusters":[...]}`.
/// Listeners whose route configuration has not arrived yet are left out
/// (they start once RDS delivers it), like Envoy's listener warming.
pub fn buildFragment(gpa: std.mem.Allocator, res: *const [4]Map, d: *Diag) ![]u8 {
    var j: Json = .{ .gpa = gpa };
    errdefer j.out.deinit(gpa);
    var inline_routes: Json = .{ .gpa = gpa };
    defer inline_routes.out.deinit(gpa);

    try j.raw("{");
    try j.key("listeners");
    try j.raw("[");
    var first = true;
    for (res[@intFromEnum(Kind.listener)].values()) |bytes| {
        const l = c.likzik__xds__listener__unpack(null, bytes.len, bytes.ptr) orelse return d.set("a listener does not decode", .{});
        defer c.likzik__xds__listener__free_unpacked(l, null);
        const name = span(l.*.name);
        if (l.*.n_filter_chains != 1) return d.set("listener '{s}': exactly one filter chain is supported (got {d})", .{ name, l.*.n_filter_chains });
        var buf: [96]u8 = undefined;
        const addr = try addressText(l.*.address, &buf, name, d);
        const chain = l.*.filter_chains[0];
        var entry: Json = .{ .gpa = gpa };
        defer entry.out.deinit(gpa);
        var ready = false;
        for (items(@TypeOf(chain.*.filters[0]), chain.*.filters, chain.*.n_filters)) |f| {
            const tc = f.*.typed_config orelse continue;
            const turl = span(tc.*.type_url);
            const v = tc.*.value;
            if (std.mem.eql(u8, turl, hcm_type)) {
                const h = c.likzik__xds__http_connection_manager__unpack(null, v.len, v.data) orelse return d.set("listener '{s}': http_connection_manager does not decode", .{name});
                defer c.likzik__xds__http_connection_manager__free_unpacked(h, null);
                try entry.raw(",");
                try entry.key("route_config");
                if (h.*.rds) |rds| {
                    const rname = span(rds.*.route_config_name);
                    if (!res[@intFromEnum(Kind.route)].contains(rname)) break; // warming: RDS pending
                    try entry.str(rname);
                } else if (h.*.route_config) |rc| {
                    var nb: [160]u8 = undefined;
                    const rname = std.fmt.bufPrint(&nb, "listener:{s}", .{name}) catch return d.set("listener name too long", .{});
                    try entry.str(rname);
                    if (inline_routes.out.items.len > 0) try inline_routes.raw(",");
                    try routeConfigJson(&inline_routes, rc, rname, d);
                } else return d.set("listener '{s}': http_connection_manager needs rds or route_config", .{name});
                ready = true;
                break;
            } else if (std.mem.eql(u8, turl, tcp_proxy_type)) {
                const t = c.likzik__xds__tcp_proxy__unpack(null, v.len, v.data) orelse return d.set("listener '{s}': tcp_proxy does not decode", .{name});
                defer c.likzik__xds__tcp_proxy__free_unpacked(t, null);
                const cl = span(t.*.cluster);
                if (cl.len == 0) return d.set("listener '{s}': tcp_proxy needs a cluster (weighted clusters are not supported)", .{name});
                try entry.raw(",");
                try entry.key("protocol");
                try entry.str("tcp");
                try entry.raw(",");
                try entry.key("cluster");
                try entry.str(cl);
                ready = true;
                break;
            } else return d.set("listener '{s}': filter '{s}' is not supported (use http_connection_manager or tcp_proxy)", .{ name, span(f.*.name) });
        }
        if (!ready) continue;
        if (!first) try j.raw(",");
        first = false;
        try j.raw("{");
        try j.key("name");
        try j.str(name);
        try j.raw(",");
        try j.key("address");
        try j.str(addr);
        try j.raw(entry.out.items);
        try j.raw("}");
    }
    try j.raw("],");
    try j.key("route_configs");
    try j.raw("[");
    first = true;
    for (res[@intFromEnum(Kind.route)].keys(), res[@intFromEnum(Kind.route)].values()) |name, bytes| {
        const rc = c.likzik__xds__route_configuration__unpack(null, bytes.len, bytes.ptr) orelse return d.set("route config '{s}' does not decode", .{name});
        defer c.likzik__xds__route_configuration__free_unpacked(rc, null);
        if (!first) try j.raw(",");
        first = false;
        try routeConfigJson(&j, rc, name, d);
    }
    if (inline_routes.out.items.len > 0) {
        if (!first) try j.raw(",");
        try j.raw(inline_routes.out.items);
    }
    try j.raw("],");
    try j.key("clusters");
    try j.raw("[");
    first = true;
    for (res[@intFromEnum(Kind.cluster)].values()) |bytes| {
        if (!first) try j.raw(",");
        first = false;
        try clusterJson(&j, gpa, bytes, &res[@intFromEnum(Kind.endpoints)], d);
    }
    try j.raw("]}");
    return j.out.toOwnedSlice(gpa);
}

/// Names to request over EDS: one per EDS cluster (service_name or name).
pub fn edsNames(gpa: std.mem.Allocator, clusters: *const Map) !std.ArrayList([]const u8) {
    var out: std.ArrayList([]const u8) = .empty;
    for (clusters.values()) |bytes| {
        const m = c.likzik__xds__cluster__unpack(null, bytes.len, bytes.ptr) orelse continue;
        defer c.likzik__xds__cluster__free_unpacked(m, null);
        if (m.*.type != 3) continue;
        const svc = span(if (m.*.eds_cluster_config) |e| e.*.service_name else null);
        try out.append(gpa, try gpa.dupe(u8, if (svc.len > 0) svc else span(m.*.name)));
    }
    return out;
}

/// Names to request over RDS: the route configs listeners refer to.
pub fn rdsNames(gpa: std.mem.Allocator, listeners: *const Map) !std.ArrayList([]const u8) {
    var out: std.ArrayList([]const u8) = .empty;
    for (listeners.values()) |bytes| {
        const l = c.likzik__xds__listener__unpack(null, bytes.len, bytes.ptr) orelse continue;
        defer c.likzik__xds__listener__free_unpacked(l, null);
        for (items(@TypeOf(l.*.filter_chains[0]), l.*.filter_chains, l.*.n_filter_chains)) |chain| for (items(@TypeOf(chain.*.filters[0]), chain.*.filters, chain.*.n_filters)) |f| {
            const tc = f.*.typed_config orelse continue;
            if (!std.mem.eql(u8, span(tc.*.type_url), hcm_type)) continue;
            const h = c.likzik__xds__http_connection_manager__unpack(null, tc.*.value.len, tc.*.value.data) orelse continue;
            defer c.likzik__xds__http_connection_manager__free_unpacked(h, null);
            if (h.*.rds) |rds| try out.append(gpa, try gpa.dupe(u8, span(rds.*.route_config_name)));
        };
    }
    return out;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn pack(gpa: std.mem.Allocator, msg: anytype, comptime size_fn: anytype, comptime pack_fn: anytype) ![]u8 {
    const buf = try gpa.alloc(u8, size_fn(msg));
    _ = pack_fn(msg, buf.ptr);
    return buf;
}

test "clusters translate to the config model, EDS clusters wait for endpoints" {
    const gpa = testing.allocator;
    var res: [4]Map = .{ .empty, .empty, .empty, .empty };
    defer for (&res) |*m| {
        for (m.values()) |v| gpa.free(v);
        m.deinit(gpa);
    };

    // STATIC cluster with one endpoint, RANDOM, 1.5 s connect timeout.
    var sa: c.Likzik__Xds__SocketAddress = undefined;
    c.likzik__xds__socket_address__init(&sa);
    sa.address = @constCast("10.0.0.1");
    sa.port_value = 8080;
    var addr: c.Likzik__Xds__Address = undefined;
    c.likzik__xds__address__init(&addr);
    addr.socket_address = &sa;
    var ep: c.Likzik__Xds__Endpoint = undefined;
    c.likzik__xds__endpoint__init(&ep);
    ep.address = &addr;
    var lbe: c.Likzik__Xds__LbEndpoint = undefined;
    c.likzik__xds__lb_endpoint__init(&lbe);
    lbe.endpoint = &ep;
    var lbes = [_][*c]c.Likzik__Xds__LbEndpoint{&lbe};
    var loc: c.Likzik__Xds__LocalityLbEndpoints = undefined;
    c.likzik__xds__locality_lb_endpoints__init(&loc);
    loc.n_lb_endpoints = 1;
    loc.lb_endpoints = &lbes;
    var locs = [_][*c]c.Likzik__Xds__LocalityLbEndpoints{&loc};
    var cla: c.Likzik__Xds__ClusterLoadAssignment = undefined;
    c.likzik__xds__cluster_load_assignment__init(&cla);
    cla.cluster_name = @constCast("api");
    cla.n_endpoints = 1;
    cla.endpoints = &locs;
    var dur: c.Likzik__Xds__Duration = undefined;
    c.likzik__xds__duration__init(&dur);
    dur.seconds = 1;
    dur.nanos = 500_000_000;
    var api: c.Likzik__Xds__Cluster = undefined;
    c.likzik__xds__cluster__init(&api);
    api.name = @constCast("api");
    api.lb_policy = 3;
    api.connect_timeout = &dur;
    api.load_assignment = &cla;
    try res[@intFromEnum(Kind.cluster)].put(gpa, "api", try pack(gpa, &api, c.likzik__xds__cluster__get_packed_size, c.likzik__xds__cluster__pack));

    // EDS cluster whose endpoints have not arrived.
    var users: c.Likzik__Xds__Cluster = undefined;
    c.likzik__xds__cluster__init(&users);
    users.name = @constCast("users");
    users.type = 3;
    try res[@intFromEnum(Kind.cluster)].put(gpa, "users", try pack(gpa, &users, c.likzik__xds__cluster__get_packed_size, c.likzik__xds__cluster__pack));

    var d: Diag = .{};
    const frag = try buildFragment(gpa, &res, &d);
    defer gpa.free(frag);
    const Fragment = struct { clusters: []const @import("../model.zig").Cluster };
    const parsed = try std.json.parseFromSlice(Fragment, gpa, frag, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const cs = parsed.value.clusters;
    try testing.expectEqual(@as(usize, 2), cs.len);
    try testing.expectEqualStrings("api", cs[0].name);
    try testing.expectEqual(@import("../model.zig").LbPolicy.random, cs[0].lb_policy);
    try testing.expectEqual(@as(u32, 1500), cs[0].connect_timeout_ms);
    try testing.expectEqualStrings("10.0.0.1:8080", cs[0].endpoints[0].address);
    try testing.expectEqual(@as(usize, 0), cs[1].endpoints.len);

    var names = try edsNames(gpa, &res[@intFromEnum(Kind.cluster)]);
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    try testing.expectEqual(@as(usize, 1), names.items.len);
    try testing.expectEqualStrings("users", names.items[0]);

    // Unsupported: a DNS name is rejected with a clear message.
    sa.address = @constCast("api.internal");
    gpa.free(res[@intFromEnum(Kind.cluster)].get("api").?);
    try res[@intFromEnum(Kind.cluster)].put(gpa, "api", try pack(gpa, &api, c.likzik__xds__cluster__get_packed_size, c.likzik__xds__cluster__pack));
    try testing.expectError(error.Unsupported, buildFragment(gpa, &res, &d));
    try testing.expect(std.mem.indexOf(u8, d.message(), "DNS names are not supported") != null);
}
