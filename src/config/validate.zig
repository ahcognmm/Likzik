//! Semantic validation of a parsed Config. Every config source (file now,
//! xDS later) goes through this one validator before a snapshot is built.

const std = @import("std");
const model = @import("model.zig");
const Address = @import("../net/addr.zig").Address;

pub const Diag = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,

    pub fn set(self: *Diag, comptime fmt: []const u8, args: anytype) error{InvalidConfig} {
        const s = std.fmt.bufPrint(&self.buf, fmt, args) catch self.buf[0..];
        self.len = s.len;
        return error.InvalidConfig;
    }

    pub fn message(self: *const Diag) []const u8 {
        return self.buf[0..self.len];
    }
};

fn dupName(comptime T: type, items: []const T, what: []const u8, d: *Diag) error{InvalidConfig}!void {
    for (items, 0..) |a, i| {
        if (a.name.len == 0) return d.set("{s}[{d}]: empty name", .{ what, i });
        for (items[0..i]) |b| {
            if (std.mem.eql(u8, a.name, b.name)) return d.set("duplicate {s} name '{s}'", .{ what, a.name });
        }
    }
}

fn findCluster(cfg: *const model.Config, name: []const u8) bool {
    for (cfg.clusters) |c| if (std.mem.eql(u8, c.name, name)) return true;
    return false;
}

fn findRouteConfig(cfg: *const model.Config, name: []const u8) bool {
    for (cfg.route_configs) |r| if (std.mem.eql(u8, r.name, name)) return true;
    return false;
}

const known_methods = [_][]const u8{ "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH" };

pub fn validate(cfg: *const model.Config, d: *Diag) error{InvalidConfig}!void {
    if (cfg.listeners.len == 0) return d.set("no listeners", .{});
    try dupName(model.Listener, cfg.listeners, "listener", d);
    try dupName(model.RouteConfig, cfg.route_configs, "route_config", d);
    try dupName(model.Cluster, cfg.clusters, "cluster", d);

    const l = cfg.limits;
    if (l.max_head_bytes < 1024 or l.max_head_bytes > 64 * 1024) return d.set("limits.max_head_bytes must be within 1024..65536", .{});
    if (l.max_connections_per_worker == 0 or l.max_connections_per_worker > 1 << 20) return d.set("limits.max_connections_per_worker out of range", .{});
    if (l.header_timeout_ms == 0 or l.idle_timeout_ms == 0) return d.set("timeouts must be > 0", .{});
    if (cfg.workers > 1024) return d.set("workers must be <= 1024", .{});
    if (cfg.admin) |a| _ = Address.parse(a.address) catch return d.set("admin: invalid address '{s}'", .{a.address});

    for (cfg.listeners, 0..) |li, i| {
        const a = Address.parse(li.address) catch return d.set("listener '{s}': invalid address '{s}'", .{ li.name, li.address });
        for (cfg.listeners[0..i]) |other| {
            const b = Address.parse(other.address) catch unreachable;
            if (a.eql(&b)) return d.set("listeners '{s}' and '{s}' share address {s}", .{ other.name, li.name, li.address });
        }
        if (li.tls != null) return d.set("listener '{s}': TLS termination is not available in this build yet", .{li.name});
        switch (li.protocol) {
            .http => {
                const rc = li.route_config orelse return d.set("listener '{s}': http listener needs route_config", .{li.name});
                if (li.cluster != null) return d.set("listener '{s}': http listener cannot set cluster", .{li.name});
                if (!findRouteConfig(cfg, rc)) return d.set("listener '{s}': unknown route_config '{s}'", .{ li.name, rc });
            },
            .tcp => {
                const c = li.cluster orelse return d.set("listener '{s}': tcp listener needs cluster", .{li.name});
                if (li.route_config != null) return d.set("listener '{s}': tcp listener cannot set route_config", .{li.name});
                if (!findCluster(cfg, c)) return d.set("listener '{s}': unknown cluster '{s}'", .{ li.name, c });
            },
        }
    }

    for (cfg.route_configs) |rc| {
        try dupName(model.VirtualHost, rc.virtual_hosts, "virtual_host", d);
        for (rc.virtual_hosts) |vh| {
            if (vh.domains.len == 0) return d.set("virtual_host '{s}': no domains", .{vh.name});
            for (vh.domains) |dom| {
                if (dom.len == 0) return d.set("virtual_host '{s}': empty domain", .{vh.name});
                if (std.mem.indexOfScalar(u8, dom, '*')) |star| {
                    if (!(dom.len == 1 or (star == 0 and dom.len > 2 and dom[1] == '.')))
                        return d.set("virtual_host '{s}': unsupported wildcard '{s}'", .{ vh.name, dom });
                }
                // A domain may appear in only one virtual host per route config.
                for (rc.virtual_hosts) |other| {
                    if (other.name.ptr == vh.name.ptr) break;
                    for (other.domains) |od| if (std.ascii.eqlIgnoreCase(od, dom))
                        return d.set("route_config '{s}': domain '{s}' in two virtual hosts", .{ rc.name, dom });
                }
            }
            for (vh.routes, 0..) |r, ri| {
                const m = r.match;
                if ((m.prefix == null) == (m.path == null))
                    return d.set("virtual_host '{s}' route {d}: set exactly one of prefix or path", .{ vh.name, ri });
                const p = m.prefix orelse m.path.?;
                if (p.len == 0 or p[0] != '/') return d.set("virtual_host '{s}' route {d}: path must start with '/'", .{ vh.name, ri });
                if (m.methods) |ms| for (ms) |meth| {
                    var ok = false;
                    for (known_methods) |k| if (std.mem.eql(u8, k, meth)) {
                        ok = true;
                    };
                    if (!ok) return d.set("virtual_host '{s}' route {d}: unknown method '{s}'", .{ vh.name, ri, meth });
                };
                if (!findCluster(cfg, r.route.cluster)) return d.set("virtual_host '{s}' route {d}: unknown cluster '{s}'", .{ vh.name, ri, r.route.cluster });
                if (r.route.prefix_rewrite) |pr| {
                    if (m.prefix == null) return d.set("virtual_host '{s}' route {d}: prefix_rewrite needs a prefix match", .{ vh.name, ri });
                    if (pr.len == 0 or pr[0] != '/') return d.set("virtual_host '{s}' route {d}: prefix_rewrite must start with '/'", .{ vh.name, ri });
                }
                if (r.route.timeout_ms == 0) return d.set("virtual_host '{s}' route {d}: timeout_ms must be > 0", .{ vh.name, ri });
            }
        }
    }

    for (cfg.clusters) |c| {
        if (c.endpoints.len == 0) return d.set("cluster '{s}': no endpoints", .{c.name});
        if (c.endpoints.len > 4096) return d.set("cluster '{s}': too many endpoints", .{c.name});
        if (c.max_connect_attempts == 0) return d.set("cluster '{s}': max_connect_attempts must be >= 1", .{c.name});
        if (c.connect_timeout_ms == 0) return d.set("cluster '{s}': connect_timeout_ms must be > 0", .{c.name});
        for (c.endpoints) |e| {
            _ = Address.parse(e.address) catch return d.set("cluster '{s}': invalid endpoint address '{s}'", .{ c.name, e.address });
            if (e.weight == 0 or e.weight > 1000) return d.set("cluster '{s}': endpoint weight must be 1..1000", .{c.name});
        }
    }
}
