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
    if (cfg.access_log) |al| {
        if (al.path.len == 0) return d.set("access_log.path is empty", .{});
        if (!dirWritable(al.path)) return d.set("access_log: cannot write to the directory of '{s}'", .{al.path});
    }

    for (cfg.listeners, 0..) |li, i| {
        const a = Address.parse(li.address) catch return d.set("listener '{s}': invalid address '{s}'", .{ li.name, li.address });
        for (cfg.listeners[0..i]) |other| {
            const b = Address.parse(other.address) catch unreachable;
            if (a.eql(&b)) return d.set("listeners '{s}' and '{s}' share address {s}", .{ other.name, li.name, li.address });
        }
        if (li.tls) |t| {
            if (li.protocol != .http) return d.set("listener '{s}': TLS on tcp listeners is not supported yet", .{li.name});
            if (t.certificates.len == 0) return d.set("listener '{s}': tls needs at least one certificate", .{li.name});
            if (t.certificates.len > 256) return d.set("listener '{s}': too many certificates", .{li.name});
            for (t.certificates) |cert| for (cert.server_names) |n| {
                if (n.len == 0 or n.len > 253) return d.set("listener '{s}': invalid server name", .{li.name});
                if (std.mem.indexOfScalar(u8, n, '*')) |star| if (star != 0 or n.len < 3 or n[1] != '.')
                    return d.set("listener '{s}': unsupported wildcard '{s}'", .{ li.name, n });
            };
        }
        switch (li.protocol) {
            .http => {
                const rc = li.route_config orelse return d.set("listener '{s}': http listener needs route_config", .{li.name});
                if (li.sni_routes.len > 0) return d.set("listener '{s}': sni_routes need a tcp listener (http listeners route by Host)", .{li.name});
                if (li.cluster != null) return d.set("listener '{s}': http listener cannot set cluster", .{li.name});
                if (!findRouteConfig(cfg, rc)) return d.set("listener '{s}': unknown route_config '{s}'", .{ li.name, rc });
            },
            .tcp => {
                if (li.cluster == null and li.sni_routes.len == 0) return d.set("listener '{s}': tcp listener needs cluster or sni_routes", .{li.name});
                if (li.route_config != null) return d.set("listener '{s}': tcp listener cannot set route_config", .{li.name});
                if (li.cluster) |c| if (!findCluster(cfg, c)) return d.set("listener '{s}': unknown cluster '{s}'", .{ li.name, c });
                for (li.sni_routes) |r| {
                    if (!findCluster(cfg, r.cluster)) return d.set("listener '{s}': sni route to unknown cluster '{s}'", .{ li.name, r.cluster });
                    if (r.server_names.len == 0) return d.set("listener '{s}': sni route to '{s}' has no server_names", .{ li.name, r.cluster });
                    for (r.server_names) |n| {
                        const star = std.mem.indexOfScalar(u8, n, '*');
                        if (n.len == 0 or (star != null and !(star.? == 0 and n.len > 2 and n[1] == '.' and std.mem.indexOfScalarPos(u8, n, 1, '*') == null)))
                            return d.set("listener '{s}': unsupported server name '{s}' (use exact names or *.suffix)", .{ li.name, n });
                    }
                }
            },
        }
    }

    for (cfg.clusters) |c| {
        if (c.max_ejection_percent > 100) return d.set("cluster '{s}': max_ejection_percent must be 0..100", .{c.name});
        if (c.health_check) |hc| {
            if (hc.interval_ms < 100 or hc.timeout_ms == 0 or hc.timeout_ms >= hc.interval_ms)
                return d.set("cluster '{s}': health_check needs interval_ms >= 100 and 0 < timeout_ms < interval_ms", .{c.name});
            if (hc.healthy_threshold == 0 or hc.unhealthy_threshold == 0) return d.set("cluster '{s}': health_check thresholds must be at least 1", .{c.name});
            if (hc.path) |p| {
                if (p.len == 0 or p[0] != '/' or std.mem.indexOfAny(u8, p, " \r\n") != null) return d.set("cluster '{s}': health_check.path must start with '/' and contain no spaces", .{c.name});
                if (c.tls != null) return d.set("cluster '{s}': HTTP health checks over TLS are not supported yet; omit path for a TCP check", .{c.name});
            }
            if (hc.host) |h| if (h.len == 0 or std.mem.indexOfAny(u8, h, " \r\n") != null) return d.set("cluster '{s}': invalid health_check.host", .{c.name});
        }
        if (c.retry) |r| {
            if (r.budget_percent > 100) return d.set("cluster '{s}': retry.budget_percent must be 0..100", .{c.name});
            if (r.num_retries > 5) return d.set("cluster '{s}': retry.num_retries must be at most 5", .{c.name});
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
                if (r.route.mirror) |mm| {
                    const mc = for (cfg.clusters) |*c| {
                        if (std.mem.eql(u8, c.name, mm.cluster)) break c;
                    } else return d.set("virtual_host '{s}' route {d}: unknown mirror cluster '{s}'", .{ vh.name, ri, mm.cluster });
                    if (mc.tls != null or mc.proxy_protocol != null) return d.set("virtual_host '{s}' route {d}: mirror cluster '{s}' must be plain HTTP (no tls or proxy_protocol yet)", .{ vh.name, ri, mm.cluster });
                    if (mm.percent > 100) return d.set("virtual_host '{s}' route {d}: mirror.percent must be 0..100", .{ vh.name, ri });
                    for (mm.methods) |meth| {
                        const known = for (known_methods) |k| {
                            if (std.mem.eql(u8, k, meth)) break true;
                        } else false;
                        if (!known) return d.set("virtual_host '{s}' route {d}: unknown mirror method '{s}'", .{ vh.name, ri, meth });
                    }
                }
                for (cfg.clusters) |c| if (c.proxy_protocol != null and std.mem.eql(u8, c.name, r.route.cluster))
                    return d.set("virtual_host '{s}' route {d}: cluster '{s}' sends PROXY protocol, which only tcp listeners support", .{ vh.name, ri, c.name });
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
        if (c.tls) |t| {
            if (t.verify and t.sni == null) return d.set("cluster '{s}': tls.verify needs tls.sni (the name to check the certificate against)", .{c.name});
        }
        for (c.endpoints) |e| {
            _ = Address.parse(e.address) catch return d.set("cluster '{s}': invalid endpoint address '{s}'", .{ c.name, e.address });
            if (e.weight == 0 or e.weight > 1000) return d.set("cluster '{s}': endpoint weight must be 1..1000", .{c.name});
        }
    }
}

/// True when the directory that would hold `path` exists and is writable.
fn dirWritable(path: []const u8) bool {
    const dir = std.fs.path.dirname(path) orelse ".";
    var z: [std.fs.max_path_bytes]u8 = undefined;
    if (dir.len >= z.len) return false;
    @memcpy(z[0..dir.len], dir);
    z[dir.len] = 0;
    const linux = std.os.linux;
    return linux.errno(linux.access(@ptrCast(&z), linux.W_OK)) == .SUCCESS;
}
