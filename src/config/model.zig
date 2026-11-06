//! Configuration model. It is xDS-shaped from day one:
//! listeners -> route configs -> virtual hosts -> routes -> clusters ->
//! endpoints, with references by name. A future xDS adapter translates
//! Envoy resources into these types; it does not need a new model.
//!
//! The file source decodes JSON straight into these structs. Unknown
//! fields are rejected (the xDS equivalent is a NACK, never a silent ignore).

const std = @import("std");

pub const Config = struct {
    /// Free-form version label, reported by the admin endpoint.
    version: []const u8 = "",
    /// Worker threads. 0 = one per CPU.
    workers: u16 = 0,
    admin: ?Admin = null,
    limits: Limits = .{},
    tls: TlsSettings = .{},
    listeners: []const Listener,
    route_configs: []const RouteConfig = &.{},
    clusters: []const Cluster = &.{},
    /// Opaque configuration for the binary's extension (e.g. the API
    /// gateway in likzik-gw). The core passes it through unread.
    extensions: ?std.json.Value = null,
};

pub const Admin = struct {
    address: []const u8,
};

pub const Limits = struct {
    /// Largest accepted request or response head.
    max_head_bytes: u32 = 16 * 1024,
    /// Time allowed to receive a complete request head.
    header_timeout_ms: u32 = 30_000,
    /// Keep-alive idle timeout for downstream connections.
    idle_timeout_ms: u32 = 60_000,
    max_requests_per_connection: u32 = 10_000,
    max_connections_per_worker: u32 = 16_384,
    /// How long removed listeners and shutdown wait for connections.
    drain_timeout_ms: u32 = 10_000,
};

pub const Protocol = enum { http, tcp };

pub const Listener = struct {
    name: []const u8,
    address: []const u8,
    protocol: Protocol = .http,
    /// HTTP listeners: name of a RouteConfig.
    route_config: ?[]const u8 = null,
    /// TCP listeners: name of the target Cluster.
    cluster: ?[]const u8 = null,
    /// Append to (rather than replace) client X-Forwarded-For.
    trust_forwarded_headers: bool = false,
    /// TCP listeners: idle timeout for the tunnel.
    idle_timeout_ms: u32 = 300_000,
    tls: ?Tls = null,
};

pub const TlsSettings = struct {
    /// Refuse to start TLS listeners or upstreams unless the kernel `tls`
    /// module is loaded. With false, TLS runs in userspace when kTLS is
    /// unavailable (slower; counted by the tls_userspace metric).
    require_ktls: bool = true,
};

/// Downstream TLS termination.
pub const Tls = struct {
    /// The first certificate is the default; others are chosen by SNI.
    certificates: []const Certificate,
};

pub const Certificate = struct {
    certificate_chain: []const u8,
    private_key: []const u8,
    /// SNI names this certificate serves ("example.com", "*.example.com").
    server_names: []const []const u8 = &.{},
};

/// TLS to the upstream.
pub const UpstreamTls = struct {
    /// Server name sent in SNI and checked against the certificate.
    sni: ?[]const u8 = null,
    verify: bool = true,
    /// CA bundle (PEM). Default: the system store.
    ca_file: ?[]const u8 = null,
};

pub const RouteConfig = struct {
    name: []const u8,
    virtual_hosts: []const VirtualHost,
};

pub const VirtualHost = struct {
    name: []const u8,
    /// "example.com", "*.example.com" or "*".
    domains: []const []const u8,
    routes: []const Route,
};

pub const Route = struct {
    match: RouteMatch,
    route: RouteAction,
};

pub const RouteMatch = struct {
    prefix: ?[]const u8 = null,
    path: ?[]const u8 = null,
    methods: ?[]const []const u8 = null,
};

pub const RouteAction = struct {
    cluster: []const u8,
    prefix_rewrite: ?[]const u8 = null,
    /// Time allowed for the upstream to start responding.
    timeout_ms: u32 = 60_000,
};

pub const LbPolicy = enum { round_robin, least_request, random };

pub const Cluster = struct {
    name: []const u8,
    lb_policy: LbPolicy = .least_request,
    connect_timeout_ms: u32 = 2_000,
    /// Idle upstream connections are closed after this long.
    idle_timeout_ms: u32 = 30_000,
    max_idle_per_endpoint: u32 = 64,
    /// Connect attempts on different endpoints before 502/503.
    max_connect_attempts: u8 = 2,
    /// Consecutive connect failures before an endpoint is ejected.
    eject_after_failures: u8 = 3,
    eject_ms: u32 = 10_000,
    tls: ?UpstreamTls = null,
    endpoints: []const Endpoint,
};

pub const Endpoint = struct {
    address: []const u8,
    weight: u32 = 1,
};

pub fn parseJson(arena: std.mem.Allocator, text: []const u8, diag_out: *[256]u8) !Config {
    var diags: std.json.Diagnostics = .{};
    var scanner: std.json.Scanner = .initCompleteInput(arena, text);
    scanner.enableDiagnostics(&diags);
    return std.json.parseFromTokenSourceLeaky(Config, arena, &scanner, .{ .allocate = .alloc_always }) catch |err| {
        _ = std.fmt.bufPrint(diag_out, "json: {s} at line {d} column {d}", .{ @errorName(err), diags.getLine(), diags.getColumn() }) catch {};
        return error.InvalidConfig;
    };
}

test "parse minimal config" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diag: [256]u8 = undefined;
    const c = try parseJson(arena.allocator(),
        \\{"listeners":[{"name":"l","address":"127.0.0.1:8080","route_config":"r"}],
        \\ "route_configs":[{"name":"r","virtual_hosts":[{"name":"v","domains":["*"],
        \\   "routes":[{"match":{"prefix":"/"},"route":{"cluster":"c"}}]}]}],
        \\ "clusters":[{"name":"c","endpoints":[{"address":"127.0.0.1:9000"}]}]}
    , &diag);
    try std.testing.expectEqual(@as(usize, 1), c.listeners.len);
    try std.testing.expectEqual(LbPolicy.least_request, c.clusters[0].lb_policy);
}

test "unknown fields are rejected" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diag: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidConfig, parseJson(arena.allocator(),
        \\{"listeners":[],"bogus":1}
    , &diag));
}
