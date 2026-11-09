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
    listeners: []const Listener = &.{},
    route_configs: []const RouteConfig = &.{},
    clusters: []const Cluster = &.{},
    access_log: ?AccessLog = null,
    /// Dynamic configuration from an xDS control plane (ADS, state of the
    /// world). Listeners, routes and clusters from it are added to the ones
    /// in this file. Read at startup only.
    xds: ?Xds = null,
    /// Opaque configuration for the binary's extension (e.g. the API
    /// gateway in likzik-gw). The core passes it through unread.
    extensions: ?std.json.Value = null,
};

pub const Xds = struct {
    /// ADS server, "ip:port" (gRPC over plaintext HTTP/2).
    address: []const u8,
    /// Node identity sent to the control plane.
    node_id: []const u8,
    node_cluster: []const u8 = "likzik",
    /// :authority for the gRPC stream (default: the address).
    authority: ?[]const u8 = null,
    connect_timeout_ms: u32 = 5_000,
};

pub const AccessLog = struct {
    /// File the log is appended to. Reopened on every config reload, so
    /// log rotation is: rename the file, then send SIGHUP.
    path: []const u8,
    format: @import("../observe/access_log.zig").Format = .text,
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
    /// Expect a PROXY protocol header (v1 or v2) from a load balancer in
    /// front: the client address comes from it. Connections that do not
    /// start with one are closed.
    proxy_protocol: bool = false,
    /// TCP listeners: choose the cluster by the TLS server name (SNI)
    /// without terminating TLS. `cluster` (optional here) takes
    /// connections with no or an unknown name.
    sni_routes: []const SniRoute = &.{},
};

pub const SniRoute = struct {
    /// Exact names or "*.example.com" (any one or more labels).
    server_names: []const []const u8,
    cluster: []const u8,
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
    /// Send a copy of matching requests to another cluster.
    mirror: ?Mirror = null,
};

pub const Mirror = struct {
    cluster: []const u8,
    /// Share of matching requests that are mirrored.
    percent: u8 = 100,
    /// Only requests without a body are ever mirrored.
    methods: []const []const u8 = &.{ "GET", "HEAD" },
};

pub const LbPolicy = enum { round_robin, least_request, random };

pub const Cluster = struct {
    name: []const u8,
    lb_policy: LbPolicy = .least_request,
    connect_timeout_ms: u32 = 2_000,
    /// Idle upstream connections are closed after this long.
    idle_timeout_ms: u32 = 30_000,
    max_idle_per_endpoint: u32 = 64,
    /// Park idle connections beyond a worker's share in a pool all workers
    /// draw from (plain and kTLS connections).
    share_idle_connections: bool = true,
    /// Connect attempts on different endpoints before 502/503.
    max_connect_attempts: u8 = 2,
    /// Consecutive connect failures before an endpoint is ejected.
    eject_after_failures: u8 = 3,
    eject_ms: u32 = 10_000,
    /// Consecutive 5xx responses from one endpoint before it is ejected
    /// (0 = off). Counted per worker, like connect failures.
    consecutive_5xx: u8 = 0,
    /// Never eject more than this share of the cluster's endpoints.
    max_ejection_percent: u8 = 50,
    circuit_breakers: CircuitBreakers = .{},
    retry: ?RetryPolicy = null,
    health_check: ?HealthCheck = null,
    tls: ?UpstreamTls = null,
    /// Send a PROXY protocol header with the client's address to the
    /// endpoints. TCP listeners only.
    proxy_protocol: ?@import("../net/proxy_protocol.zig").Version = null,
    endpoints: []const Endpoint,
};

/// Process-wide limits for one cluster (0 = unlimited). Over a limit the
/// proxy answers 503 at once instead of piling onto a struggling cluster.
pub const CircuitBreakers = struct {
    max_connections: u32 = 0,
    max_requests: u32 = 0,
    max_retries: u32 = 0,
};

/// Active health checks: a TCP connect, or an HTTP GET of `path` that must
/// answer 200-399.
pub const HealthCheck = struct {
    interval_ms: u32 = 5_000,
    timeout_ms: u32 = 1_000,
    /// Failures in a row before an endpoint is marked unhealthy.
    unhealthy_threshold: u8 = 3,
    /// Passes in a row before it is healthy again.
    healthy_threshold: u8 = 2,
    path: ?[]const u8 = null,
    /// Host header (default: the endpoint address).
    host: ?[]const u8 = null,
};

pub const RetryOn = enum {
    /// Any 5xx response.
    @"5xx",
    /// 502, 503 or 504 from the upstream.
    gateway_error,
    /// The connection broke before a response arrived.
    reset,
};

/// Retries idempotent requests without a body on another endpoint.
pub const RetryPolicy = struct {
    retry_on: []const RetryOn = &.{ .gateway_error, .reset },
    num_retries: u8 = 1,
    /// Retries in flight may be at most this share of active requests
    /// (with a floor of 3 per worker).
    budget_percent: u8 = 20,
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
