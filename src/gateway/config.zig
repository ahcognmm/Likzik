//! Gateway configuration: the `extensions.gateway` section of the likzik
//! config. Parsed from the opaque JSON value the core hands over; unknown
//! fields are rejected, like the rest of the config.

const std = @import("std");

pub const Root = struct {
    gateway: Gateway,
};

pub const Gateway = struct {
    /// Listener names the gateway handles (default: every HTTP listener).
    listeners: ?[]const []const u8 = null,
    /// When no gateway route matches: true hands the request to the core
    /// routes (route_configs), false answers 404.
    fallthrough: bool = false,
    /// Header carrying the authenticated consumer to the upstream.
    consumer_header: []const u8 = "X-Consumer",
    api_keys: []const ApiKeySet = &.{},
    jwt: []const JwtProvider = &.{},
    rate_limits: []const RateLimit = &.{},
    routes: []const Route,
};

pub const ApiKeySet = struct {
    name: []const u8,
    /// Request header holding the key.
    header: []const u8 = "X-API-Key",
    /// Optional query parameter holding the key.
    query: ?[]const u8 = null,
    /// Remove the key from the request before forwarding.
    strip: bool = true,
    keys: []const ApiKey,
};

pub const ApiKey = struct {
    consumer: []const u8,
    /// SHA-256 of the key, hex (preferred: the config never holds the key).
    sha256: ?[]const u8 = null,
    /// The key itself (hashed at load time).
    key: ?[]const u8 = null,
};

pub const JwtProvider = struct {
    name: []const u8,
    /// Allowed signature algorithms, e.g. ["RS256"]. "none" is never allowed.
    algorithms: []const []const u8,
    issuer: ?[]const u8 = null,
    /// Accepted `aud` values (any match); empty = audience not checked.
    audiences: []const []const u8 = &.{},
    /// JWKS document (file path, or inline object) with the verification keys.
    jwks_file: ?[]const u8 = null,
    jwks: ?std.json.Value = null,
    /// Shared secret for HS256/384/512.
    hs_secret: ?[]const u8 = null,
    /// Clock skew allowed for exp/nbf, seconds.
    leeway_s: u32 = 30,
    /// Header with "Bearer <token>".
    header: []const u8 = "Authorization",
    /// Optional query parameter holding the token.
    query: ?[]const u8 = null,
    /// Claim that names the consumer.
    consumer_claim: []const u8 = "sub",
    /// Claims copied into request headers.
    claims_to_headers: []const ClaimHeader = &.{},
    /// Keep the token in the forwarded request.
    forward_token: bool = true,
    /// Require `exp`.
    require_exp: bool = true,
};

pub const ClaimHeader = struct {
    claim: []const u8,
    header: []const u8,
};

pub const Period = enum { second, minute, hour };

pub const RateLimit = struct {
    name: []const u8,
    requests: u32,
    per: Period = .second,
    /// Bucket size (default: `requests`).
    burst: ?u32 = null,
    /// "client_ip", "consumer", "route", or "header:<name>".
    key: []const u8 = "client_ip",
};

pub const Route = struct {
    name: []const u8,
    /// "example.com", "*.example.com" or "*" (default: any host).
    hosts: []const []const u8 = &.{},
    /// "/users/:id", "/static/*rest", "/exact". Params match one segment;
    /// a wildcard matches the rest (zero or more segments).
    path: []const u8,
    methods: []const []const u8 = &.{},
    headers: []const HeaderMatch = &.{},
    query: []const QueryMatch = &.{},
    /// Authentication: names of api_keys sets / jwt providers (any of).
    auth: []const []const u8 = &.{},
    /// Let requests without credentials through (credentials that are
    /// present must still be valid).
    auth_optional: bool = false,
    rate_limits: []const []const u8 = &.{},
    /// Exactly one of cluster / redirect / respond.
    cluster: ?[]const u8 = null,
    redirect: ?Redirect = null,
    respond: ?Respond = null,
    /// New upstream path, template: "/v2/users/{id}", "/{rest}".
    rewrite: ?[]const u8 = null,
    timeout_ms: u32 = 60_000,
    request_headers: HeaderOps = .{},
    response_headers: HeaderOps = .{},
};

pub const HeaderMatch = struct {
    name: []const u8,
    /// Exact value.
    value: ?[]const u8 = null,
    prefix: ?[]const u8 = null,
    /// Must be present (true) or absent (false).
    present: ?bool = null,
};

pub const QueryMatch = struct {
    name: []const u8,
    value: ?[]const u8 = null,
    present: ?bool = null,
};

pub const Redirect = struct {
    status: u16 = 302,
    /// Template: "https://{host}{path}", "/new/{id}".
    location: []const u8,
};

pub const Respond = struct {
    status: u16 = 200,
    body: []const u8 = "",
    content_type: []const u8 = "text/plain",
};

pub const HeaderOps = struct {
    /// Replace (remove any existing, then add). Request values are templates.
    set: []const NameValue = &.{},
    /// Append.
    add: []const NameValue = &.{},
    remove: []const []const u8 = &.{},
};

pub const NameValue = struct {
    name: []const u8,
    value: []const u8,
};

pub fn parse(arena: std.mem.Allocator, value: std.json.Value) !Root {
    return std.json.parseFromValueLeaky(Root, arena, value, .{ .allocate = .alloc_always });
}
