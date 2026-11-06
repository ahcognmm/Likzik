//! Extension point for request/response filters (the API gateway lives
//! behind it, in src/gateway/; the core knows nothing gateway-specific).
//!
//! One extension can be registered per binary, before startup:
//!
//!   * `compile` turns the config's opaque `extensions` section into
//!     immutable state stored in the config snapshot (control thread). It
//!     is rebuilt on every reload, like the rest of the snapshot.
//!   * `initWorker` creates per-worker mutable state (counters, rate-limit
//!     buckets, scratch buffers). No locks: each worker owns its own.
//!   * `onRequest` runs for every request after parsing and the smuggling
//!     checks, before routing. It may pick the upstream cluster, rewrite
//!     the path, add/remove request headers, or answer locally.
//!   * `onResponse` runs on the upstream's final response head and may
//!     add/remove response headers.
//!
//! Slices returned in RequestOut/ResponseOut/LocalResponse must stay valid
//! until the next call on the same worker (point them into the snapshot
//! state or the worker state). The plain `likzik` binary registers nothing
//! and pays one null check per request.

const std = @import("std");
const parser = @import("../http1/parser.zig");
const codec = @import("../http1/codec.zig");
const snapshot = @import("../config/snapshot.zig");
const Diag = @import("../config/validate.zig").Diag;

pub const HeaderEdit = codec.Edit;

pub const RequestCtx = struct {
    worker: u16,
    workers: u16,
    now_ms: u64,
    req: *const parser.Request,
    /// Host header value (validated, may include a port).
    host: []const u8,
    client_ip: []const u8,
    /// Downstream connection is TLS.
    tls: bool,
    listener: *const snapshot.Listener,
    snapshot: *const snapshot.Snapshot,
};

pub const RequestOut = struct {
    /// Upstream cluster chosen by the extension; null means core routing
    /// (the listener's route_config) decides.
    cluster: ?*const snapshot.Cluster = null,
    /// Response timeout when `cluster` is set (0: 60 s).
    timeout_ms: u32 = 0,
    /// New request target (path and query).
    target: ?[]const u8 = null,
    /// Request headers added before forwarding.
    add: []const HeaderEdit = &.{},
    /// Request header names (case-insensitive) removed before forwarding.
    remove: []const []const u8 = &.{},
    /// Opaque value handed back to onResponse for this request.
    token: usize = 0,
};

pub const LocalResponse = struct {
    status: u16,
    body: []const u8 = "",
    content_type: []const u8 = "text/plain",
    headers: []const HeaderEdit = &.{},
};

pub const Decision = union(enum) {
    proceed,
    respond: LocalResponse,
};

pub const ResponseCtx = struct {
    status: u16,
    headers: []const parser.Header,
    token: usize,
};

pub const ResponseOut = struct {
    add: []const HeaderEdit = &.{},
    remove: []const []const u8 = &.{},
};

pub const Extension = struct {
    name: []const u8,
    compile: *const fn (arena: std.mem.Allocator, config: std.json.Value, snap: *const snapshot.Snapshot, diag: *Diag) anyerror!*anyopaque,
    /// Releases resources the arena does not own (optional).
    destroy: ?*const fn (state: *anyopaque) void = null,
    initWorker: *const fn (gpa: std.mem.Allocator, worker: u16, workers: u16) anyerror!*anyopaque,
    deinitWorker: *const fn (gpa: std.mem.Allocator, worker_state: *anyopaque) void,
    onRequest: *const fn (worker_state: *anyopaque, state: *anyopaque, ctx: *const RequestCtx, out: *RequestOut) Decision,
    onResponse: ?*const fn (worker_state: *anyopaque, state: *anyopaque, ctx: *const ResponseCtx, out: *ResponseOut) void = null,
    /// Appends Prometheus text for the extension's own metrics (control
    /// thread; worker states are read concurrently, use relaxed atomics).
    writeMetrics: ?*const fn (out: *std.ArrayList(u8), gpa: std.mem.Allocator, worker_states: []const ?*anyopaque) anyerror!void = null,
};

/// Set once by the binary's entry point, before config is loaded.
pub var registered: ?*const Extension = null;
