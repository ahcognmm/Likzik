//! Library root: every subsystem, so tests and tools can import them.

pub const http1 = struct {
    pub const chars = @import("http1/chars.zig");
    pub const headers = @import("http1/headers.zig");
    pub const parser = @import("http1/parser.zig");
    pub const chunked = @import("http1/chunked.zig");
    pub const rules = @import("http1/smuggling_rules.zig");
    pub const codec = @import("http1/codec.zig");
    pub const path = @import("http1/path.zig");
};

pub const net = struct {
    pub const addr = @import("net/addr.zig");
    pub const socket = @import("net/socket.zig");
    pub const proxy_protocol = @import("net/proxy_protocol.zig");
};

pub const config = struct {
    pub const model = @import("config/model.zig");
    pub const validate = @import("config/validate.zig");
    pub const snapshot = @import("config/snapshot.zig");
    pub const file_watch = @import("config/sources/file_watch.zig");
    pub const xds = @import("config/sources/xds.zig");
    pub const xds_translate = @import("config/sources/xds_translate.zig");
};

test {
    inline for (.{ http1, net, config, mem, runtime, upstream, tls, proxy, l4, control, observe }) |ns| {
        inline for (@typeInfo(ns).@"struct".decl_names) |name| _ = @field(ns, name);
    }
    _ = rcu;
}

pub const mem = struct {
    pub const pool = @import("mem/pool.zig");
    pub const blocks = @import("mem/blocks.zig");
    pub const region = @import("mem/region.zig");
};

pub const runtime = struct {
    pub const timer_wheel = @import("runtime/timer_wheel.zig");
    pub const loop = @import("runtime/loop.zig");
    pub const send_queue = @import("runtime/send_queue.zig");
    pub const buf_ring = @import("runtime/buf_ring.zig");
    pub const worker = @import("runtime/worker.zig");
    pub const checks = @import("runtime/checks.zig");
};

pub const upstream = struct {
    pub const health = @import("upstream/health.zig");
    pub const lb = @import("upstream/lb.zig");
    pub const pool = @import("upstream/pool.zig");
    pub const breaker = @import("upstream/breaker.zig");
    pub const active_health = @import("upstream/active_health.zig");
    pub const shared_pool = @import("upstream/shared_pool.zig");
};

pub const tls = struct {
    pub const backend = @import("tls/backend.zig");
    pub const openssl = @import("tls/openssl.zig");
    pub const sni = @import("tls/sni.zig");
    pub const ktls = @import("tls/ktls.zig");
    pub const client_hello = @import("tls/client_hello.zig");
};

pub const proxy = struct {
    pub const http = @import("proxy/http.zig");
    pub const filter = @import("proxy/filter.zig");
};

pub const l4 = struct {
    pub const tcp_proxy = @import("l4/tcp_proxy.zig");
};

pub const control = struct {
    pub const thread = @import("control/thread.zig");
    pub const admin_server = @import("control/admin_server.zig");
};

pub const observe = struct {
    pub const stats = @import("observe/stats.zig");
    pub const prometheus = @import("observe/prometheus.zig");
    pub const access_log = @import("observe/access_log.zig");
};

pub const rcu = @import("config/rcu.zig");
