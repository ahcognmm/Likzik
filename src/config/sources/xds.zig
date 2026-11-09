//! xDS client: one Aggregated Discovery Service stream (state of the world)
//! over gRPC/HTTP/2 (nghttp2, plaintext), on its own thread.
//!
//! Subscriptions: clusters and listeners as wildcards; endpoints for every
//! EDS cluster and route configurations for every listener that uses RDS,
//! following what the control plane sends. Each response is translated
//! (xds_translate.zig), merged with the config file by the control thread
//! and validated like any reload: accepted -> ACK with the new version,
//! rejected -> NACK with the previous version and the validator's message.
//! The stream reconnects with backoff and resumes from the accepted
//! versions.

const std = @import("std");
const linux = std.os.linux;
const c = @import("xds_c");
const tr = @import("xds_translate.zig");
const model = @import("../model.zig");
const Address = @import("../../net/addr.zig").Address;
const socket = @import("../../net/socket.zig");

const log = std.log.scoped(.xds);

const ads_path = "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources";
const max_message = 64 << 20;

/// Applies a translated fragment; returns null or the rejection reason.
pub const ApplyFn = *const fn (ctx: *anyopaque, fragment: []const u8, err: *[512]u8) ?[]const u8;

const TypeState = struct {
    /// Accepted resources: name -> serialized message (owned).
    map: tr.Map = .empty,
    version: []u8 = &.{},
    nonce: []u8 = &.{},
    /// Names subscribed to (EDS/RDS); empty for wildcard types.
    names: std.ArrayList([]const u8) = .empty,
    /// Last rejected response, retried after another type is accepted:
    /// updates of different types can arrive in an order where one only
    /// fits after the other (a cluster removed before its listener).
    rejected: ?Pending = null,
};

const Pending = struct { kind: tr.Kind, version: []u8, nonce: []u8, resources: std.ArrayList([]u8) };

pub const Client = struct {
    gpa: std.mem.Allocator,
    addr: Address,
    authority: [:0]u8,
    node_id: [:0]u8,
    node_cluster: [:0]u8,
    connect_timeout_ms: u32,
    apply_ctx: *anyopaque,
    apply_fn: ApplyFn,

    stop: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    // Reported by the admin endpoint.
    connected: std.atomic.Value(bool) = .init(false),
    accepted: std.atomic.Value(u64) = .init(0),
    rejected: std.atomic.Value(u64) = .init(0),

    types: [4]TypeState = .{ .{}, .{}, .{}, .{} },

    // Connection state (xDS thread only).
    fd: linux.fd_t = -1,
    session: ?*c.nghttp2_session = null,
    stream_id: i32 = -1,
    stream_open: bool = false,
    tx: std.ArrayList(u8) = .empty,
    tx_off: usize = 0,
    rx: std.ArrayList(u8) = .empty,
    pending: std.ArrayList(Pending) = .empty,
    grpc_status: [64]u8 = undefined,
    grpc_status_len: usize = 0,

    pub fn init(gpa: std.mem.Allocator, cfg: model.Xds, apply_ctx: *anyopaque, apply_fn: ApplyFn) !*Client {
        const self = try gpa.create(Client);
        self.* = .{
            .gpa = gpa,
            .addr = try Address.parse(cfg.address),
            .authority = try gpa.dupeSentinel(u8, cfg.authority orelse cfg.address, 0),
            .node_id = try gpa.dupeSentinel(u8, cfg.node_id, 0),
            .node_cluster = try gpa.dupeSentinel(u8, cfg.node_cluster, 0),
            .connect_timeout_ms = cfg.connect_timeout_ms,
            .apply_ctx = apply_ctx,
            .apply_fn = apply_fn,
        };
        return self;
    }

    pub fn start(self: *Client) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn deinit(self: *Client) void {
        self.stop.store(true, .release);
        if (self.thread) |t| t.join();
        self.disconnect();
        for (&self.types) |*t| {
            for (t.map.keys(), t.map.values()) |k, v| {
                self.gpa.free(k);
                self.gpa.free(v);
            }
            t.map.deinit(self.gpa);
            self.gpa.free(t.version);
            self.gpa.free(t.nonce);
            freeNames(self.gpa, &t.names);
            if (t.rejected) |*r| freePending(self.gpa, r);
        }
        self.tx.deinit(self.gpa);
        self.rx.deinit(self.gpa);
        self.pending.deinit(self.gpa);
        self.gpa.free(self.authority);
        self.gpa.free(self.node_id);
        self.gpa.free(self.node_cluster);
        self.gpa.destroy(self);
    }

    // ------------------------------------------------------------ main loop

    fn run(self: *Client) void {
        var backoff_ms: u64 = 500;
        while (!self.stop.load(.acquire)) {
            if (self.connect()) {
                backoff_ms = 500;
                self.serve();
            }
            self.disconnect();
            if (self.stop.load(.acquire)) break;
            log.warn("ADS stream down; reconnecting in {d} ms", .{backoff_ms});
            sleepMs(backoff_ms, &self.stop);
            backoff_ms = @min(backoff_ms * 2, 30_000);
        }
    }

    fn connect(self: *Client) bool {
        const fd = socket.connectSocket(&self.addr) catch return false;
        self.fd = fd;
        const rc = linux.connect(fd, &self.addr.any, self.addr.len());
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INPROGRESS => {
                var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
                if (linux.poll(&pfd, 1, @intCast(self.connect_timeout_ms)) != 1) {
                    log.warn("connect to {s}: timed out", .{self.authority});
                    return false;
                }
                var err: i32 = 0;
                var len: linux.socklen_t = @sizeOf(i32);
                _ = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&err), &len);
                if (err != 0) {
                    log.warn("connect to {s}: {s}", .{ self.authority, @tagName(@as(linux.E, @enumFromInt(err))) });
                    return false;
                }
            },
            else => |e| {
                log.warn("connect to {s}: {s}", .{ self.authority, @tagName(e) });
                return false;
            },
        }

        var cbs: ?*c.nghttp2_session_callbacks = null;
        if (c.nghttp2_session_callbacks_new(&cbs) != 0) return false;
        defer c.nghttp2_session_callbacks_del(cbs);
        c.nghttp2_session_callbacks_set_send_callback(cbs, onSend);
        c.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, onData);
        c.nghttp2_session_callbacks_set_on_stream_close_callback(cbs, onStreamClose);
        c.nghttp2_session_callbacks_set_on_header_callback(cbs, onHeader);
        if (c.nghttp2_session_client_new(&self.session, cbs, self) != 0) return false;
        if (c.nghttp2_submit_settings(self.session, c.NGHTTP2_FLAG_NONE, null, 0) != 0) return false;

        const nva = [_]c.nghttp2_nv{
            nv(":method", "POST"),
            nv(":scheme", "http"),
            nv(":path", ads_path),
            nv(":authority", self.authority),
            nv("content-type", "application/grpc"),
            nv("te", "trailers"),
            nv("user-agent", "likzik-xds"),
        };
        var prd: c.nghttp2_data_provider = .{ .source = .{ .ptr = self }, .read_callback = onRead };
        const sid = c.nghttp2_submit_request(self.session, null, &nva, nva.len, &prd, self);
        if (sid < 0) return false;
        self.stream_id = sid;
        self.stream_open = true;
        self.grpc_status_len = 0;
        self.connected.store(true, .release);
        log.info("ADS stream open to {s} as node '{s}'", .{ self.authority, self.node_id });

        // (Re)subscribe from the accepted versions.
        self.subscribe(.cluster, null, null);
        self.subscribe(.listener, null, null);
        if (self.types[@intFromEnum(tr.Kind.endpoints)].names.items.len > 0) self.subscribe(.endpoints, null, null);
        if (self.types[@intFromEnum(tr.Kind.route)].names.items.len > 0) self.subscribe(.route, null, null);
        return true;
    }

    fn disconnect(self: *Client) void {
        if (self.session) |s| c.nghttp2_session_del(s);
        self.session = null;
        if (self.fd >= 0) socket.closeFd(self.fd);
        self.fd = -1;
        self.stream_open = false;
        self.tx.clearRetainingCapacity();
        self.tx_off = 0;
        self.rx.clearRetainingCapacity();
        for (self.pending.items) |*p| freePending(self.gpa, p);
        self.pending.clearRetainingCapacity();
        self.connected.store(false, .release);
    }

    fn serve(self: *Client) void {
        var buf: [16 * 1024]u8 = undefined;
        while (!self.stop.load(.acquire)) {
            if (c.nghttp2_session_send(self.session) != 0) return;
            if (!self.stream_open) {
                if (self.grpc_status_len > 0) log.warn("ADS stream closed by the server: {s}", .{self.grpc_status[0..self.grpc_status_len]});
                return;
            }
            const want_out = c.nghttp2_session_want_write(self.session) != 0;
            var pfd = [_]linux.pollfd{.{ .fd = self.fd, .events = linux.POLL.IN | (if (want_out) @as(i16, linux.POLL.OUT) else 0), .revents = 0 }};
            _ = linux.poll(&pfd, 1, 250);
            if (pfd[0].revents & (linux.POLL.IN | linux.POLL.HUP | linux.POLL.ERR) != 0) {
                const n = socket.recvNb(self.fd, &buf, false) catch |e| switch (e) {
                    error.WouldBlock => 0,
                    error.SyscallFailed => return,
                };
                if (n == 0 and pfd[0].revents & linux.POLL.IN != 0) return; // closed
                if (n > 0 and c.nghttp2_session_mem_recv(self.session, &buf, n) < 0) return;
            }
            // Responses are handled outside nghttp2 callbacks.
            while (self.pending.items.len > 0) {
                var p = self.pending.orderedRemove(0);
                defer freePending(self.gpa, &p);
                self.handle(&p);
            }
        }
    }

    // ------------------------------------------------------------ protocol

    fn handle(self: *Client, p: *Pending) void {
        const kind = p.kind;
        const st = &self.types[@intFromEnum(kind)];
        // Tentative state: this type's resources replaced by the response.
        var tentative: [4]tr.Map = undefined;
        for (&tentative, &self.types) |*m, *t| m.* = t.map;
        var fresh: tr.Map = .empty;
        defer fresh.deinit(self.gpa);
        var reason_buf: [512]u8 = undefined;
        var reason: ?[]const u8 = null;
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |n| self.gpa.free(n);
            names.deinit(self.gpa);
        }
        for (p.resources.items) |bytes| {
            const name = tr.resourceName(self.gpa, kind, bytes) orelse {
                reason = "a resource does not decode";
                break;
            };
            if (fresh.contains(name)) {
                self.gpa.free(name);
                reason = "a resource name appears twice";
                break;
            }
            names.append(self.gpa, name) catch break;
            fresh.put(self.gpa, name, bytes) catch break;
        }
        tentative[@intFromEnum(kind)] = fresh;
        var d: tr.Diag = .{};
        if (reason == null) {
            if (tr.buildFragment(self.gpa, &tentative, &d)) |frag| {
                defer self.gpa.free(frag);
                reason = self.apply_fn(self.apply_ctx, frag, &reason_buf);
            } else |e| reason = if (e == error.Unsupported) d.message() else @errorName(e);
        }

        setOwned(self.gpa, &st.nonce, p.nonce);
        if (reason) |why| {
            _ = self.rejected.fetchAdd(1, .monotonic);
            log.warn("rejected {s} version '{s}': {s}", .{ @tagName(kind), p.version, why });
            self.request(kind, why);
            if (st.rejected) |*old| freePending(self.gpa, old);
            st.rejected = clonePending(self.gpa, p) catch null;
            return;
        }
        // Commit: take ownership of the resources and names.
        for (st.map.keys(), st.map.values()) |k, v| {
            self.gpa.free(k);
            self.gpa.free(v);
        }
        st.map.clearRetainingCapacity();
        for (names.items, p.resources.items) |n, bytes| st.map.put(self.gpa, n, bytes) catch {};
        names.clearRetainingCapacity();
        p.resources.clearRetainingCapacity(); // owned by the map now
        setOwned(self.gpa, &st.version, p.version);
        _ = self.accepted.fetchAdd(1, .monotonic);
        log.info("applied {s} version '{s}' ({d} resources)", .{ @tagName(kind), st.version, st.map.count() });
        self.request(kind, null);
        if (st.rejected) |*old| { // superseded
            freePending(self.gpa, old);
            st.rejected = null;
        }
        defer self.retryRejected(kind);

        // Follow the dependencies: EDS names from clusters, RDS names from listeners.
        switch (kind) {
            .cluster => self.follow(.endpoints, tr.edsNames(self.gpa, &st.map) catch return),
            .listener => self.follow(.route, tr.rdsNames(self.gpa, &st.map) catch return),
            else => {},
        }
    }

    /// Retries rejected responses of other types: they may fit now.
    fn retryRejected(self: *Client, accepted: tr.Kind) void {
        for (&self.types, 0..) |*t, i| {
            if (i == @intFromEnum(accepted)) continue;
            var r = t.rejected orelse continue;
            t.rejected = null;
            defer freePending(self.gpa, &r);
            log.info("retrying rejected {s} version '{s}'", .{ @tagName(r.kind), r.version });
            self.handle(&r);
        }
    }

    fn follow(self: *Client, kind: tr.Kind, wanted: std.ArrayList([]const u8)) void {
        var w = wanted;
        const st = &self.types[@intFromEnum(kind)];
        std.mem.sort([]const u8, w.items, {}, lessThan);
        if (sameNames(st.names.items, w.items)) {
            freeNames(self.gpa, &w);
            return;
        }
        freeNames(self.gpa, &st.names);
        st.names = w;
        self.subscribe(kind, null, null);
    }

    /// ACK (why == null) or NACK for the latest response of `kind`.
    fn request(self: *Client, kind: tr.Kind, why: ?[]const u8) void {
        self.subscribe(kind, self.types[@intFromEnum(kind)].nonce, why);
    }

    fn subscribe(self: *Client, kind: tr.Kind, nonce: ?[]const u8, why: ?[]const u8) void {
        const a = self.gpa;
        const st = &self.types[@intFromEnum(kind)];
        var node: c.Likzik__Xds__Node = undefined;
        c.likzik__xds__node__init(&node);
        node.id = self.node_id.ptr;
        node.cluster = self.node_cluster.ptr;
        node.user_agent_name = @constCast("likzik");
        var req: c.Likzik__Xds__DiscoveryRequest = undefined;
        c.likzik__xds__discovery_request__init(&req);
        req.node = &node;
        const version = a.dupeSentinel(u8, st.version, 0) catch return;
        defer a.free(version);
        req.version_info = version.ptr;
        req.type_url = @constCast(kind.typeUrl().ptr);
        const nz = a.dupeSentinel(u8, nonce orelse "", 0) catch return;
        defer a.free(nz);
        req.response_nonce = nz.ptr;
        var name_ptrs: std.ArrayList([*c]u8) = .empty;
        defer {
            for (name_ptrs.items) |p| a.free(std.mem.span(@as([*:0]u8, @ptrCast(p))));
            name_ptrs.deinit(a);
        }
        for (st.names.items) |n| {
            const z = a.dupeSentinel(u8, n, 0) catch return;
            name_ptrs.append(a, z.ptr) catch return;
        }
        req.n_resource_names = name_ptrs.items.len;
        req.resource_names = if (name_ptrs.items.len > 0) name_ptrs.items.ptr else null;
        var status: c.Likzik__Xds__Status = undefined;
        var msg: ?[:0]u8 = null;
        defer if (msg) |m| a.free(m);
        if (why) |w| {
            c.likzik__xds__status__init(&status);
            status.code = 3; // INVALID_ARGUMENT
            msg = a.dupeSentinel(u8, w, 0) catch return;
            status.message = msg.?.ptr;
            req.error_detail = &status;
        }
        const size = c.likzik__xds__discovery_request__get_packed_size(&req);
        const at = self.tx.items.len;
        self.tx.resize(a, at + 5 + size) catch return;
        self.tx.items[at] = 0; // not compressed
        std.mem.writeInt(u32, self.tx.items[at + 1 ..][0..4], @intCast(size), .big);
        _ = c.likzik__xds__discovery_request__pack(&req, self.tx.items[at + 5 ..].ptr);
        if (self.session) |s| _ = c.nghttp2_session_resume_data(s, self.stream_id);
    }

    /// Splits the received bytes into gRPC messages.
    fn takeMessages(self: *Client) bool {
        while (self.rx.items.len >= 5) {
            if (self.rx.items[0] != 0) return false; // compressed: not negotiated
            const len = std.mem.readInt(u32, self.rx.items[1..5], .big);
            if (len > max_message) return false;
            if (self.rx.items.len < 5 + len) return true;
            self.queueResponse(self.rx.items[5 .. 5 + len]);
            self.rx.replaceRange(self.gpa, 0, 5 + len, &.{}) catch return false;
        }
        return true;
    }

    fn queueResponse(self: *Client, bytes: []const u8) void {
        const a = self.gpa;
        const r = c.likzik__xds__discovery_response__unpack(null, bytes.len, bytes.ptr) orelse {
            log.warn("a DiscoveryResponse does not decode", .{});
            return;
        };
        defer c.likzik__xds__discovery_response__free_unpacked(r, null);
        const kind = tr.Kind.fromTypeUrl(std.mem.sliceTo(r.*.type_url, 0)) orelse {
            log.warn("ignoring resources of type {s}", .{std.mem.sliceTo(r.*.type_url, 0)});
            return;
        };
        var p: Pending = .{
            .kind = kind,
            .version = a.dupe(u8, std.mem.sliceTo(r.*.version_info, 0)) catch return,
            .nonce = a.dupe(u8, std.mem.sliceTo(r.*.nonce, 0)) catch return,
            .resources = .empty,
        };
        for (tr.items(@TypeOf(r.*.resources[0]), r.*.resources, r.*.n_resources)) |any| {
            const v = any.*.value;
            const copy = a.dupe(u8, if (v.len > 0) v.data[0..v.len] else &.{}) catch break;
            p.resources.append(a, copy) catch break;
        }
        // A newer response of the same type supersedes an unhandled one.
        for (self.pending.items, 0..) |*q, i| if (q.kind == kind) {
            freePending(a, q);
            _ = self.pending.orderedRemove(i);
            break;
        };
        self.pending.append(a, p) catch freePending(a, &p);
    }

    // ------------------------------------------------------------ nghttp2 callbacks

    fn from(ud: ?*anyopaque) *Client {
        return @ptrCast(@alignCast(ud.?));
    }

    fn onSend(_: ?*c.nghttp2_session, data: [*c]const u8, len: usize, _: c_int, ud: ?*anyopaque) callconv(.c) isize {
        const self = from(ud);
        const n = socket.writeNb(self.fd, data[0..len]) catch |e| switch (e) {
            error.WouldBlock => return c.NGHTTP2_ERR_WOULDBLOCK,
            error.SyscallFailed => return c.NGHTTP2_ERR_CALLBACK_FAILURE,
        };
        return @intCast(n);
    }

    fn onRead(_: ?*c.nghttp2_session, _: i32, buf: [*c]u8, len: usize, flags: [*c]u32, _: [*c]c.nghttp2_data_source, ud: ?*anyopaque) callconv(.c) isize {
        const self = from(ud);
        _ = flags;
        const avail = self.tx.items.len - self.tx_off;
        if (avail == 0) return c.NGHTTP2_ERR_DEFERRED;
        const n = @min(avail, len);
        @memcpy(buf[0..n], self.tx.items[self.tx_off .. self.tx_off + n]);
        self.tx_off += n;
        if (self.tx_off == self.tx.items.len) {
            self.tx.clearRetainingCapacity();
            self.tx_off = 0;
        }
        return @intCast(n);
    }

    fn onData(_: ?*c.nghttp2_session, _: u8, stream_id: i32, data: [*c]const u8, len: usize, ud: ?*anyopaque) callconv(.c) c_int {
        const self = from(ud);
        if (stream_id != self.stream_id) return 0;
        if (len == 0) return 0;
        self.rx.appendSlice(self.gpa, data[0..len]) catch return c.NGHTTP2_ERR_CALLBACK_FAILURE;
        if (!self.takeMessages()) return c.NGHTTP2_ERR_CALLBACK_FAILURE;
        return 0;
    }

    fn onStreamClose(_: ?*c.nghttp2_session, stream_id: i32, _: u32, ud: ?*anyopaque) callconv(.c) c_int {
        const self = from(ud);
        if (stream_id == self.stream_id) self.stream_open = false;
        return 0;
    }

    fn onHeader(_: ?*c.nghttp2_session, _: [*c]const c.nghttp2_frame, name: [*c]const u8, namelen: usize, value: [*c]const u8, valuelen: usize, _: u8, ud: ?*anyopaque) callconv(.c) c_int {
        const self = from(ud);
        const n = name[0..namelen];
        if (std.mem.eql(u8, n, "grpc-status") or std.mem.eql(u8, n, "grpc-message")) {
            const v = if (valuelen == 0) "" else value[0..valuelen];
            const room = self.grpc_status.len - self.grpc_status_len;
            const take = @min(room, v.len + 1);
            if (take > 0) {
                if (self.grpc_status_len > 0) {
                    self.grpc_status[self.grpc_status_len] = ' ';
                    self.grpc_status_len += 1;
                }
                const k = @min(v.len, self.grpc_status.len - self.grpc_status_len);
                @memcpy(self.grpc_status[self.grpc_status_len..][0..k], v[0..k]);
                self.grpc_status_len += k;
            }
        }
        return 0;
    }
};

fn nv(name: []const u8, value: []const u8) c.nghttp2_nv {
    return .{
        .name = @constCast(name.ptr),
        .value = @constCast(value.ptr),
        .namelen = name.len,
        .valuelen = value.len,
        .flags = c.NGHTTP2_NV_FLAG_NONE,
    };
}

fn setOwned(gpa: std.mem.Allocator, slot: *[]u8, v: []const u8) void {
    const copy = gpa.dupe(u8, v) catch return;
    gpa.free(slot.*);
    slot.* = copy;
}

fn clonePending(gpa: std.mem.Allocator, p: *const Pending) !Pending {
    var q: Pending = .{ .kind = p.kind, .version = try gpa.dupe(u8, p.version), .nonce = try gpa.dupe(u8, p.nonce), .resources = .empty };
    for (p.resources.items) |r| try q.resources.append(gpa, try gpa.dupe(u8, r));
    return q;
}

fn freePending(gpa: std.mem.Allocator, p: *Pending) void {
    gpa.free(p.version);
    gpa.free(p.nonce);
    for (p.resources.items) |r| gpa.free(r);
    p.resources.deinit(gpa);
}

fn freeNames(gpa: std.mem.Allocator, l: *std.ArrayList([]const u8)) void {
    for (l.items) |n| gpa.free(n);
    l.deinit(gpa);
    l.* = .empty;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn sameNames(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

fn sleepMs(ms: u64, stop: *std.atomic.Value(bool)) void {
    var left = ms;
    while (left > 0 and !stop.load(.acquire)) {
        const step: u64 = @min(left, 100);
        const ts: linux.timespec = .{ .sec = 0, .nsec = @intCast(step * std.time.ns_per_ms) };
        _ = linux.nanosleep(&ts, null);
        left -= step;
    }
}
