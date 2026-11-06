//! likzik-ui: a small web dashboard for likzik / likzik-gw.
//!
//! It runs next to the proxy and needs no changes to it:
//!   * status and counters come from the proxy's admin endpoint
//!     (/server_info, /stats, /metrics), proxied through /api/admin/*;
//!   * configuration is the proxy's config file. An edit is validated by
//!     running `<proxy binary> --check` on a candidate file next to the
//!     real one, then atomically renamed into place; the proxy's inotify
//!     watcher applies it, and the UI waits for the new generation.
//!
//! Security: binds 127.0.0.1 by default. Binding any other address
//! requires --token; API calls then need "Authorization: Bearer <token>".
//! The config can hold secrets (HS256 secrets, plain API keys), so treat
//! access to the UI like access to the config file.

const std = @import("std");
const linux = std.os.linux;
const likzik = @import("likzik");
const Address = likzik.net.addr.Address;
const socket = likzik.net.socket;
const file_watch = likzik.config.file_watch;

const index_html = @embedFile("index.html");

pub const std_options: std.Options = .{ .log_level = .info };
const log = std.log.scoped(.ui);

const usage =
    \\usage: likzik-ui -c CONFIG [options]
    \\
    \\  -c, --config PATH   the proxy's config file (required)
    \\  -l, --listen ADDR   dashboard address (default 127.0.0.1:9902)
    \\      --admin ADDR    proxy admin endpoint (default: admin.address in the config)
    \\      --proxy PATH    proxy binary used for --check (default: likzik-gw next to likzik-ui)
    \\      --token TOKEN   require "Authorization: Bearer TOKEN" on the API
    \\                      (mandatory when listening on a non-loopback address)
    \\
;

const Opts = struct {
    config: []const u8 = "",
    listen: []const u8 = "127.0.0.1:9902",
    admin: ?[]const u8 = null,
    proxy: ?[]const u8 = null,
    token: ?[]const u8 = null,
};

const max_body = 4 * 1024 * 1024;

const Server = struct {
    gpa: std.mem.Allocator,
    opts: Opts,
    proxy_bin: [:0]const u8,
    admin_addr: ?Address,
};

pub fn main(init: std.process.Init) !u8 {
    const gpa = std.heap.smp_allocator;
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);
    var o: Opts = .{};
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        const val = if (i + 1 < argv.len) argv[i + 1] else "";
        if (std.mem.eql(u8, a, "-c") or std.mem.eql(u8, a, "--config")) {
            o.config = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "-l") or std.mem.eql(u8, a, "--listen")) {
            o.listen = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--admin")) {
            o.admin = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--proxy")) {
            o.proxy = val;
            i += 1;
        } else if (std.mem.eql(u8, a, "--token")) {
            o.token = val;
            i += 1;
        } else {
            std.debug.print("{s}", .{usage});
            return 2;
        }
    }
    if (o.config.len == 0) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    const listen = Address.parse(o.listen) catch {
        log.err("invalid --listen address '{s}'", .{o.listen});
        return 2;
    };
    if (!isLoopback(&listen) and o.token == null) {
        log.err("refusing to listen on {s} without --token (the API can change the proxy's config)", .{o.listen});
        return 2;
    }

    // Proxy binary for validation: --proxy, else likzik-gw next to us.
    var bin_buf: [4096]u8 = undefined;
    const proxy_bin: [:0]const u8 = if (o.proxy) |p| try arena.dupeSentinel(u8, p, 0) else blk: {
        const n = linux.readlink("/proc/self/exe", &bin_buf, bin_buf.len);
        if (linux.errno(n) != .SUCCESS) return error.CannotFindSelf;
        const self_path = bin_buf[0..n];
        const dir = std.fs.path.dirname(self_path) orelse ".";
        break :blk try std.fmt.allocPrintSentinel(arena, "{s}/likzik-gw", .{dir}, 0);
    };

    var srv: Server = .{ .gpa = gpa, .opts = o, .proxy_bin = proxy_bin, .admin_addr = null };
    srv.admin_addr = resolveAdmin(&srv);
    if (srv.admin_addr == null) log.warn("no admin address (config has no 'admin' and no --admin): status views will be empty", .{});

    const lfd = socket.listen(&listen, 64) catch {
        log.err("cannot listen on {s}: {s}", .{ o.listen, @tagName(socket.last_errno) });
        return 1;
    };
    // The listener is non-blocking (shared helper); accept in a poll loop.
    log.info("dashboard on http://{s}/ (config {s}, validator {s})", .{ o.listen, o.config, proxy_bin });
    while (true) {
        var pfd = [_]linux.pollfd{.{ .fd = lfd, .events = linux.POLL.IN, .revents = 0 }};
        _ = linux.poll(&pfd, 1, -1);
        const rc = linux.accept4(lfd, null, null, linux.SOCK.CLOEXEC);
        const fd: linux.fd_t = @intCast(socket.check(rc) catch continue);
        handle(&srv, fd);
        socket.closeFd(fd);
    }
}

fn isLoopback(a: *const Address) bool {
    if (a.family() == linux.AF.INET) return (@as([4]u8, @bitCast(a.in4.addr)))[0] == 127;
    var lo: [16]u8 = @splat(0);
    lo[15] = 1;
    return std.mem.eql(u8, &a.in6.addr, &lo);
}

fn resolveAdmin(srv: *Server) ?Address {
    if (srv.opts.admin) |a| return Address.parse(a) catch null;
    const text = file_watch.readFile(srv.gpa, srv.opts.config) catch return null;
    defer srv.gpa.free(text);
    var arena: std.heap.ArenaAllocator = .init(srv.gpa);
    defer arena.deinit();
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), text, .{}) catch return null;
    if (v != .object) return null;
    const admin = v.object.get("admin") orelse return null;
    if (admin != .object) return null;
    const addr = admin.object.get("address") orelse return null;
    if (addr != .string) return null;
    return Address.parse(addr.string) catch null;
}

// ---------------------------------------------------------------- HTTP

const Request = struct {
    method: []const u8,
    path: []const u8,
    auth: ?[]const u8 = null,
    if_match: ?[]const u8 = null,
    body: []const u8 = "",
};

fn setTimeouts(fd: linux.fd_t, secs: isize) void {
    const tv: linux.timeval = .{ .sec = secs, .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
}

fn readRequest(gpa: std.mem.Allocator, fd: linux.fd_t, buf: *std.ArrayList(u8)) !?Request {
    var head_end: ?usize = null;
    while (head_end == null) {
        try buf.ensureUnusedCapacity(gpa, 16 * 1024);
        const dst = buf.unusedCapacitySlice();
        const n = socket.check(linux.read(fd, dst.ptr, dst.len)) catch return null;
        if (n == 0) return null;
        buf.items.len += n;
        if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |e| head_end = e + 4;
        if (buf.items.len > 64 * 1024 and head_end == null) return null;
    }
    const head = buf.items[0..head_end.?];
    const line_end = std.mem.indexOf(u8, head, "\r\n").?;
    var it = std.mem.splitScalar(u8, head[0..line_end], ' ');
    var req: Request = .{ .method = it.next() orelse return null, .path = it.next() orelse return null };
    var content_length: usize = 0;
    var lines = std.mem.splitSequence(u8, head[line_end + 2 ..], "\r\n");
    while (lines.next()) |l| {
        const colon = std.mem.indexOfScalar(u8, l, ':') orelse continue;
        const name = l[0..colon];
        const value = std.mem.trim(u8, l[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch return null;
        } else if (std.ascii.eqlIgnoreCase(name, "authorization")) {
            req.auth = value;
        } else if (std.ascii.eqlIgnoreCase(name, "if-match")) {
            req.if_match = std.mem.trim(u8, value, "\"");
        }
    }
    if (content_length > max_body) return null;
    while (buf.items.len < head_end.? + content_length) {
        try buf.ensureUnusedCapacity(gpa, content_length);
        const dst = buf.unusedCapacitySlice();
        const n = socket.check(linux.read(fd, dst.ptr, dst.len)) catch return null;
        if (n == 0) return null;
        buf.items.len += n;
    }
    // Slices into buf: re-slice after all reads (buf may have moved).
    const h = buf.items[0..head_end.?];
    const le = std.mem.indexOf(u8, h, "\r\n").?;
    var it2 = std.mem.splitScalar(u8, h[0..le], ' ');
    req.method = it2.next().?;
    req.path = it2.next().?;
    if (req.auth != null or req.if_match != null) {
        var ls = std.mem.splitSequence(u8, h[le + 2 ..], "\r\n");
        while (ls.next()) |l| {
            const colon = std.mem.indexOfScalar(u8, l, ':') orelse continue;
            const name = l[0..colon];
            const value = std.mem.trim(u8, l[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "authorization")) req.auth = value;
            if (std.ascii.eqlIgnoreCase(name, "if-match")) req.if_match = std.mem.trim(u8, value, "\"");
        }
    }
    req.body = buf.items[head_end.? .. head_end.? + content_length];
    return req;
}

fn writeAll(fd: linux.fd_t, data: []const u8) void {
    var off: usize = 0;
    while (off < data.len) {
        const n = socket.check(linux.write(fd, data[off..].ptr, data.len - off)) catch return;
        off += n;
    }
}

fn respond(fd: linux.fd_t, status: u16, ctype: []const u8, extra: []const u8, body: []const u8) void {
    var head: [512]u8 = undefined;
    const reason = switch (status) {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Content Too Large",
        502 => "Bad Gateway",
        else => "Error",
    };
    const h = std.fmt.bufPrint(&head, "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n{s}\r\n", .{ status, reason, ctype, body.len, extra }) catch return;
    writeAll(fd, h);
    writeAll(fd, body);
}

fn respondJson(srv: *Server, fd: linux.fd_t, status: u16, value: anytype) void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(srv.gpa);
    out.print(srv.gpa, "{f}", .{std.json.fmt(value, .{})}) catch return;
    respond(fd, status, "application/json", "", out.items);
}

fn authorized(srv: *Server, req: *const Request) bool {
    const token = srv.opts.token orelse return true;
    const got = req.auth orelse return false;
    if (got.len < 7 or !std.ascii.eqlIgnoreCase(got[0..7], "Bearer ")) return false;
    const t = got[7..];
    if (t.len != token.len) return false;
    var diff: u8 = 0;
    for (t, token) |x, y| diff |= x ^ y;
    return diff == 0;
}

fn handle(srv: *Server, fd: linux.fd_t) void {
    setTimeouts(fd, 5);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(srv.gpa);
    const req = (readRequest(srv.gpa, fd, &buf) catch null) orelse return respond(fd, 400, "text/plain", "", "bad request\n");
    const path = if (std.mem.indexOfScalar(u8, req.path, '?')) |q| req.path[0..q] else req.path;
    const get = std.mem.eql(u8, req.method, "GET");

    if (get and (std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, "/index.html"))) {
        return respond(fd, 200, "text/html; charset=utf-8", "Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; frame-ancestors 'none'\r\n", index_html);
    }
    if (!std.mem.startsWith(u8, path, "/api/")) return respond(fd, 404, "text/plain", "", "not found\n");
    if (!authorized(srv, &req)) return respond(fd, 401, "application/json", "", "{\"error\":\"unauthorized\"}");

    if (get and std.mem.eql(u8, path, "/api/info")) {
        return respondJson(srv, fd, 200, .{ .config_path = srv.opts.config, .validator = srv.proxy_bin, .admin = srv.admin_addr != null, .token_required = srv.opts.token != null });
    }
    if (get and std.mem.eql(u8, path, "/api/config")) return getConfig(srv, fd);
    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, path, "/api/validate")) return validateOnly(srv, fd, req.body);
    if (std.mem.eql(u8, req.method, "PUT") and std.mem.eql(u8, path, "/api/config")) return applyConfig(srv, fd, &req);
    if (std.mem.startsWith(u8, path, "/api/admin/")) return proxyAdmin(srv, fd, req.method, path["/api/admin".len..]);
    respond(fd, 404, "application/json", "", "{\"error\":\"not found\"}");
}

// ---------------------------------------------------------------- config

fn etagOf(text: []const u8) [16]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &h, .{});
    var out: [16]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{h[0..8].*}) catch unreachable;
    return out;
}

fn getConfig(srv: *Server, fd: linux.fd_t) void {
    const text = file_watch.readFile(srv.gpa, srv.opts.config) catch
        return respondJson(srv, fd, 502, .{ .@"error" = "cannot read the config file" });
    defer srv.gpa.free(text);
    const etag = etagOf(text);
    respondJson(srv, fd, 200, .{ .path = srv.opts.config, .etag = &etag, .text = text });
}

const Check = struct { ok: bool, output: []const u8 };

fn zpath(buf: []u8, s: []const u8) ?[*:0]const u8 {
    if (s.len >= buf.len) return null;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return @ptrCast(buf.ptr);
}

fn candidatePath(srv: *Server, buf: []u8) ?[]const u8 {
    const dir = std.fs.path.dirname(srv.opts.config) orelse ".";
    const base = std.fs.path.basename(srv.opts.config);
    return std.fmt.bufPrint(buf, "{s}/.{s}.likzik-ui.tmp", .{ dir, base }) catch null;
}

fn writeFile(path: []const u8, data: []const u8) bool {
    var pb: [4096]u8 = undefined;
    const z = zpath(&pb, path) orelse return false;
    const rc = linux.open(z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o600);
    const fd: linux.fd_t = @intCast(socket.check(rc) catch return false);
    defer socket.closeFd(fd);
    var off: usize = 0;
    while (off < data.len) {
        const n = socket.check(linux.write(fd, data[off..].ptr, data.len - off)) catch return false;
        off += n;
    }
    return linux.errno(linux.fsync(fd)) == .SUCCESS;
}

/// Runs `<proxy> -c <path> --check` and captures its output.
fn runCheck(srv: *Server, path: []const u8, out: *std.ArrayList(u8)) bool {
    var pb: [4096]u8 = undefined;
    const zp = zpath(&pb, path) orelse return false;
    var fds: [2]linux.fd_t = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return false;
    const argv = [_:null]?[*:0]const u8{ srv.proxy_bin.ptr, "-c", zp, "--check" };
    const envp = [_:null]?[*:0]const u8{};
    const pid_rc = linux.fork();
    if (linux.errno(pid_rc) != .SUCCESS) {
        socket.closeFd(fds[0]);
        socket.closeFd(fds[1]);
        return false;
    }
    if (pid_rc == 0) {
        _ = linux.dup2(fds[1], 1);
        _ = linux.dup2(fds[1], 2);
        _ = linux.execve(srv.proxy_bin.ptr, &argv, &envp);
        linux.exit(127);
    }
    socket.closeFd(fds[1]);
    var tmp: [4096]u8 = undefined;
    while (true) {
        const n = linux.read(fds[0], &tmp, tmp.len);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        out.appendSlice(srv.gpa, tmp[0..n]) catch break;
        if (out.items.len > 64 * 1024) break;
    }
    socket.closeFd(fds[0]);
    var status: i32 = 0;
    _ = linux.waitpid(@intCast(pid_rc), &status, 0);
    const st: u32 = @bitCast(status);
    const exited = (st & 0x7f) == 0;
    const code = (st >> 8) & 0xff;
    if (exited and code == 127 and out.items.len == 0) {
        out.appendSlice(srv.gpa, "cannot run the validator (") catch {};
        out.appendSlice(srv.gpa, srv.proxy_bin) catch {};
        out.appendSlice(srv.gpa, "); pass --proxy") catch {};
    }
    return exited and code == 0;
}

fn validateText(srv: *Server, text: []const u8, out: *std.ArrayList(u8)) bool {
    var cb: [4096]u8 = undefined;
    const cand = candidatePath(srv, &cb) orelse return false;
    if (!writeFile(cand, text)) {
        out.appendSlice(srv.gpa, "cannot write a candidate file next to the config") catch {};
        return false;
    }
    defer {
        var pb: [4096]u8 = undefined;
        if (zpath(&pb, cand)) |z| _ = linux.unlink(z);
    }
    return runCheck(srv, cand, out);
}

/// The validator's message without log-level prefixes and file paths.
fn cleanOutput(s: []const u8) []const u8 {
    var t = std.mem.trim(u8, s, " \r\n");
    if (std.mem.lastIndexOf(u8, t, ".likzik-ui.tmp: ")) |i| t = t[i + ".likzik-ui.tmp: ".len ..];
    return t;
}

fn validateOnly(srv: *Server, fd: linux.fd_t, body: []const u8) void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(srv.gpa);
    const ok = validateText(srv, body, &out);
    respondJson(srv, fd, 200, .{ .ok = ok, .message = cleanOutput(out.items) });
}

fn applyConfig(srv: *Server, fd: linux.fd_t, req: *const Request) void {
    const current = file_watch.readFile(srv.gpa, srv.opts.config) catch
        return respondJson(srv, fd, 502, .{ .ok = false, .message = "cannot read the config file" });
    defer srv.gpa.free(current);
    const etag = etagOf(current);
    if (req.if_match) |want| if (!std.mem.eql(u8, want, &etag))
        return respondJson(srv, fd, 409, .{ .ok = false, .message = "the config file changed since it was loaded; reload and re-apply" });

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(srv.gpa);
    if (!validateText(srv, req.body, &out))
        return respondJson(srv, fd, 400, .{ .ok = false, .message = cleanOutput(out.items) });

    const gen_before = adminGeneration(srv);
    // Keep the previous version, then swap the new one in atomically.
    var bb: [4096]u8 = undefined;
    const bak = std.fmt.bufPrint(&bb, "{s}.bak", .{srv.opts.config}) catch "";
    _ = writeFile(bak, current);
    var cb: [4096]u8 = undefined;
    const cand = candidatePath(srv, &cb) orelse return respondJson(srv, fd, 500, .{ .ok = false, .message = "path too long" });
    if (!writeFile(cand, req.body)) return respondJson(srv, fd, 500, .{ .ok = false, .message = "cannot write the candidate file" });
    var p1: [4096]u8 = undefined;
    var p2: [4096]u8 = undefined;
    if (linux.errno(linux.rename(zpath(&p1, cand).?, zpath(&p2, srv.opts.config).?)) != .SUCCESS)
        return respondJson(srv, fd, 500, .{ .ok = false, .message = "cannot replace the config file" });
    log.info("config written ({d} bytes), previous version in {s}", .{ req.body.len, bak });

    // Wait for the proxy to pick it up (inotify), up to 3 s.
    const new_etag = etagOf(req.body);
    var waited: u32 = 0;
    while (waited < 30) : (waited += 1) {
        const g = adminGeneration(srv);
        if (gen_before != null and g != null and g.? > gen_before.?)
            return respondJson(srv, fd, 200, .{ .ok = true, .applied = true, .generation = g.?, .etag = &new_etag, .message = "applied" });
        const ts: linux.timespec = .{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
        _ = linux.nanosleep(&ts, null);
    }
    respondJson(srv, fd, 200, .{ .ok = true, .applied = false, .etag = &new_etag, .message = "written; the proxy has not reported a new generation (is it running and watching this file?)" });
}

// ---------------------------------------------------------------- admin proxy

fn adminRequest(srv: *Server, method: []const u8, path: []const u8, out: *std.ArrayList(u8)) ?u16 {
    const a = srv.admin_addr orelse return null;
    const rc = linux.socket(a.family(), linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    const fd: linux.fd_t = @intCast(socket.check(rc) catch return null);
    defer socket.closeFd(fd);
    setTimeouts(fd, 3);
    if (linux.errno(linux.connect(fd, &a.any, a.len())) != .SUCCESS) return null;
    var req: [512]u8 = undefined;
    const r = std.fmt.bufPrint(&req, "{s} {s} HTTP/1.1\r\nHost: admin\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{ method, path }) catch return null;
    writeAll(fd, r);
    var tmp: [16384]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &tmp, tmp.len);
        if (linux.errno(n) != .SUCCESS or n == 0) break;
        out.appendSlice(srv.gpa, tmp[0..n]) catch return null;
    }
    if (out.items.len < 12 or !std.mem.startsWith(u8, out.items, "HTTP/1.")) return null;
    return std.fmt.parseInt(u16, out.items[9..12], 10) catch null;
}

fn adminGeneration(srv: *Server) ?u64 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(srv.gpa);
    _ = adminRequest(srv, "GET", "/server_info", &out) orelse return null;
    const i = std.mem.indexOf(u8, out.items, "\"generation\":") orelse return null;
    var j = i + "\"generation\":".len;
    var v: u64 = 0;
    while (j < out.items.len and out.items[j] >= '0' and out.items[j] <= '9') : (j += 1) v = v * 10 + (out.items[j] - '0');
    return v;
}

fn proxyAdmin(srv: *Server, fd: linux.fd_t, method: []const u8, path: []const u8) void {
    const allowed = [_][]const u8{ "/server_info", "/stats", "/metrics", "/ready" };
    var ok = false;
    for (allowed) |p| if (std.mem.eql(u8, p, path)) {
        ok = true;
    };
    if (!ok or !std.mem.eql(u8, method, "GET")) return respond(fd, 404, "application/json", "", "{\"error\":\"not found\"}");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(srv.gpa);
    const status = adminRequest(srv, "GET", path, &out) orelse
        return respond(fd, 502, "application/json", "", "{\"error\":\"proxy admin endpoint unreachable\"}");
    const body_start = (std.mem.indexOf(u8, out.items, "\r\n\r\n") orelse return respond(fd, 502, "text/plain", "", "")) + 4;
    const ctype = if (std.mem.eql(u8, path, "/server_info")) "application/json" else "text/plain";
    respond(fd, status, ctype, "", out.items[body_start..]);
}
