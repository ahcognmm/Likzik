//! File config source: read the JSON file, and watch its directory with
//! inotify so edits (including atomic rename-into-place, as editors and
//! GitOps tools do) trigger a reload. The last valid config keeps running
//! when a new one fails validation.

const std = @import("std");
const linux = std.os.linux;
const socket = @import("../../net/socket.zig");

pub fn readFile(gpa: std.mem.Allocator, path: []const u8) ![]u8 {
    var pbuf: [4096]u8 = undefined;
    if (path.len >= pbuf.len) return error.NameTooLong;
    @memcpy(pbuf[0..path.len], path);
    pbuf[path.len] = 0;
    const rc = linux.open(@ptrCast(&pbuf), .{ .CLOEXEC = true }, 0);
    const fd: linux.fd_t = @intCast(socket.check(rc) catch return error.FileNotFound);
    defer socket.closeFd(fd);
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    while (true) {
        try list.ensureUnusedCapacity(gpa, 64 * 1024);
        const dst = list.unusedCapacitySlice();
        const n = socket.check(linux.read(fd, dst.ptr, dst.len)) catch return error.ReadFailed;
        if (n == 0) break;
        list.items.len += n;
        if (list.items.len > 64 * 1024 * 1024) return error.FileTooBig;
    }
    return list.toOwnedSlice(gpa);
}

pub const Watcher = struct {
    fd: linux.fd_t,
    file_name: []const u8,

    pub fn init(path: []const u8) !Watcher {
        const fd: linux.fd_t = @intCast(try socket.check(linux.inotify_init1(linux.IN.CLOEXEC | linux.IN.NONBLOCK)));
        errdefer socket.closeFd(fd);
        const slash = std.mem.lastIndexOfScalar(u8, path, '/');
        const dir = if (slash) |s| (if (s == 0) "/" else path[0..s]) else ".";
        const name = if (slash) |s| path[s + 1 ..] else path;
        var dbuf: [4096]u8 = undefined;
        if (dir.len >= dbuf.len) return error.NameTooLong;
        @memcpy(dbuf[0..dir.len], dir);
        dbuf[dir.len] = 0;
        const mask = linux.IN.CLOSE_WRITE | linux.IN.MOVED_TO | linux.IN.CREATE;
        _ = try socket.check(linux.inotify_add_watch(fd, @ptrCast(&dbuf), mask));
        return .{ .fd = fd, .file_name = name };
    }

    pub fn deinit(self: *Watcher) void {
        socket.closeFd(self.fd);
    }

    /// Drains pending events; true if the config file was touched.
    pub fn changed(self: *Watcher) bool {
        var buf: [4096]u8 align(@alignOf(linux.inotify_event)) = undefined;
        var hit = false;
        while (true) {
            const rc = linux.read(self.fd, &buf, buf.len);
            if (linux.errno(rc) != .SUCCESS or rc == 0) break;
            var off: usize = 0;
            while (off + @sizeOf(linux.inotify_event) <= rc) {
                const ev: *const linux.inotify_event = @ptrCast(@alignCast(&buf[off]));
                const name_start = off + @sizeOf(linux.inotify_event);
                const raw = buf[name_start .. name_start + ev.len];
                const name = std.mem.sliceTo(raw, 0);
                if (std.mem.eql(u8, name, self.file_name)) hit = true;
                off = name_start + ev.len;
            }
        }
        return hit;
    }
};
