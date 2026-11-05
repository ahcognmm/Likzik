//! Load balancing. All policies run per worker on worker-local state.
//!
//! * least_request (default): power of two choices on in-flight requests,
//!   weighted (compare active/weight).
//! * round_robin: smooth weighted round robin (nginx's algorithm).
//! * random: weighted random.
//!
//! Ejected endpoints are skipped unless every endpoint is ejected (panic
//! mode: then all are eligible, as in Envoy).

const std = @import("std");
const snapshot = @import("../config/snapshot.zig");
const health = @import("health.zig");

pub const Ctx = struct {
    gpa: std.mem.Allocator,
    eps: *health.Table,
    rng: std.Random,
    now_ms: u64,
};

fn eligible(ctx: *Ctx, e: *const snapshot.Endpoint, exclude: ?u32, panic: bool) !bool {
    if (exclude) |x| if (x == e.id) return false;
    if (panic) return true;
    return (try ctx.eps.get(ctx.gpa, e.id)).healthy(ctx.now_ms);
}

pub fn pick(ctx: *Ctx, c: *const snapshot.Cluster, exclude: ?u32) !?*const snapshot.Endpoint {
    const eps = c.endpoints;
    if (eps.len == 1) {
        return if (exclude != null and exclude.? == eps[0].id) null else &eps[0];
    }
    // Panic mode when nothing (besides the excluded one) is healthy.
    var any_healthy = false;
    for (eps) |*e| if (try eligible(ctx, e, exclude, false)) {
        any_healthy = true;
        break;
    };
    const panic = !any_healthy;
    return switch (c.lb) {
        .least_request => p2c(ctx, c, exclude, panic),
        .round_robin => smoothWrr(ctx, c, exclude, panic),
        .random => weightedRandom(ctx, c, exclude, panic),
    };
}

fn weightedRandom(ctx: *Ctx, c: *const snapshot.Cluster, exclude: ?u32, panic: bool) !?*const snapshot.Endpoint {
    var total: u64 = 0;
    for (c.endpoints) |*e| if (try eligible(ctx, e, exclude, panic)) {
        total += e.weight;
    };
    if (total == 0) return null;
    var r = ctx.rng.uintLessThan(u64, total);
    for (c.endpoints) |*e| if (try eligible(ctx, e, exclude, panic)) {
        if (r < e.weight) return e;
        r -= e.weight;
    };
    unreachable;
}

fn p2c(ctx: *Ctx, c: *const snapshot.Cluster, exclude: ?u32, panic: bool) !?*const snapshot.Endpoint {
    const a = (try weightedRandom(ctx, c, exclude, panic)) orelse return null;
    var b = a;
    var tries: u8 = 0;
    while (b == a and tries < 4) : (tries += 1) {
        b = (try weightedRandom(ctx, c, exclude, panic)).?;
    }
    if (a == b) return a;
    const sa = try ctx.eps.get(ctx.gpa, a.id);
    const sb = try ctx.eps.get(ctx.gpa, b.id);
    // Compare active/weight without division.
    const la = @as(u64, sa.active) * b.weight;
    const lb = @as(u64, sb.active) * a.weight;
    return if (la <= lb) a else b;
}

fn smoothWrr(ctx: *Ctx, c: *const snapshot.Cluster, exclude: ?u32, panic: bool) !?*const snapshot.Endpoint {
    var best: ?*const snapshot.Endpoint = null;
    var best_cur: i64 = std.math.minInt(i64);
    var total: i64 = 0;
    for (c.endpoints) |*e| {
        if (!try eligible(ctx, e, exclude, panic)) continue;
        const st = try ctx.eps.get(ctx.gpa, e.id);
        st.rr_current += e.weight;
        total += e.weight;
        if (st.rr_current > best_cur) {
            best_cur = st.rr_current;
            best = e;
        }
    }
    if (best) |b| (try ctx.eps.get(ctx.gpa, b.id)).rr_current -= total;
    return best;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn mkCluster(eps: []snapshot.Endpoint, lb: anytype) snapshot.Cluster {
    var total: u32 = 0;
    for (eps) |e| total += e.weight;
    return .{ .name = "c", .id = 0, .lb = lb, .connect_timeout_ms = 1, .idle_timeout_ms = 1, .max_idle_per_endpoint = 1, .max_connect_attempts = 2, .eject_after_failures = 3, .eject_ms = 1000, .endpoints = eps, .total_weight = total };
}

fn ep(id: u32, w: u32) snapshot.Endpoint {
    return .{ .addr = undefined, .weight = w, .id = id, .text = "" };
}

test "smooth weighted round robin distribution" {
    var eps = [_]snapshot.Endpoint{ ep(0, 5), ep(1, 1), ep(2, 1) };
    const c = mkCluster(&eps, .round_robin);
    var table: health.Table = .{};
    defer table.deinit(testing.allocator);
    var prng = std.Random.DefaultPrng.init(1);
    var ctx: Ctx = .{ .gpa = testing.allocator, .eps = &table, .rng = prng.random(), .now_ms = 0 };
    var counts = [_]u32{ 0, 0, 0 };
    for (0..70) |_| counts[(try pick(&ctx, &c, null)).?.id] += 1;
    try testing.expectEqual([_]u32{ 50, 10, 10 }, counts);
}

test "p2c prefers the less loaded endpoint" {
    var eps = [_]snapshot.Endpoint{ ep(0, 1), ep(1, 1) };
    const c = mkCluster(&eps, .least_request);
    var table: health.Table = .{};
    defer table.deinit(testing.allocator);
    var prng = std.Random.DefaultPrng.init(2);
    var ctx: Ctx = .{ .gpa = testing.allocator, .eps = &table, .rng = prng.random(), .now_ms = 0 };
    (try table.get(testing.allocator, 0)).active = 10;
    var to1: u32 = 0;
    for (0..100) |_| {
        if ((try pick(&ctx, &c, null)).?.id == 1) to1 += 1;
    }
    try testing.expect(to1 >= 70);
}

test "ejected endpoints are skipped, panic mode when all are down, exclude works" {
    var eps = [_]snapshot.Endpoint{ ep(0, 1), ep(1, 1) };
    const c = mkCluster(&eps, .random);
    var table: health.Table = .{};
    defer table.deinit(testing.allocator);
    var prng = std.Random.DefaultPrng.init(3);
    var ctx: Ctx = .{ .gpa = testing.allocator, .eps = &table, .rng = prng.random(), .now_ms = 0 };
    (try table.get(testing.allocator, 0)).ejected_until_ms = 1000;
    for (0..20) |_| try testing.expectEqual(@as(u32, 1), (try pick(&ctx, &c, null)).?.id);
    (try table.get(testing.allocator, 1)).ejected_until_ms = 1000;
    var seen0 = false;
    for (0..50) |_| {
        if ((try pick(&ctx, &c, null)).?.id == 0) seen0 = true;
    }
    try testing.expect(seen0);
    for (0..20) |_| try testing.expectEqual(@as(u32, 0), (try pick(&ctx, &c, 1)).?.id);
    var one = [_]snapshot.Endpoint{ep(7, 1)};
    const c1 = mkCluster(&one, .random);
    try testing.expect((try pick(&ctx, &c1, 7)) == null);
}
