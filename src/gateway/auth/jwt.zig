//! JWT (JWS compact) verification with keys from a JWKS document.
//!
//! * Algorithms: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384,
//!   EdDSA (Ed25519). All verification uses Zig's std.crypto: no FFI, no
//!   allocation outside the per-request scratch buffer.
//! * The provider's `algorithms` list is enforced before any key is used;
//!   "none" is never accepted, and a key is only used with algorithms of
//!   its own type (an RSA key can never verify an HS256 token).
//! * Claims: exp/nbf with leeway, iss, aud (string or array). `crit`
//!   headers are rejected (no extensions are understood).
//!
//! Keys are parsed once, when the config snapshot is compiled.

const std = @import("std");
const crypto = std.crypto;
const rsa = crypto.Certificate.rsa;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;
const Sha512 = crypto.hash.sha2.Sha512;
const EcP256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const EcP384 = crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = crypto.sign.Ed25519;
const b64 = std.base64.url_safe_no_pad;

pub const Alg = enum(u4) { HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA };

pub const AlgSet = std.EnumSet(Alg);

pub fn parseAlg(s: []const u8) ?Alg {
    return std.meta.stringToEnum(Alg, s);
}

const RsaKey = struct { pk: rsa.PublicKey, modulus_len: usize };

pub const KeyMaterial = union(enum) {
    rsa: RsaKey,
    p256: EcP256.PublicKey,
    p384: EcP384.PublicKey,
    ed25519: Ed25519.PublicKey,
    hmac: []const u8,

    fn fits(self: KeyMaterial, alg: Alg) bool {
        return switch (alg) {
            .HS256, .HS384, .HS512 => self == .hmac,
            .RS256, .RS384, .RS512, .PS256, .PS384, .PS512 => self == .rsa,
            .ES256 => self == .p256,
            .ES384 => self == .p384,
            .EdDSA => self == .ed25519,
        };
    }
};

pub const Key = struct {
    kid: ?[]const u8,
    /// The JWK's own `alg`, when given: the key is restricted to it.
    alg: ?Alg,
    material: KeyMaterial,
};

pub const ClaimHeader = struct { claim: []const u8, header: []const u8 };

pub const Provider = struct {
    name: []const u8,
    algs: AlgSet,
    issuer: ?[]const u8,
    audiences: []const []const u8,
    keys: []const Key,
    leeway_s: i64,
    require_exp: bool,
    consumer_claim: []const u8,
    claims_to_headers: []const ClaimHeader,
    header: []const u8,
    query: ?[]const u8,
    forward_token: bool,
};

// ---------------------------------------------------------------- key loading

pub const LoadError = error{ InvalidJwks, OutOfMemory };

fn decodeB64(arena: std.mem.Allocator, s: []const u8) LoadError![]u8 {
    const n = b64.Decoder.calcSizeForSlice(s) catch return error.InvalidJwks;
    const out = try arena.alloc(u8, n);
    b64.Decoder.decode(out, s) catch return error.InvalidJwks;
    return out;
}

fn str(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = obj.get(name) orelse return null;
    return if (v == .string) v.string else null;
}

/// Parses a JWKS document ({"keys": [...]}). Keys with "use" other than
/// "sig" are skipped. `why` receives a short reason on error.
pub fn loadJwks(arena: std.mem.Allocator, doc: std.json.Value, out: *std.ArrayList(Key), why: *[]const u8) LoadError!void {
    if (doc != .object) {
        why.* = "JWKS must be an object";
        return error.InvalidJwks;
    }
    const keys = doc.object.get("keys") orelse {
        why.* = "JWKS has no 'keys' array";
        return error.InvalidJwks;
    };
    if (keys != .array) {
        why.* = "JWKS 'keys' must be an array";
        return error.InvalidJwks;
    }
    for (keys.array.items) |k| {
        if (k != .object) {
            why.* = "JWK must be an object";
            return error.InvalidJwks;
        }
        const o = k.object;
        if (str(o, "use")) |u| if (!std.mem.eql(u8, u, "sig")) continue;
        const kty = str(o, "kty") orelse {
            why.* = "JWK without 'kty'";
            return error.InvalidJwks;
        };
        var key: Key = .{
            .kid = if (str(o, "kid")) |s| try arena.dupe(u8, s) else null,
            .alg = if (str(o, "alg")) |s| parseAlg(s) else null,
            .material = undefined,
        };
        if (std.mem.eql(u8, kty, "RSA")) {
            const n_raw = try decodeB64(arena, str(o, "n") orelse return badKey(why, "RSA JWK without 'n'"));
            const e = try decodeB64(arena, str(o, "e") orelse return badKey(why, "RSA JWK without 'e'"));
            const n = std.mem.trimStart(u8, n_raw, &.{0});
            if (n.len != 256 and n.len != 384 and n.len != 512) return badKey(why, "RSA key must be 2048, 3072 or 4096 bits");
            const pk = rsa.PublicKey.fromBytes(e, n) catch return badKey(why, "invalid RSA key");
            key.material = .{ .rsa = .{ .pk = pk, .modulus_len = n.len } };
        } else if (std.mem.eql(u8, kty, "EC")) {
            const crv = str(o, "crv") orelse return badKey(why, "EC JWK without 'crv'");
            const x = try decodeB64(arena, str(o, "x") orelse return badKey(why, "EC JWK without 'x'"));
            const y = try decodeB64(arena, str(o, "y") orelse return badKey(why, "EC JWK without 'y'"));
            var sec1: [97]u8 = undefined;
            sec1[0] = 4;
            if (std.mem.eql(u8, crv, "P-256")) {
                if (x.len != 32 or y.len != 32) return badKey(why, "bad P-256 coordinates");
                @memcpy(sec1[1..33], x);
                @memcpy(sec1[33..65], y);
                key.material = .{ .p256 = EcP256.PublicKey.fromSec1(sec1[0..65]) catch return badKey(why, "invalid P-256 key") };
            } else if (std.mem.eql(u8, crv, "P-384")) {
                if (x.len != 48 or y.len != 48) return badKey(why, "bad P-384 coordinates");
                @memcpy(sec1[1..49], x);
                @memcpy(sec1[49..97], y);
                key.material = .{ .p384 = EcP384.PublicKey.fromSec1(sec1[0..97]) catch return badKey(why, "invalid P-384 key") };
            } else return badKey(why, "unsupported EC curve (P-256, P-384)");
        } else if (std.mem.eql(u8, kty, "OKP")) {
            const crv = str(o, "crv") orelse return badKey(why, "OKP JWK without 'crv'");
            if (!std.mem.eql(u8, crv, "Ed25519")) return badKey(why, "unsupported OKP curve (Ed25519)");
            const x = try decodeB64(arena, str(o, "x") orelse return badKey(why, "OKP JWK without 'x'"));
            if (x.len != 32) return badKey(why, "bad Ed25519 key length");
            key.material = .{ .ed25519 = Ed25519.PublicKey.fromBytes(x[0..32].*) catch return badKey(why, "invalid Ed25519 key") };
        } else if (std.mem.eql(u8, kty, "oct")) {
            const k_ = try decodeB64(arena, str(o, "k") orelse return badKey(why, "oct JWK without 'k'"));
            if (k_.len < 32) return badKey(why, "HMAC keys must be at least 32 bytes");
            key.material = .{ .hmac = k_ };
        } else return badKey(why, "unsupported JWK kty");
        try out.append(arena, key);
    }
}

fn badKey(why: *[]const u8, msg: []const u8) LoadError {
    why.* = msg;
    return error.InvalidJwks;
}

// ---------------------------------------------------------------- verification

pub const Failure = enum {
    malformed,
    bad_alg,
    no_key,
    bad_signature,
    expired,
    not_yet_valid,
    bad_issuer,
    bad_audience,
    missing_exp,
    unsupported,
};

pub const Verified = struct {
    claims: std.json.ObjectMap,

    pub fn claimString(self: *const Verified, name: []const u8, buf: []u8) ?[]const u8 {
        const v = self.claims.get(name) orelse return null;
        return switch (v) {
            .string => |s| s,
            .integer => |i| std.fmt.bufPrint(buf, "{d}", .{i}) catch null,
            .bool => |b| if (b) "true" else "false",
            else => null,
        };
    }
};

pub const Result = union(enum) { ok: Verified, fail: Failure };

fn numClaim(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |i| i,
        .float => |f| if (std.math.isFinite(f)) @intFromFloat(f) else null,
        else => null,
    };
}

fn verifyHmac(comptime H: type, key: []const u8, msg: []const u8, sig: []const u8) bool {
    const M = crypto.auth.hmac.Hmac(H);
    if (sig.len != M.mac_length) return false;
    var mac: [M.mac_length]u8 = undefined;
    M.create(&mac, msg, key);
    return crypto.timing_safe.eql([M.mac_length]u8, mac, sig[0..M.mac_length].*);
}

fn verifyRsa(comptime pss: bool, comptime H: type, k: RsaKey, msg: []const u8, sig: []const u8) bool {
    if (sig.len != k.modulus_len) return false;
    const S = if (pss) rsa.PSSSignature else rsa.PKCS1v1_5Signature;
    switch (k.modulus_len) {
        inline 256, 384, 512 => |ml| {
            S.verify(ml, sig[0..ml], msg, k.pk, H) catch return false;
            return true;
        },
        else => return false,
    }
}

fn verifySig(alg: Alg, m: KeyMaterial, msg: []const u8, sig: []const u8) bool {
    return switch (alg) {
        .HS256 => verifyHmac(Sha256, m.hmac, msg, sig),
        .HS384 => verifyHmac(Sha384, m.hmac, msg, sig),
        .HS512 => verifyHmac(Sha512, m.hmac, msg, sig),
        .RS256 => verifyRsa(false, Sha256, m.rsa, msg, sig),
        .RS384 => verifyRsa(false, Sha384, m.rsa, msg, sig),
        .RS512 => verifyRsa(false, Sha512, m.rsa, msg, sig),
        .PS256 => verifyRsa(true, Sha256, m.rsa, msg, sig),
        .PS384 => verifyRsa(true, Sha384, m.rsa, msg, sig),
        .PS512 => verifyRsa(true, Sha512, m.rsa, msg, sig),
        .ES256 => blk: {
            if (sig.len != 64) break :blk false;
            const s = EcP256.Signature.fromBytes(sig[0..64].*);
            s.verify(msg, m.p256) catch break :blk false;
            break :blk true;
        },
        .ES384 => blk: {
            if (sig.len != 96) break :blk false;
            const s = EcP384.Signature.fromBytes(sig[0..96].*);
            s.verify(msg, m.p384) catch break :blk false;
            break :blk true;
        },
        .EdDSA => blk: {
            if (sig.len != 64) break :blk false;
            const s = Ed25519.Signature.fromBytes(sig[0..64].*);
            s.verify(msg, m.ed25519) catch break :blk false;
            break :blk true;
        },
    };
}

/// Per-worker cache of verified signatures. Asymmetric verification costs
/// tens to hundreds of microseconds, and clients reuse a token for many
/// requests. The key is the token's SHA-256 (collision-resistant, so a
/// different token can never hit an entry); only the signature result is
/// cached: claims (exp, nbf, iss, aud) are checked on every request.
/// Entries are tied to a config generation and provider, and live at most
/// `max_age_s`.
pub const Cache = struct {
    pub const size = 4096;
    pub const max_age_s = 300;
    const Entry = struct { hash: [32]u8 = @splat(0), generation: u64 = 0, provider: u32 = 0, until_s: i64 = 0 };
    entries: [size]Entry = @splat(.{}),
    hits: u64 = 0,
    misses: u64 = 0,

    pub const Scope = struct { generation: u64, provider: u32 };

    fn slot(self: *Cache, h: *const [32]u8) *Entry {
        const idx = std.mem.readInt(u64, h[0..8], .little) & (size - 1);
        return &self.entries[idx];
    }

    fn lookup(self: *Cache, h: *const [32]u8, scope: Scope, now_s: i64) bool {
        const e = self.slot(h);
        return e.generation == scope.generation and e.provider == scope.provider and
            now_s < e.until_s and std.mem.eql(u8, &e.hash, h);
    }

    fn store(self: *Cache, h: *const [32]u8, scope: Scope, now_s: i64) void {
        self.slot(h).* = .{ .hash = h.*, .generation = scope.generation, .provider = scope.provider, .until_s = now_s + max_age_s };
    }
};

/// Verifies `token`. `scratch` is a per-request allocator (e.g. a
/// FixedBufferAllocator); the returned claims live in it.
pub fn verify(p: *const Provider, token: []const u8, now_s: i64, scratch: std.mem.Allocator) Result {
    return verifyCached(p, token, now_s, scratch, null, .{ .generation = 0, .provider = 0 });
}

pub fn verifyCached(p: *const Provider, token: []const u8, now_s: i64, scratch: std.mem.Allocator, cache: ?*Cache, scope: Cache.Scope) Result {
    if (token.len > 8192) return .{ .fail = .malformed };
    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return .{ .fail = .malformed };
    const dot2 = std.mem.indexOfScalarPos(u8, token, dot1 + 1, '.') orelse return .{ .fail = .malformed };
    if (std.mem.indexOfScalarPos(u8, token, dot2 + 1, '.') != null) return .{ .fail = .malformed };
    const h_b64 = token[0..dot1];
    const p_b64 = token[dot1 + 1 .. dot2];
    const s_b64 = token[dot2 + 1 ..];
    const signing_input = token[0..dot2];

    const hdr_json = decodeScratch(scratch, h_b64) orelse return .{ .fail = .malformed };
    const hdr = std.json.parseFromSliceLeaky(std.json.Value, scratch, hdr_json, .{}) catch return .{ .fail = .malformed };
    if (hdr != .object) return .{ .fail = .malformed };
    if (hdr.object.get("crit") != null) return .{ .fail = .unsupported };
    const alg_s = str(hdr.object, "alg") orelse return .{ .fail = .malformed };
    const alg = parseAlg(alg_s) orelse return .{ .fail = .bad_alg }; // includes "none"
    if (!p.algs.contains(alg)) return .{ .fail = .bad_alg };
    const kid = str(hdr.object, "kid");

    var token_hash: [32]u8 = undefined;
    var cached = false;
    if (cache) |c| {
        Sha256.hash(token, &token_hash, .{});
        cached = c.lookup(&token_hash, scope, now_s);
        if (cached) c.hits += 1 else c.misses += 1;
    }
    if (!cached) switch (verifySignature(p, alg, kid, signing_input, s_b64, scratch)) {
        .ok => if (cache) |c| c.store(&token_hash, scope, now_s),
        .fail => |f| return .{ .fail = f },
    };
    return checkClaims(p, p_b64, now_s, scratch);
}

const SigResult = union(enum) { ok, fail: Failure };

fn verifySignature(p: *const Provider, alg: Alg, kid: ?[]const u8, signing_input: []const u8, s_b64: []const u8, scratch: std.mem.Allocator) SigResult {
    const sig = decodeScratch(scratch, s_b64) orelse return .{ .fail = .malformed };
    var tried: usize = 0;
    var any_key = false;
    var ok = false;
    for (p.keys) |k| {
        if (!k.material.fits(alg)) continue;
        if (k.alg) |ka| if (ka != alg) continue;
        if (kid) |want| {
            if (k.kid == null or !std.mem.eql(u8, k.kid.?, want)) continue;
        }
        any_key = true;
        // Without a kid, bound the work an attacker can cause.
        tried += 1;
        if (tried > 4) break;
        if (verifySig(alg, k.material, signing_input, sig)) {
            ok = true;
            break;
        }
    }
    if (!any_key) return .{ .fail = .no_key };
    if (!ok) return .{ .fail = .bad_signature };
    return .ok;
}

fn checkClaims(p: *const Provider, p_b64: []const u8, now_s: i64, scratch: std.mem.Allocator) Result {
    const pl_json = decodeScratch(scratch, p_b64) orelse return .{ .fail = .malformed };
    const pl = std.json.parseFromSliceLeaky(std.json.Value, scratch, pl_json, .{}) catch return .{ .fail = .malformed };
    if (pl != .object) return .{ .fail = .malformed };
    const c = pl.object;

    if (c.get("exp")) |v| {
        const exp = numClaim(v) orelse return .{ .fail = .malformed };
        if (now_s >= exp + p.leeway_s) return .{ .fail = .expired };
    } else if (p.require_exp) return .{ .fail = .missing_exp };
    if (c.get("nbf")) |v| {
        const nbf = numClaim(v) orelse return .{ .fail = .malformed };
        if (now_s + p.leeway_s < nbf) return .{ .fail = .not_yet_valid };
    }
    if (p.issuer) |iss| {
        const got = str(c, "iss") orelse return .{ .fail = .bad_issuer };
        if (!std.mem.eql(u8, got, iss)) return .{ .fail = .bad_issuer };
    }
    if (p.audiences.len > 0) {
        const aud = c.get("aud") orelse return .{ .fail = .bad_audience };
        if (!audienceMatches(aud, p.audiences)) return .{ .fail = .bad_audience };
    }
    return .{ .ok = .{ .claims = c } };
}

fn audienceMatches(aud: std.json.Value, want: []const []const u8) bool {
    switch (aud) {
        .string => |s| {
            for (want) |w| if (std.mem.eql(u8, s, w)) return true;
        },
        .array => |a| for (a.items) |item| {
            if (item != .string) continue;
            for (want) |w| if (std.mem.eql(u8, item.string, w)) return true;
        },
        else => {},
    }
    return false;
}

fn decodeScratch(scratch: std.mem.Allocator, s: []const u8) ?[]u8 {
    const n = b64.Decoder.calcSizeForSlice(s) catch return null;
    const out = scratch.alloc(u8, n) catch return null;
    b64.Decoder.decode(out, s) catch return null;
    return out;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const jwks_json = @embedFile("testdata/jwks.json");
const tokens_json = @embedFile("testdata/tokens.json");
const hs_secret = "s3cret-s3cret-s3cret-s3cret-s3cr";
const now: i64 = 1_800_000_000; // 2027

fn testProvider(arena: std.mem.Allocator, algs: []const Alg) !Provider {
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, jwks_json, .{});
    var keys: std.ArrayList(Key) = .empty;
    var why: []const u8 = "";
    try loadJwks(arena, doc, &keys, &why);
    try keys.append(arena, .{ .kid = null, .alg = null, .material = .{ .hmac = hs_secret } });
    var set: AlgSet = .empty;
    for (algs) |a| set.insert(a);
    return .{
        .name = "t",
        .algs = set,
        .issuer = "https://issuer.test",
        .audiences = &.{"api"},
        .keys = keys.items,
        .leeway_s = 30,
        .require_exp = true,
        .consumer_claim = "sub",
        .claims_to_headers = &.{},
        .header = "Authorization",
        .query = null,
        .forward_token = true,
    };
}

fn fixtureToken(arena: std.mem.Allocator, name: []const u8) ![]const u8 {
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, arena, tokens_json, .{});
    return doc.object.get(name).?.string;
}

fn check(p: *const Provider, arena: std.mem.Allocator, name: []const u8) !Result {
    var buf: [16384]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const r = verify(p, try fixtureToken(arena, name), now, fba.allocator());
    // Copy the consumer out before the scratch goes away.
    return switch (r) {
        .ok => .{ .ok = .{ .claims = undefined } },
        .fail => r,
    };
}

test "valid tokens for every key type" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try testProvider(a, &.{ .RS256, .PS256, .ES256, .EdDSA, .HS256 });
    for ([_][]const u8{ "rs256", "ps256", "es256", "eddsa", "hs256", "aud_array" }) |name| {
        const r = try check(&p, a, name);
        if (r != .ok) {
            std.debug.print("{s}: {s}\n", .{ name, @tagName(r.fail) });
            return error.TestUnexpectedResult;
        }
    }
}

test "claims are readable" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try testProvider(a, &.{.RS256});
    var buf: [16384]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const r = verify(&p, try fixtureToken(a, "rs256"), now, fba.allocator());
    var nb: [32]u8 = undefined;
    try testing.expectEqualStrings("alice", r.ok.claimString("sub", &nb).?);
    try testing.expectEqualStrings("acme", r.ok.claimString("tenant", &nb).?);
    try testing.expectEqualStrings("4102444800", r.ok.claimString("exp", &nb).?);
}

test "rejections" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try testProvider(a, &.{ .RS256, .ES256 });
    const cases = [_]struct { tok: []const u8, want: Failure }{
        .{ .tok = "expired", .want = .expired },
        .{ .tok = "not_yet", .want = .not_yet_valid },
        .{ .tok = "wrong_aud", .want = .bad_audience },
        .{ .tok = "wrong_iss", .want = .bad_issuer },
        .{ .tok = "no_exp", .want = .missing_exp },
        .{ .tok = "tampered", .want = .bad_signature },
        .{ .tok = "alg_none", .want = .bad_alg },
        .{ .tok = "hs256", .want = .bad_alg }, // not in the allow-list
        .{ .tok = "eddsa", .want = .bad_alg },
    };
    for (cases) |cse| {
        const r = try check(&p, a, cse.tok);
        if (r != .fail or r.fail != cse.want) {
            std.debug.print("{s}: got {any}\n", .{ cse.tok, r });
            return error.TestUnexpectedResult;
        }
    }
}

test "algorithm confusion: an RSA key never verifies an HMAC token" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var p = try testProvider(a, &.{ .HS256, .RS256 });
    // Drop the real HMAC key: only asymmetric keys remain.
    p.keys = p.keys[0 .. p.keys.len - 1];
    const r = try check(&p, a, "hs256");
    try testing.expect(r == .fail and r.fail == .no_key);
}

test "malformed tokens" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try testProvider(a, &.{.RS256});
    var buf: [16384]u8 = undefined;
    for ([_][]const u8{ "", "a", "a.b", "a.b.c.d", "!!!.e30.sig", "e30.e30.", "bm90IGpzb24.e30.AA" }) |t| {
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        const r = verify(&p, t, now, fba.allocator());
        try testing.expect(r == .fail);
    }
}

test "cache: hits skip verification, misses on other tokens, generations and expiry" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try testProvider(a, &.{.RS256});
    const cache = try testing.allocator.create(Cache);
    defer testing.allocator.destroy(cache);
    cache.* = .{};
    var buf: [16384]u8 = undefined;
    const scope: Cache.Scope = .{ .generation = 7, .provider = 0 };
    const good = try fixtureToken(a, "rs256");
    for (0..3) |_| {
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        try testing.expect(verifyCached(&p, good, now, fba.allocator(), cache, scope) == .ok);
    }
    try testing.expectEqual(@as(u64, 1), cache.misses);
    try testing.expectEqual(@as(u64, 2), cache.hits);
    // A tampered token is a different hash: verified (and rejected).
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    const r = verifyCached(&p, try fixtureToken(a, "tampered"), now, fba.allocator(), cache, scope);
    try testing.expect(r == .fail and r.fail == .bad_signature);
    // Claims are still checked on a hit: an expired-at-request-time token
    // fails even though its signature is cached.
    const exp_tok = try fixtureToken(a, "rs256");
    fba = .init(&buf);
    const late = verifyCached(&p, exp_tok, 4102444800 + 100, fba.allocator(), cache, scope);
    try testing.expect(late == .fail and late.fail == .expired);
    // New config generation: miss.
    const misses = cache.misses;
    fba = .init(&buf);
    try testing.expect(verifyCached(&p, good, now, fba.allocator(), cache, .{ .generation = 8, .provider = 0 }) == .ok);
    try testing.expectEqual(misses + 1, cache.misses);
}
