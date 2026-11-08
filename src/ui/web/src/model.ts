// Pure logic over the config: no React, no I/O. Unit-tested in model.test.ts.
import type { Config, Gateway, GwRoute, Listener, CoreRoute, RateLimit, Cluster } from "./types";

export const clone = <T,>(o: T): T => (o == null ? o : JSON.parse(JSON.stringify(o)));
export const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export const gw = (c: Config | null | undefined): Gateway | null => c?.extensions?.gateway ?? null;
export const isHttp = (l: Listener) => (l.protocol ?? "http") === "http";
export const gwHandles = (c: Config, l: Listener) => {
  const g = gw(c);
  return !!g && isHttp(l) && (!g.listeners || g.listeners.includes(l.name));
};
export function ensureGw(c: Config): Gateway {
  c.extensions ??= {};
  c.extensions.gateway ??= { routes: [] };
  c.extensions.gateway.routes ??= [];
  return c.extensions.gateway;
}

export const methodLabel = (ms?: string[]) => (ms && ms.length ? ms.join(", ") : "Any");
export type MatchKind = "Exact" | "Parameter" | "Wildcard";
export function matchKind(path: string): MatchKind {
  const s = segs(path);
  if (s.some((x) => x[0] === "*")) return "Wildcard";
  if (s.some((x) => x[0] === ":")) return "Parameter";
  return "Exact";
}
export const lbText: Record<string, string> = {
  least_request: "Least request, two random choices",
  round_robin: "Weighted round robin",
  random: "Weighted random",
};
const PER = { second: "per second", minute: "per minute", hour: "per hour" } as const;
export const keyDesc = (k?: string) =>
  !k || k === "client_ip" ? "by client IP" : k === "consumer" ? "by consumer" : k === "route" ? "for the whole route" : "by header " + k.slice(7);
export const limitText = (l: RateLimit) => `${l.requests} ${PER[l.per ?? "second"]}, ${keyDesc(l.key)}`;
export const limitShort = (l: RateLimit) => `${l.requests}/${(l.per ?? "second")[0]}`;

export function authOf(c: Config, name: string): { type: "JWT" | "API key"; name: string } | null {
  const g = gw(c);
  if (g?.jwt?.some((a) => a.name === name)) return { type: "JWT", name };
  if (g?.api_keys?.some((a) => a.name === name)) return { type: "API key", name };
  return null;
}

// ---------------------------------------------------------------- routes per listener

export type Dest = { t: "cluster"; v: string } | { t: "redirect"; v: string } | { t: "respond"; v: string };
export interface RouteItem {
  kind: "gw" | "core"; id: string; ref: (string | number)[]; name: string;
  method: string; path: string; hosts: string[]; dest: Dest; auth: string[]; limits: string[];
  gw?: GwRoute; core?: CoreRoute; fallthrough?: boolean;
}
export function gwItem(r: GwRoute, i: number): RouteItem {
  return {
    kind: "gw", id: "route:" + r.name, ref: ["extensions", "gateway", "routes", i], gw: r, name: r.name,
    method: methodLabel(r.methods), path: r.path, hosts: r.hosts ?? [],
    dest: r.cluster != null ? { t: "cluster", v: r.cluster } : r.redirect ? { t: "redirect", v: `${r.redirect.status ?? 302} ${r.redirect.location}` } : { t: "respond", v: String(r.respond?.status ?? 200) },
    auth: r.auth ?? [], limits: r.rate_limits ?? [],
  };
}
export function routesFor(c: Config, lname: string | null): RouteItem[] {
  const l = c.listeners.find((x) => x.name === lname);
  if (!l || !isHttp(l)) return [];
  const out: RouteItem[] = [];
  const g = gw(c);
  const handled = gwHandles(c, l);
  if (handled) g!.routes.forEach((r, i) => out.push(gwItem(r, i)));
  if (!handled || g!.fallthrough) {
    (c.route_configs ?? []).forEach((rc, ri) => {
      if (rc.name !== l.route_config) return;
      rc.virtual_hosts.forEach((vh, vi) => vh.routes.forEach((r, k) => {
        const m = r.match ?? {};
        out.push({
          kind: "core", id: `core:${rc.name}/${vh.name}/${k}`, ref: ["route_configs", ri, "virtual_hosts", vi, "routes", k], core: r,
          fallthrough: handled, name: `${vh.name} #${k + 1}`, method: methodLabel(m.methods),
          path: m.prefix != null ? m.prefix + (m.prefix.endsWith("/") ? "*" : "") : m.path ?? "",
          hosts: vh.domains, dest: { t: "cluster", v: r.route?.cluster }, auth: [], limits: [],
        });
      }));
    });
  }
  return out;
}

export function chainOf(c: Config, it: RouteItem): string[] {
  const steps: string[] = [];
  if (it.kind === "core") {
    if (it.core?.route?.prefix_rewrite) steps.push("Rewrite the prefix to " + it.core.route.prefix_rewrite);
    steps.push("Forward upstream");
    return steps;
  }
  const r = it.gw!, auth = r.auth ?? [];
  if (auth.length === 1) steps.push(`${authOf(c, auth[0])?.type === "JWT" ? "Check JWT" : "Check API key"} (${auth[0]})`);
  if (auth.length > 1) steps.push("Check credentials: " + auth.join(" or "));
  if (r.auth_optional) steps.push("Allow callers without credentials");
  for (const n of r.rate_limits ?? []) {
    const l = gw(c)?.rate_limits?.find((x) => x.name === n);
    steps.push("Rate limit, " + (l ? limitText(l) : n));
  }
  const rh = r.request_headers ?? {};
  if (rh.set?.length || rh.add?.length || rh.remove?.length) steps.push("Set request headers");
  if (r.redirect) steps.push(`Redirect ${r.redirect.status ?? 302}`);
  else if (r.respond) steps.push(`Respond ${r.respond.status ?? 200}`);
  else {
    if (r.rewrite) steps.push("Rewrite the path to " + r.rewrite);
    steps.push("Forward upstream");
  }
  return steps;
}

export function usedByCluster(c: Config, name: string): string[] {
  const out: string[] = [];
  for (const r of gw(c)?.routes ?? []) if (r.cluster === name) out.push("route " + r.name);
  for (const rc of c.route_configs ?? []) for (const vh of rc.virtual_hosts) for (const r of vh.routes)
    if (r.route?.cluster === name) out.push("core route " + (r.match.prefix ?? r.match.path));
  for (const l of c.listeners) if (l.cluster === name) out.push("listener " + l.name);
  return out;
}
export function renameCluster(c: Config, from: string, to: string) {
  for (const r of gw(c)?.routes ?? []) if (r.cluster === from) r.cluster = to;
  for (const rc of c.route_configs ?? []) for (const vh of rc.virtual_hosts) for (const r of vh.routes) if (r.route?.cluster === from) r.route.cluster = to;
  for (const l of c.listeners) if (l.cluster === from) l.cluster = to;
}

// ---------------------------------------------------------------- draft vs live

export interface Entity { kind: string; label: string; obj: unknown }
export function entities(c: Config | null): Map<string, Entity> {
  const m = new Map<string, Entity>();
  if (!c) return m;
  const put = (key: string, kind: string, label: string, obj: unknown) => m.set(key, { kind, label, obj });
  c.listeners.forEach((l) => put("listener:" + l.name, "listener", `${l.name} ${l.address ?? ""}`, l));
  (c.clusters ?? []).forEach((x) => put("cluster:" + x.name, "cluster", x.name, x));
  (c.route_configs ?? []).forEach((rc) => rc.virtual_hosts.forEach((vh) => vh.routes.forEach((r, k) =>
    put(`core:${rc.name}/${vh.name}/${k}`, "core route", `${methodLabel(r.match?.methods)} ${r.match?.prefix ?? r.match?.path}`, r))));
  const g = gw(c);
  if (g) {
    g.routes.forEach((r) => put("route:" + r.name, "route", `${methodLabel(r.methods)} ${r.path}`, r));
    (g.api_keys ?? []).forEach((a) => put("apikeys:" + a.name, "API key set", a.name, a));
    (g.jwt ?? []).forEach((a) => put("jwt:" + a.name, "JWT provider", a.name, a));
    (g.rate_limits ?? []).forEach((a) => put("limit:" + a.name, "rate limit", a.name, a));
    const { routes: _r, api_keys: _a, jwt: _j, rate_limits: _l, ...settings } = g;
    put("settings:gateway", "gateway settings", "Gateway", settings);
  }
  const { listeners: _li, clusters: _c, route_configs: _rc, extensions: _e, ...top } = c;
  put("settings:global", "settings", "Global settings", top);
  return m;
}
export interface Change extends Entity { key: string; op: "New" | "Edited" | "Removed"; before?: unknown }
export function changes(live: Config | null, draft: Config | null): Change[] {
  const a = entities(live), b = entities(draft), out: Change[] = [];
  for (const [k, v] of b) {
    const old = a.get(k);
    if (!old) out.push({ key: k, op: "New", ...v });
    else if (!same(old.obj, v.obj)) out.push({ key: k, op: "Edited", ...v, before: old.obj });
  }
  for (const [k, v] of a) if (!b.has(k)) out.push({ key: k, op: "Removed", ...v });
  return out;
}
const SECRET = /(^|\.)(hs_secret|key|private_key)$/;
export function flatten(o: unknown, p = "", out: Record<string, unknown> = {}): Record<string, unknown> {
  if (o && typeof o === "object" && !Array.isArray(o)) {
    for (const [k, v] of Object.entries(o)) flatten(v, p ? `${p}.${k}` : k, out);
  } else if (Array.isArray(o) && o.some((x) => x && typeof x === "object")) {
    o.forEach((v, i) => flatten(v, `${p}[${i}]`, out));
  } else out[p] = o;
  return out;
}
export function showVal(k: string, v: unknown): string {
  if (v === undefined) return "Not set";
  if (SECRET.test(k.replace(/\[\d+\]/g, ""))) return "••• (secret)";
  if (Array.isArray(v)) return v.join(", ") || "None";
  if (typeof v === "boolean") return v ? "On" : "Off";
  return String(v);
}
export function changeSummary(x: Change): string {
  const o = x.obj as Record<string, never>;
  if (x.kind === "route") {
    const r = o as unknown as GwRoute;
    return r.cluster ? `to ${r.cluster}, ${r.auth?.length ? r.auth.join(" or ") + " required" : "public"}, ${r.rate_limits?.length ? "rate limited" : "no rate limit"}` : r.redirect ? "redirect" : "direct response";
  }
  if (x.kind === "cluster") { const cl = o as unknown as Cluster; return `${cl.endpoints.length} endpoints, ${(lbText[cl.lb_policy ?? "least_request"] ?? "").toLowerCase()}`; }
  if (x.kind === "listener") { const l = o as unknown as Listener; return `${l.address}, ${l.protocol === "tcp" ? "TCP" : "HTTP"}${l.tls ? ", TLS" : ""}`; }
  if (x.kind === "rate limit") return limitText(o as unknown as RateLimit);
  return "";
}

// ---------------------------------------------------------------- route overlap
// Mirrors the gateway's trie priority: at the first segment where two
// patterns differ in kind, static beats :param beats *wildcard.

export const segs = (p: string) => (p ?? "").split("/").filter(Boolean);
const rank = (s: string) => (s[0] === "*" ? 2 : s[0] === ":" ? 1 : 0);
export function overlap(a: string[], b: string[]): boolean {
  if (!a.length && !b.length) return true;
  if (a.length && a[0][0] === "*") return true;
  if (b.length && b[0][0] === "*") return true;
  if (!a.length || !b.length) return false;
  const x = a[0], y = b[0];
  if (x[0] !== ":" && y[0] !== ":" && x !== y) return false;
  return overlap(a.slice(1), b.slice(1));
}
export function moreSpecific(a: string[], b: string[]): boolean {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const ra = i < a.length ? rank(a[i]) : 3, rb = i < b.length ? rank(b[i]) : 3;
    if (ra !== rb) return ra < rb;
  }
  return false;
}
const shape = (p: string) => segs(p).map((s) => (s[0] === ":" ? ":" : s[0] === "*" ? "*" : s)).join("/");
const listsOverlap = (x?: string[], y?: string[]) => !x?.length || !y?.length || x.some((v) => y.includes(v));
export interface Conflict { t: "dup" | "wins" | "loses"; other: GwRoute }
export function conflicts(r: { path: string; methods?: string[]; hosts?: string[] }, others: GwRoute[]): Conflict[] {
  const out: Conflict[] = [];
  for (const o of others) {
    if (!listsOverlap(r.methods, o.methods) || !listsOverlap(r.hosts, o.hosts) || !overlap(segs(r.path), segs(o.path))) continue;
    if (shape(r.path) === shape(o.path)) out.push({ t: "dup", other: o });
    else out.push({ t: moreSpecific(segs(r.path), segs(o.path)) ? "wins" : "loses", other: o });
  }
  return out;
}

export function autoName(c: Config, methods: string[], path: string): string {
  const base = ((methods.length === 1 ? methods[0] : "any") + "-" + segs(path.replace(/[:*]/g, "")).join("-")).toLowerCase().replace(/[^a-z0-9-]/g, "") || "route";
  const names = new Set((gw(c)?.routes ?? []).map((r) => r.name));
  let n = base, i = 2;
  while (names.has(n)) n = `${base}-${i++}`;
  return n;
}

// ---------------------------------------------------------------- checks before publishing
export type CheckResult = ["Passed" | "Failed" | "Warning", string];
export function clientChecks(c: Config): CheckResult[] {
  const out: CheckResult[] = [];
  const names = new Set((c.clusters ?? []).map((x) => x.name));
  const bad: string[] = [];
  for (const r of gw(c)?.routes ?? []) if (r.cluster != null && !names.has(r.cluster)) bad.push(r.name);
  for (const rc of c.route_configs ?? []) for (const vh of rc.virtual_hosts) for (const r of vh.routes)
    if (r.route && !names.has(r.route.cluster)) bad.push(r.match.prefix ?? r.match.path ?? "?");
  out.push(bad.length ? ["Failed", `Routes point at clusters that do not exist: ${bad.join(", ")}.`] : ["Passed", "Every route points at a cluster that exists in this generation."]);
  const g = gw(c);
  if (g) {
    const clashes: string[] = [];
    g.routes.forEach((r, i) => conflicts(r, g.routes.slice(0, i)).filter((x) => x.t === "dup").forEach((x) => clashes.push(`${r.name} and ${x.other.name}`)));
    out.push(clashes.length ? ["Warning", `Two routes match the same method and path: ${clashes.join("; ")}. The one listed first wins.`] : ["Passed", "No two gateway routes match the same method and path."]);
    const plain = (g.api_keys ?? []).filter((s) => s.keys.some((k) => k.key)).map((s) => s.name);
    if (plain.length) out.push(["Warning", `API key sets ${plain.join(", ")} keep plain keys in the config file. Replace them with hashed keys.`]);
    if ((g.jwt ?? []).some((j) => j.hs_secret)) out.push(["Warning", "A JWT shared secret is stored in the config file. Restrict who can read it."]);
  }
  return out;
}

// Path helpers for form bindings ("tls.certificates.0.private_key").
export function getPath(o: unknown, p: (string | number)[] | string): unknown {
  const ks = typeof p === "string" ? p.split(".") : p;
  return ks.reduce<unknown>((x, k) => (x == null ? x : (x as Record<string, unknown>)[k as string]), o);
}
export function setPath(o: unknown, p: (string | number)[] | string, v: unknown) {
  const ks = typeof p === "string" ? p.split(".") : p.map(String);
  let x = o as Record<string, unknown>;
  for (let i = 0; i < ks.length - 1; i++) {
    if (x[ks[i]] == null) x[ks[i]] = /^\d+$/.test(ks[i + 1]) ? [] : {};
    x = x[ks[i]] as Record<string, unknown>;
  }
  x[ks[ks.length - 1]] = v;
}
export const portOf = (a?: string) => { const i = (a ?? "").lastIndexOf(":"); return i >= 0 ? a!.slice(i) : ""; };
