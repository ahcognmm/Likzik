// The likzik-ui server API (src/ui/main.zig).
import type { HistoryEntry, ServerInfo, Stats } from "./types";

function token(): string {
  try { return sessionStorage.getItem("likzik-token") ?? ""; } catch { return ""; }
}

async function call(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const t = token();
  if (t) headers.set("Authorization", "Bearer " + t);
  const r = await fetch(path, { ...init, headers });
  if (r.status === 401) {
    const entered = window.prompt("This console needs its access token (likzik-ui was started with --token).");
    if (entered == null) throw new Error("An access token is required.");
    try { sessionStorage.setItem("likzik-token", entered); } catch { /* private mode: token only lives for this call */ }
    return call(path, init);
  }
  return r;
}

export interface ConfigFile { path: string; etag: string; text: string }
export async function getConfig(): Promise<ConfigFile> {
  const r = await call("/api/config");
  const j = await r.json();
  if (!r.ok) throw new Error(j.error ?? "The config file could not be read.");
  return j;
}
export async function validate(text: string): Promise<{ ok: boolean; message: string }> {
  const r = await call("/api/validate", { method: "POST", body: text });
  return r.json();
}
export interface ApplyResult { ok: boolean; applied?: boolean; generation?: number; previous_generation?: number; etag?: string; message: string; conflict?: boolean }
export async function apply(text: string, etag: string, note: string): Promise<ApplyResult> {
  const r = await call("/api/config", { method: "PUT", body: text, headers: { "If-Match": etag, "X-Likzik-Note": encodeURIComponent(note) } });
  const j = await r.json();
  return { ...j, conflict: r.status === 409 };
}
export async function serverInfo(): Promise<ServerInfo> {
  const r = await call("/api/admin/server_info");
  if (!r.ok) throw new Error("admin");
  return r.json();
}
export async function stats(): Promise<Stats> {
  const r = await call("/api/admin/stats");
  if (!r.ok) throw new Error("admin");
  const text = await r.text();
  return Object.fromEntries(text.trim().split("\n").map((l) => { const [k, v] = l.split(": "); return [k, Number(v)]; }));
}
export async function history(): Promise<HistoryEntry[]> {
  const r = await call("/api/history");
  return r.ok ? r.json() : [];
}
export async function historyVersion(id: number): Promise<string> {
  const r = await call("/api/history/" + id);
  if (!r.ok) throw new Error("That version is no longer in the history.");
  return (await r.json()).text;
}
export const serialize = (c: unknown) => JSON.stringify(c, null, 2) + "\n";
