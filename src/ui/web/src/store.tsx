// App state: the live config, the draft, proxy status, and a hash router.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import * as api from "./api";
import { changes, clone, type Change } from "./model";
import type { Config, HistoryEntry, ServerInfo, Stats } from "./types";

export type View = "status" | "listeners" | "routes" | "clusters" | "certificates" | "auth" | "publish" | "add";
const VIEWS: View[] = ["status", "listeners", "routes", "clusters", "certificates", "auth", "publish", "add"];

interface Ui { listener: string | null; route: string | null; aside: { type: string; index: number | null } | null }

interface Store {
  view: View; go: (v: View) => void;
  live: Config | null; draft: Config | null; etag: string; path: string; loadError: string | null;
  update: (fn: (d: Config) => void) => void; replaceDraft: (c: Config) => void; discard: () => void;
  reload: () => Promise<void>; changes: Change[];
  server: ServerInfo | null; stats: Stats | null; rps: number | null; adminUp: boolean | null; refreshStatus: () => Promise<void>;
  history: HistoryEntry[]; refreshHistory: () => Promise<void>;
  ui: Ui; setUi: (u: Partial<Ui>) => void;
}
const Ctx = createContext<Store | null>(null);
export const useStore = () => { const s = useContext(Ctx); if (!s) throw new Error("no store"); return s; };

const viewFromHash = (): View => { const v = location.hash.slice(1) as View; return VIEWS.includes(v) ? v : "routes"; };

export function StoreProvider({ children }: { children: ReactNode }) {
  const [view, setView] = useState<View>(viewFromHash);
  const [live, setLive] = useState<Config | null>(null);
  const [draft, setDraft] = useState<Config | null>(null);
  const [etag, setEtag] = useState("");
  const [path, setPath] = useState("");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [server, setServer] = useState<ServerInfo | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [rps, setRps] = useState<number | null>(null);
  const [adminUp, setAdminUp] = useState<boolean | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [ui, setUiState] = useState<Ui>({ listener: null, route: null, aside: null });
  const prev = useRef<{ total: number; at: number } | null>(null);

  useEffect(() => {
    const on = () => { setView(viewFromHash()); window.scrollTo(0, 0); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const go = useCallback((v: View) => { location.hash = "#" + v; }, []);

  const reload = useCallback(async () => {
    try {
      const f = await api.getConfig();
      const c = JSON.parse(f.text) as Config;
      setLive(c); setDraft(clone(c)); setEtag(f.etag); setPath(f.path); setLoadError(null);
    } catch (e) { setLoadError(e instanceof Error ? e.message : String(e)); }
  }, []);
  const refreshStatus = useCallback(async () => {
    try {
      const [si, st] = await Promise.all([api.serverInfo(), api.stats()]);
      const now = performance.now();
      if (prev.current && now > prev.current.at) setRps(Math.max(0, (st.downstream_rq_total - prev.current.total) / ((now - prev.current.at) / 1000)));
      prev.current = { total: st.downstream_rq_total, at: now };
      setServer(si); setStats(st); setAdminUp(true);
    } catch { setAdminUp(false); }
  }, []);
  const refreshHistory = useCallback(async () => { try { setHistory(await api.history()); } catch { setHistory([]); } }, []);

  useEffect(() => {
    reload(); refreshStatus(); refreshHistory();
    const t = setInterval(refreshStatus, 2000);
    return () => clearInterval(t);
  }, [reload, refreshStatus, refreshHistory]);

  const update = useCallback((fn: (d: Config) => void) => setDraft((d) => { if (!d) return d; const n = clone(d); fn(n); return n; }), []);
  const ch = useMemo(() => changes(live, draft), [live, draft]);
  useEffect(() => {
    const warn = (e: BeforeUnloadEvent) => { if (ch.length) { e.preventDefault(); } };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [ch.length]);

  const value: Store = {
    view, go, live, draft, etag, path, loadError,
    update, replaceDraft: (c) => setDraft(clone(c)), discard: () => setDraft(clone(live)), reload, changes: ch,
    server, stats, rps, adminUp, refreshStatus, history, refreshHistory,
    ui, setUi: (u) => setUiState((s) => ({ ...s, ...u })),
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
