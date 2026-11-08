import { useMemo, useState, type ReactNode } from "react";
import { useStore, type View } from "../store";
import { Icon } from "./ui";
import { routesFor } from "../model";

function Sidebar({ open }: { open: boolean }) {
  const { view, changes } = useStore();
  const [routing, setRouting] = useState(true);
  const cur = (v: View | View[]) => ((Array.isArray(v) ? v : [v]).includes(view) ? { "aria-current": "page" as const } : {});
  return <nav className="side" aria-label="Console" style={open ? undefined : { display: "none" }}>
    <a href="#status" {...cur("status")}><Icon name="status" />Sources and status</a>
    <button type="button" aria-expanded={routing} onClick={() => setRouting(!routing)}>
      <Icon name="routing" /><span className="grow">Routing</span>
      {changes.length > 0 && <span className="badge" aria-label={`${changes.length} draft changes`}>{changes.length}</span>}
      <Icon name={routing ? "up" : "down"} size={16} width={2} />
    </button>
    {routing && <>
      <a className="sub" href="#listeners" {...cur("listeners")}>Listeners</a>
      <a className="sub" href="#routes" {...cur(["routes", "add"])}>Routes</a>
      <a className="sub" href="#clusters" {...cur("clusters")}>Clusters</a>
    </>}
    <a href="#certificates" {...cur("certificates")}><Icon name="cert" />Certificates</a>
    <a href="#auth" {...cur("auth")}><Icon name="auth" />Auth providers</a>
    <a href="#publish" {...cur("publish")}><Icon name="publish" />Review and publish</a>
    <div className="bottom"><p>Resources</p>
      <a href="https://github.com/ahcognmm/Likzik/blob/phase1-core/docs/gateway.md" target="_blank" rel="noopener noreferrer"><Icon name="docs" />Docs</a></div>
  </nav>;
}

interface Hit { kind: string; label: string; go: () => void }
function Search() {
  const { draft, setUi, go } = useStore();
  const [q, setQ] = useState("");
  const [hl, setHl] = useState(0);
  const hits = useMemo<Hit[]>(() => {
    const s = q.trim().toLowerCase();
    if (!s || !draft) return [];
    const out: Hit[] = [], seen = new Set<string>();
    for (const l of draft.listeners) for (const it of routesFor(draft, l.name)) {
      if (seen.has(it.id) || !`${it.method} ${it.path} ${it.name}`.toLowerCase().includes(s)) continue;
      seen.add(it.id);
      out.push({ kind: "Route", label: `${it.method} ${it.path}`, go: () => { setUi({ listener: l.name, route: it.id }); go("routes"); } });
    }
    (draft.clusters ?? []).forEach((c, i) => {
      if (c.name.toLowerCase().includes(s)) out.push({ kind: "Cluster", label: c.name, go: () => { setUi({ aside: { type: "cluster", index: i } }); go("clusters"); } });
      for (const e of c.endpoints) if (e.address.toLowerCase().includes(s)) out.push({ kind: "Endpoint", label: `${e.address} in ${c.name}`, go: () => { setUi({ aside: { type: "cluster", index: i } }); go("clusters"); } });
    });
    draft.listeners.forEach((l, i) => { if (`${l.name} ${l.address}`.toLowerCase().includes(s)) out.push({ kind: "Listener", label: `${l.name} ${l.address}`, go: () => { setUi({ aside: { type: "listener", index: i } }); go("listeners"); } }); });
    return out.slice(0, 12);
  }, [q, draft, setUi, go]);
  const pick = (h: Hit) => { h.go(); setQ(""); };
  return <div className="search">
    <label><Icon name="search" size={16} width={2} /><span className="sr">Search</span>
      <input type="search" placeholder="Search routes, clusters, endpoints..." value={q} autoComplete="off" aria-controls="results"
        onChange={(e) => { setQ(e.target.value); setHl(0); }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") { setHl(Math.min(hl + 1, hits.length - 1)); e.preventDefault(); }
          if (e.key === "ArrowUp") { setHl(Math.max(hl - 1, 0)); e.preventDefault(); }
          if (e.key === "Enter" && hits[hl]) pick(hits[hl]);
          if (e.key === "Escape") setQ("");
        }} /></label>
    <div id="results" className={`results ${q ? "open" : ""}`} role="listbox" aria-label="Search results">
      {hits.map((h, i) => <button key={i} type="button" role="option" aria-selected={i === hl} className={i === hl ? "hl" : ""} onClick={() => pick(h)}><span className="kind">{h.kind}</span><span className="mono small">{h.label}</span></button>)}
      {q && !hits.length && <p className="small muted" style={{ padding: "10px 12px" }}>Nothing matches.</p>}
    </div>
  </div>;
}

function Status() {
  const { server, adminUp, changes } = useStore();
  const g = server?.config.generation;
  return <div className="right" aria-live="polite">
    {adminUp === false ? <span className="gen down" title="The proxy's admin endpoint does not answer">Proxy unreachable</span>
      : g != null ? <span className="gen" title="Generation the workers are serving">Live {g}</span> : null}
    {changes.length > 0 && <a className="gen draft" href="#publish" title="Unpublished changes">Draft {g != null ? g + 1 : ""} · {changes.length}</a>}
  </div>;
}

export function Shell({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(() => !matchMedia("(max-width: 760px)").matches);
  return <>
    <header className="top">
      <button className="iconbtn" type="button" aria-label="Toggle menu" aria-expanded={open} onClick={() => setOpen(!open)}><Icon name="menu" size={20} /></button>
      <a className="logo" href="#routes"><span className="mark" aria-hidden="true">L</span><span className="word">Likzik</span></a>
      <Search />
      <Status />
    </header>
    <div className="frame"><Sidebar open={open} /><main id="main">{children}</main></div>
  </>;
}
