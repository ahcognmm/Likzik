import { useState } from "react";
import { useStore } from "../store";
import { authOf, chainOf, clone, entities, gw, gwHandles, isHttp, lbText, limitShort, limitText, matchKind, portOf, routesFor, same, type RouteItem } from "../model";
import { METHODS, type Config, type CoreRoute, type GwRoute, type Listener } from "../types";
import { Button, CardOption, Check, DraftActions, DraftBanner, Field, Icon, Legend, LinkBtn, NumInput, PageHead, Seg, Select, Tag, TextInput } from "../components/ui";

export function RoutesPage() {
  const { draft, ui, setUi } = useStore();
  const c = draft!;
  const listener = c.listeners.find((l) => l.name === ui.listener) ?? c.listeners.find(isHttp) ?? c.listeners[0];
  const pick = <>
    <label htmlFor="lis" className="sr">Listener</label>
    <select id="lis" className="select head-sel" value={listener?.name ?? ""} onChange={(e) => setUi({ listener: e.target.value, route: null })}>
      {c.listeners.map((l) => <option key={l.name} value={l.name}>{l.name} {portOf(l.address)}</option>)}
    </select>
    <DraftActions />
  </>;
  return <>
    <PageHead title="Routes" actions={pick} />
    <DraftBanner />
    {!listener ? <div className="notice dashed">There are no listeners yet. <a href="#listeners">Add a listener</a> first, then add routes to it.</div>
      : !isHttp(listener) ? <TcpListener l={listener} />
      : <RoutesOn c={c} l={listener} />}
  </>;
}

function TcpListener({ l }: { l: Listener }) {
  const { setUi, draft } = useStore();
  return <div className="panel"><div className="panel-body stack"><h2>{l.name} passes TCP straight through</h2>
    <p>Connections on <span className="mono">{l.address}</span> go to cluster <span className="mono">{l.cluster}</span> without looking at HTTP, so this listener has no routes.</p>
    <div><a className="btn sec sm" href="#listeners" onClick={() => setUi({ aside: { type: "listener", index: draft!.listeners.indexOf(l) } })}>Edit listener</a></div></div></div>;
}

function RoutesOn({ c, l }: { c: Config; l: Listener }) {
  const { ui, setUi, live } = useStore();
  const items = routesFor(c, l.name);
  const sel = items.find((i) => i.id === ui.route) ?? items[0];
  const was = entities(live);
  const g = gw(c);
  const gwOn = gwHandles(c, l);
  let dividerShown = false;
  return <div className="cols">
    <section className="main-col" aria-labelledby="rts">
      <div className="panel">
        <div className="panel-head"><div><h2 id="rts">Routes on {l.name}</h2>
          <p className="small muted">{gwOn
            ? <>Gateway routes, matched by path: exact segments first, then <span className="mono">:parameters</span>, then <span className="mono">*wildcards</span>.{g!.fallthrough && " Requests no route matches fall through to the core routes below."}</>
            : <>Core routes from <span className="mono">{l.route_config}</span>, tried in order; the first match wins.</>}</p></div>
          <LinkBtn kind="sec" small href="#add"><Icon name="plus" size={14} width={2.2} />Add route</LinkBtn></div>
        <div className="tw"><table style={{ minWidth: 640 }}>
          <thead><tr><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Sends to</th><th scope="col">Policies</th></tr></thead>
          <tbody>
            {items.map((it) => {
              const old = was.get(it.id);
              const flag = !old ? "New" : !same(old.obj, it.gw ?? it.core) ? "Edited" : "";
              const divider = it.kind === "core" && it.fallthrough && !dividerShown;
              if (divider) dividerShown = true;
              return [
                divider && <tr key="div" className="divider"><td colSpan={4}>When no gateway route matches</td></tr>,
                <tr key={it.id} className={it.id === sel?.id ? "sel" : ""}>
                  <td className="mono small" style={{ fontWeight: 500, whiteSpace: "nowrap" }}>{it.method}</td>
                  <td><button type="button" className="linkbtn" onClick={() => setUi({ route: it.id })}>{it.path}</button>
                    {flag && <> <Tag kind="warn">{flag}</Tag></>}
                    {it.kind === "gw" && it.hosts.length > 0 && <div className="small muted">{it.hosts.join(", ")}</div>}</td>
                  <td className="mono small">{it.dest.t === "cluster" ? it.dest.v : it.dest.t === "redirect" ? "Redirect " + it.dest.v : "Direct response " + it.dest.v}</td>
                  <td><span className="tags">{it.kind === "core" ? <Tag>Core route</Tag> : <>
                    {it.auth.length ? it.auth.map((a) => <Tag key={a}>{authOf(c, a)?.type ?? "?"} {a}</Tag>) : <Tag>Public</Tag>}
                    {it.limits.map((n) => { const lim = g?.rate_limits?.find((x) => x.name === n); return <Tag key={n}>{lim ? limitShort(lim) : n}</Tag>; })}
                  </>}</span></td>
                </tr>,
              ];
            })}
            {!items.length && <tr><td colSpan={4} className="muted">No routes yet. Add one to start sending traffic.</td></tr>}
          </tbody>
        </table></div>
      </div>
      {sel && <Pipeline c={c} l={l} it={sel} />}
    </section>
    {sel && (sel.kind === "gw" ? <GwEditor key={sel.id + JSON.stringify(sel.gw)} c={c} it={sel} /> : <CoreEditor key={sel.id + JSON.stringify(sel.core)} c={c} it={sel} />)}
  </div>;
}

function Pipeline({ c, l, it }: { c: Config; l: Listener; it: RouteItem }) {
  const tls = l.tls ? `TLS, ${l.tls.certificates.length > 1 ? "certificate by SNI" : "one certificate"}${c.tls?.require_ktls === false ? "" : ", kernel TLS"}` : "Plain HTTP";
  const steps = chainOf(c, it);
  const cl = it.dest.t === "cluster" ? (c.clusters ?? []).find((x) => x.name === it.dest.v) : undefined;
  return <div className="panel panel-body">
    <h2>How a request travels</h2>
    <p className="small muted" style={{ margin: "2px 0 20px" }}>For <span className="mono">{it.method} {it.path}</span> in the draft. Every step runs on the same worker.</p>
    <div className="pipe">
      <div className="box"><div className="k">Listener</div><div style={{ fontWeight: 600 }}>{l.name}</div><div className="mono" style={{ fontSize: 12 }}>{l.address}</div><div style={{ fontSize: 12, marginTop: 6 }}>{tls}</div></div>
      <div className="link" aria-hidden="true" />
      <div className="box route"><div className="k">Route</div><div className="mono" style={{ fontSize: 13, fontWeight: 700 }}>{it.method} {it.path}</div>
        <ol className="steps">{steps.map((s, i) => <li key={i}><span className="n">{i + 1}</span><span>{s}</span></li>)}</ol></div>
      <div className="link" aria-hidden="true" />
      <div className="box"><div className="k">Cluster</div><div className="mono" style={{ fontSize: 13, fontWeight: 500 }}>{it.dest.t === "cluster" ? it.dest.v : "None"}</div>
        {cl ? <><div style={{ fontSize: 12, marginTop: 6 }}>{lbText[cl.lb_policy ?? "least_request"]}</div><div style={{ fontSize: 12 }}>{cl.endpoints.length} endpoint{cl.endpoints.length === 1 ? "" : "s"}{cl.tls ? ", TLS to upstream" : ""}</div></>
          : <div style={{ fontSize: 12, marginTop: 6 }}>Answered by the proxy</div>}</div>
      <div className="link" aria-hidden="true" />
      <div className="box eps"><div className="k">Endpoints</div>
        {it.dest.t !== "cluster" ? <p className="small" style={{ marginTop: 4 }}>No upstream. {it.dest.t === "redirect" ? "The proxy redirects the client." : `The proxy answers with ${it.dest.v}.`}</p>
          : !cl ? <p className="err-text" style={{ marginTop: 4 }}>Cluster {it.dest.v} does not exist.</p>
          : <ul className="eplist">{cl.endpoints.map((e) => <li key={e.address}><span className="dot" aria-hidden="true" /><span className="mono" style={{ fontSize: 12, flex: "1 1 auto" }}>{e.address}</span><span className="small muted">weight {e.weight ?? 1}</span></li>)}</ul>}
      </div>
    </div>
  </div>;
}

// ---------------------------------------------------------------- editors

type Rule = { op: "set" | "add" | "remove"; name: string; value: string };
const toRules = (h?: GwRoute["request_headers"]): Rule[] => [
  ...(h?.set ?? []).map((x) => ({ op: "set" as const, ...x })),
  ...(h?.add ?? []).map((x) => ({ op: "add" as const, ...x })),
  ...(h?.remove ?? []).map((n) => ({ op: "remove" as const, name: n, value: "" })),
];
function fromRules(rows: Rule[]) {
  const out: NonNullable<GwRoute["request_headers"]> = {};
  for (const r of rows) {
    if (!r.name) continue;
    if (r.op === "remove") (out.remove ??= []).push(r.name);
    else (out[r.op] ??= []).push({ name: r.name, value: r.value });
  }
  return Object.keys(out).length ? out : undefined;
}
type Dest = "cluster" | "redirect" | "respond";

function EditorFrame({ title, sub, tabs, tab, setTab, children, err, onSave, onDelete }: {
  title: string; sub: string; tabs: [string, string][]; tab: string; setTab: (t: string) => void;
  children: React.ReactNode; err: string; onSave: () => void; onDelete: () => void;
}) {
  return <aside className="panel" aria-labelledby="det">
    <div className="editor-head"><div className="small muted">{sub}</div><h2 id="det">{title}</h2></div>
    <div className="tabs" role="tablist" aria-label="Route settings">
      {tabs.map(([id, label]) => <button key={id} type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>{label}</button>)}
    </div>
    <div className="editor-body">{children}
      {err && <p className="err-text" role="alert">{err}</p>}
      <div className="editor-foot"><Button kind="danger" onClick={onDelete}>Delete route</Button><Button kind="pri" onClick={onSave}>Save to draft</Button></div>
    </div>
  </aside>;
}

function deleteAt(update: (fn: (d: Config) => void) => void, ref: (string | number)[]) {
  if (!confirm("Remove this route from the draft?")) return;
  update((d) => { const list = ref.slice(0, -1).reduce<unknown>((x, k) => (x as Record<string, unknown>)[k as string], d) as unknown[]; list.splice(ref[ref.length - 1] as number, 1); });
}

function GwEditor({ c, it }: { c: Config; it: RouteItem }) {
  const { update, setUi } = useStore();
  const [tab, setTab] = useState("match");
  const [r, setR] = useState<GwRoute>(() => clone(it.gw!));
  const [dest, setDest] = useState<Dest>(it.gw!.cluster != null ? "cluster" : it.gw!.redirect ? "redirect" : "respond");
  const [req, setReq] = useState<Rule[]>(() => toRules(it.gw!.request_headers));
  const [resp, setResp] = useState<Rule[]>(() => toRules(it.gw!.response_headers));
  const [err, setErr] = useState("");
  const set = (p: Partial<GwRoute>) => setR((x) => ({ ...x, ...p }));
  const g = gw(c)!;

  const save = () => {
    if (!r.name) return setErr("Give the route a name.");
    if (!r.path?.startsWith("/")) return setErr("Start the path with a slash, like /v1/refunds.");
    const idx = it.ref[3] as number;
    if (g.routes.some((x, i) => i !== idx && x.name === r.name)) return setErr(`Another route is already called ${r.name}.`);
    const o: GwRoute = clone(r);
    if (dest === "cluster") { delete o.redirect; delete o.respond; if (!o.cluster) return setErr("Choose a cluster."); }
    if (dest === "redirect") { delete o.cluster; delete o.respond; delete o.rewrite; if (!o.redirect?.location) return setErr("Enter where to redirect to."); }
    if (dest === "respond") { delete o.cluster; delete o.redirect; delete o.rewrite; o.respond ??= { status: 200 }; if (!o.respond.body) delete o.respond.body; }
    o.request_headers = fromRules(req); o.response_headers = fromRules(resp);
    for (const k of ["headers", "query", "methods", "hosts", "auth", "rate_limits"] as const) if (Array.isArray(o[k]) && !o[k]!.length) delete o[k];
    for (const k of ["request_headers", "response_headers", "rewrite"] as const) if (o[k] === undefined || o[k] === "") delete o[k];
    if (!o.auth_optional) delete o.auth_optional;
    update((d) => { d.extensions!.gateway!.routes[idx] = o; });
    setUi({ route: "route:" + o.name });
  };

  const tabs: [string, string][] = [["match", "Match"], ["upstream", "Upstream"], ["auth", "Auth"], ["rate", "Rate limit"], ["headers", "Headers"]];
  return <EditorFrame title={`${it.method} ${it.path}`} sub="Route" tabs={tabs} tab={tab} setTab={setTab} err={err} onSave={save} onDelete={() => deleteAt(update, it.ref)}>
    {tab === "match" && <MatchTab r={r} set={set} />}
    {tab === "upstream" && <UpstreamTab c={c} r={r} set={set} dest={dest} setDest={setDest} />}
    {tab === "auth" && <AuthTab c={c} r={r} set={set} />}
    {tab === "rate" && <RateTab c={c} r={r} set={set} />}
    {tab === "headers" && <HeadersTab req={req} setReq={setReq} resp={resp} setResp={setResp} r={r} dest={dest} />}
  </EditorFrame>;
}

function MatchTab({ r, set }: { r: GwRoute; set: (p: Partial<GwRoute>) => void }) {
  const toggle = (m: string) => { const s = new Set(r.methods ?? []); s.has(m) ? s.delete(m) : s.add(m); set({ methods: METHODS.filter((x) => s.has(x)) }); };
  const headers = r.headers ?? [], query = r.query ?? [];
  return <div className="stack">
    <Field id="f-name" label="Name" help="Used in metrics and in the change history."><TextInput id="f-name" value={r.name} onValue={(v) => set({ name: v })} /></Field>
    <Field id="f-path" label="Path" help={<>Use <span className="mono">:name</span> for one segment and <span className="mono">*name</span> at the end for the rest of the path.</>}>
      <TextInput id="f-path" value={r.path} onValue={(v) => set({ path: v })} /></Field>
    <fieldset><Legend>How the path matches</Legend>
      <div className="seg" aria-label="Match kind">{(["Exact", "Parameter", "Wildcard"] as const).map((k) => <button key={k} type="button" aria-pressed={matchKind(r.path) === k} tabIndex={-1} aria-disabled="true">{k}</button>)}</div>
      <p className="help" style={{ marginTop: 6 }}>Set by the path itself.</p></fieldset>
    <fieldset><Legend>Methods</Legend><Seg label="Methods" multi value={r.methods ?? []} options={METHODS.map((m) => [m, m])} onValue={toggle} />
      {!(r.methods ?? []).length && <p className="help" style={{ marginTop: 6 }}>None selected: every method matches.</p>}</fieldset>
    <Field id="f-hosts" label="Hosts" help={<>Comma separated. <span className="mono">*.example.com</span> matches subdomains.</>}>
      <TextInput id="f-hosts" placeholder="Any host" value={(r.hosts ?? []).join(", ")} onValue={(v) => set({ hosts: v.split(",").map((s) => s.trim()).filter(Boolean) })} /></Field>
    <div><div className="legend" style={{ marginBottom: 6 }}>Header and query conditions</div>
      <p className="help" style={{ marginBottom: 8 }}>Checked after the path matches.{headers.length + query.length ? "" : " None set."}</p>
      <div className="stack" style={{ gap: 8 }}>
        {headers.map((h, i) => <CondRow key={"h" + i} label="Header" kinds={["value", "prefix", "present", "absent"]} c={h}
          onChange={(n) => set({ headers: headers.map((x, j) => (j === i ? n : x)) })} onRemove={() => set({ headers: headers.filter((_, j) => j !== i) })} />)}
        {query.map((h, i) => <CondRow key={"q" + i} label="Query" kinds={["value", "present", "absent"]} c={h}
          onChange={(n) => set({ query: query.map((x, j) => (j === i ? n : x)) })} onRemove={() => set({ query: query.filter((_, j) => j !== i) })} />)}
      </div>
      <div className="row" style={{ marginTop: 8, flex: "none" }}>
        <Button kind="sec" small style={{ flex: "0 0 auto" }} onClick={() => set({ headers: [...headers, { name: "", value: "" }] })}>Add header condition</Button>
        <Button kind="sec" small style={{ flex: "0 0 auto" }} onClick={() => set({ query: [...query, { name: "", value: "" }] })}>Add query condition</Button>
      </div></div>
  </div>;
}

type Cond = { name: string; value?: string; prefix?: string; present?: boolean };
function CondRow({ label, kinds, c, onChange, onRemove }: { label: string; kinds: string[]; c: Cond; onChange: (c: Cond) => void; onRemove: () => void }) {
  const kind = c.present === false ? "absent" : c.present === true ? "present" : c.prefix != null ? "prefix" : "value";
  const words: Record<string, string> = { value: "equals", prefix: "starts with", present: "is present", absent: "is absent" };
  const setKind = (k: string) => {
    const n: Cond = { name: c.name };
    if (k === "present") n.present = true; else if (k === "absent") n.present = false; else (n as unknown as Record<string, string>)[k] = "";
    onChange(n);
  };
  return <div className="rule-row"><span className="small muted" style={{ flex: "0 0 56px" }}>{label}</span>
    <TextInput aria-label={`${label} name`} placeholder="name" value={c.name} onValue={(v) => onChange({ ...c, name: v })} />
    <select className="select op" aria-label="Condition" value={kind} onChange={(e) => setKind(e.target.value)}>{kinds.map((k) => <option key={k} value={k}>{words[k]}</option>)}</select>
    {(kind === "value" || kind === "prefix") && <TextInput aria-label="Value" placeholder="value" value={(c as unknown as Record<string, string>)[kind]} onValue={(v) => onChange({ ...c, [kind]: v })} />}
    <button type="button" className="x" aria-label="Remove condition" onClick={onRemove}>×</button></div>;
}

function UpstreamTab({ c, r, set, dest, setDest }: { c: Config; r: GwRoute; set: (p: Partial<GwRoute>) => void; dest: Dest; setDest: (d: Dest) => void }) {
  const cl = (c.clusters ?? []).find((x) => x.name === r.cluster);
  const dests: [Dest, string, string][] = [["cluster", "Forward to a cluster", "The request goes to one of the cluster's endpoints."], ["redirect", "Redirect", "The client is sent to another URL."], ["respond", "Direct response", "The proxy answers by itself."]];
  return <div className="stack">
    <fieldset><Legend>Where requests go</Legend><div className="stack" style={{ gap: 8 }}>
      {dests.map(([id, l, h]) => <CardOption key={id} name="dest" checked={dest === id} onChange={() => setDest(id)} title={l} help={h} />)}</div></fieldset>
    {dest === "cluster" && <>
      <Field id="f-clu" label="Send to cluster" help={cl ? `${lbText[cl.lb_policy ?? "least_request"]}. Change balancing on the cluster.` : undefined}>
        <Select id="f-clu" value={r.cluster} onValue={(v) => set({ cluster: v })} options={(c.clusters ?? []).map((x) => x.name)} /></Field>
      <div className="row">
        <Field id="f-rw" label="Path sent upstream" help={<>Template, e.g. <span className="mono">/users/{"{id}"}</span>. Empty keeps the original path.</>}>
          <TextInput id="f-rw" placeholder="Unchanged" value={r.rewrite} onValue={(v) => set({ rewrite: v })} /></Field>
        <Field id="f-to" label="Timeout (ms)" help="Until the response starts."><NumInput id="f-to" placeholder="60000" value={r.timeout_ms} onValue={(v) => set({ timeout_ms: v })} /></Field>
      </div>
      <p className="notice">If a connection to an endpoint fails, likzik tries another endpoint (up to {cl?.max_connect_attempts ?? 2} attempts, set on the cluster). Requests are not retried once they reach an upstream.</p>
    </>}
    {dest === "redirect" && <div className="row">
      <Field id="f-loc" label="Redirect to"><TextInput id="f-loc" placeholder="https://{host}/v2/{rest}" value={r.redirect?.location} onValue={(v) => set({ redirect: { status: r.redirect?.status ?? 308, location: v } })} /></Field>
      <div className="field" style={{ flex: "0 1 150px" }}><label htmlFor="f-code">Status</label>
        <Select id="f-code" value={String(r.redirect?.status ?? 308)} options={["301", "302", "303", "307", "308"]} onValue={(v) => set({ redirect: { location: r.redirect?.location ?? "", status: Number(v) } })} /></div>
    </div>}
    {dest === "respond" && <>
      <div className="row">
        <Field id="f-st" label="Status code"><NumInput id="f-st" value={r.respond?.status ?? 200} onValue={(v) => set({ respond: { ...r.respond, status: v } })} /></Field>
        <Field id="f-ct" label="Content type"><TextInput id="f-ct" value={r.respond?.content_type ?? "text/plain"} onValue={(v) => set({ respond: { ...r.respond, content_type: v } })} /></Field>
      </div>
      <Field id="f-body" label="Body (optional)"><TextInput id="f-body" mono={false} placeholder="Left empty, the response has no body" value={r.respond?.body} onValue={(v) => set({ respond: { ...r.respond, body: v } })} /></Field>
    </>}
  </div>;
}

function AuthTab({ c, r, set }: { c: Config; r: GwRoute; set: (p: Partial<GwRoute>) => void }) {
  const g = gw(c)!, on = new Set(r.auth ?? []);
  const provs = [
    ...(g.jwt ?? []).map((a) => ({ name: a.name, title: `JWT: ${a.name}`, help: `${a.algorithms.join(", ")}${a.issuer ? ", issuer " + a.issuer : ""}` })),
    ...(g.api_keys ?? []).map((a) => ({ name: a.name, title: `API key: ${a.name}`, help: `Key in the ${a.header ?? "X-API-Key"} header${a.query ? " or ?" + a.query : ""}, ${a.keys.length} consumers` })),
  ];
  const toggle = (n: string, yes: boolean) => { const s = new Set(on); yes ? s.add(n) : s.delete(n); set({ auth: [...s] }); };
  return <div className="stack">
    <fieldset><Legend>Who can call this route</Legend><div className="stack" style={{ gap: 8 }}>
      <CardOption type="checkbox" checked={!on.size} onChange={(v) => v && set({ auth: [] })} title="Anyone" help="No check. Use for health and public endpoints." />
      {provs.map((p) => <CardOption key={p.name} type="checkbox" checked={on.has(p.name)} onChange={(v) => toggle(p.name, v)} title={p.title} help={p.help} />)}
    </div>
      <p className="help" style={{ marginTop: 6 }}>{on.size > 1 && "Any one of the selected methods is enough. "}{!provs.length && <>No auth providers yet. <a href="#auth">Add one</a>.</>}</p></fieldset>
    {on.size > 0 && <Check checked={!!r.auth_optional} onChange={(v) => set({ auth_optional: v })}>Also let callers without credentials through. Credentials that are sent must still be valid.</Check>}
    {[...on].map((n) => { const j = g.jwt?.find((a) => a.name === n); if (!j) return null;
      return <div key={n} className="kv">
        <div><div className="k">Issuer</div><div className="v">{j.issuer ?? "Not checked"}</div></div>
        <div><div className="k">Audience</div><div className="v">{j.audiences?.join(", ") || "Not checked"}</div></div>
        <div><div className="k">Allowed algorithms</div><div className="v">{j.algorithms.join(", ")}</div></div>
        <div className="small">Keys from {j.jwks_file ? <><span className="mono">{j.jwks_file}</span>, read when the configuration loads</> : j.jwks ? "an inline JWKS" : "a shared secret"}.</div>
      </div>; })}
  </div>;
}

function RateTab({ c, r, set }: { c: Config; r: GwRoute; set: (p: Partial<GwRoute>) => void }) {
  const { update } = useStore();
  const lims = gw(c)?.rate_limits ?? [], on = new Set(r.rate_limits ?? []);
  const addLimit = () => {
    let n = (r.name || "route") + "-limit", i = 2;
    while (lims.some((x) => x.name === n)) n = `${r.name}-limit-${i++}`;
    update((d) => { const g = d.extensions!.gateway!; (g.rate_limits ??= []).push({ name: n, requests: 100, per: "second", key: "client_ip" }); });
    set({ rate_limits: [...on, n] });
  };
  return <div className="stack">
    {!lims.length ? <div className="notice dashed"><p style={{ marginBottom: 10 }}>This route has no rate limit, so only the cluster's connection limits bound it.</p><Button kind="pri" small onClick={addLimit}>Add a rate limit</Button></div> : <>
      <fieldset><Legend>Limits that apply</Legend><div className="stack" style={{ gap: 8 }}>
        {lims.map((l) => <CardOption key={l.name} type="checkbox" checked={on.has(l.name)} title={l.name} help={`${limitText(l)}${l.burst ? `, bursts up to ${l.burst}` : ""}`}
          onChange={(v) => { const s = new Set(on); v ? s.add(l.name) : s.delete(l.name); set({ rate_limits: [...s] }); }} />)}
      </div></fieldset>
      <div><Button kind="sec" small onClick={addLimit}>Add a rate limit</Button></div>
    </>}
    <p className="notice">Limits are shared by all workers of this proxy, so 100 per second means 100 per second for the whole process. Over the limit, callers get 429 with a Retry-After header.</p>
  </div>;
}

function RuleRows({ rows, setRows, label }: { rows: Rule[]; setRows: (r: Rule[]) => void; label: string }) {
  const upd = (i: number, p: Partial<Rule>) => setRows(rows.map((x, j) => (j === i ? { ...x, ...p } : x)));
  return <>{rows.map((r, i) => <div key={i} className="rule-row">
    <select className="select op" aria-label="Operation" value={r.op} onChange={(e) => upd(i, { op: e.target.value as Rule["op"] })}>
      <option value="set">Set</option><option value="add">Add</option><option value="remove">Remove</option></select>
    <TextInput aria-label="Header name" placeholder="Header-Name" value={r.name} onValue={(v) => upd(i, { name: v })} />
    {r.op !== "remove" && <TextInput aria-label="Value" placeholder="value" value={r.value} onValue={(v) => upd(i, { value: v })} />}
    <button type="button" className="x" aria-label={`Remove ${label} rule`} onClick={() => setRows(rows.filter((_, j) => j !== i))}>×</button>
  </div>)}</>;
}
function HeadersTab({ req, setReq, resp, setResp, r, dest }: { req: Rule[]; setReq: (r: Rule[]) => void; resp: Rule[]; setResp: (r: Rule[]) => void; r: GwRoute; dest: Dest }) {
  return <div className="stack" style={{ gap: 14 }}>
    <div className="legend">Request headers</div>
    {req.length ? <RuleRows rows={req} setRows={setReq} label="request" /> : <p className="help">None. The gateway always sets its consumer header after authentication and removes copies sent by clients.</p>}
    <div><Button kind="sec" small onClick={() => setReq([...req, { op: "set", name: "", value: "" }])}>Add request header rule</Button></div>
    <p className="help">Values may use <span className="mono">{"{param}"}</span>, <span className="mono">{"{consumer}"}</span>, <span className="mono">{"{client_ip}"}</span>, <span className="mono">{"{host}"}</span>.</p>
    <div className="legend" style={{ marginTop: 6 }}>Response headers</div>
    {resp.length ? <RuleRows rows={resp} setRows={setResp} label="response" /> : <p className="help">None.</p>}
    <div><Button kind="sec" small onClick={() => setResp([...resp, { op: "set", name: "", value: "" }])}>Add response header rule</Button></div>
    <div className="legend" style={{ marginTop: 6 }}>Path sent upstream</div>
    <p>{dest !== "cluster" ? "No upstream." : r.rewrite ? <>Rewritten to <span className="mono">{r.rewrite}</span>; the query string is kept.</> : "Unchanged. The original path is forwarded; normalization is only used to pick the route."}</p>
  </div>;
}

function CoreEditor({ c, it }: { c: Config; it: RouteItem }) {
  const { update } = useStore();
  const [tab, setTab] = useState("match");
  const [r, setR] = useState<CoreRoute>(() => clone(it.core!));
  const [err, setErr] = useState("");
  const m = r.match, prefix = m.prefix != null, p = m.prefix ?? m.path ?? "";
  const setMatch = (n: Partial<CoreRoute["match"]>) => setR((x) => ({ ...x, match: { ...x.match, ...n } }));
  const setRoute = (n: Partial<CoreRoute["route"]>) => setR((x) => ({ ...x, route: { ...x.route, ...n } }));
  const save = () => {
    if (!p.startsWith("/")) return setErr("Start the path with a slash.");
    const o = clone(r);
    if (o.match.methods && !o.match.methods.length) delete o.match.methods;
    if (o.route.prefix_rewrite === "") delete o.route.prefix_rewrite;
    update((d) => {
      const list = it.ref.slice(0, -1).reduce<unknown>((x, k) => (x as Record<string, unknown>)[k as string], d) as CoreRoute[];
      list[it.ref[it.ref.length - 1] as number] = o;
    });
  };
  const toggle = (x: string) => { const s = new Set(m.methods ?? []); s.has(x) ? s.delete(x) : s.add(x); setMatch({ methods: METHODS.filter((y) => s.has(y)) }); };
  return <EditorFrame title={`${it.method} ${it.path}`} sub="Core route" tabs={[["match", "Match"], ["upstream", "Upstream"]]} tab={tab} setTab={setTab} err={err} onSave={save} onDelete={() => deleteAt(update, it.ref)}>
    {tab === "match" ? <div className="stack">
      <Field id="f-cpath" label="Path"><TextInput id="f-cpath" value={p} onValue={(v) => setR((x) => ({ ...x, match: { methods: x.match.methods, ...(prefix ? { prefix: v } : { path: v }) } }))} /></Field>
      <fieldset><Legend>How the path matches</Legend>
        <Seg label="Match kind" value={prefix ? "prefix" : "path"} options={[["path", "Exact"], ["prefix", "Prefix"]]}
          onValue={(k) => setR((x) => ({ ...x, match: { methods: x.match.methods, [k]: p } }))} /></fieldset>
      <fieldset><Legend>Methods</Legend><Seg label="Methods" multi value={m.methods ?? []} options={METHODS.map((x) => [x, x])} onValue={toggle} /></fieldset>
      <p className="notice">Core routes have no gateway policies (auth, rate limits, header rules). Use a gateway route for those.</p>
    </div> : <div className="stack">
      <Field id="f-cclu" label="Send to cluster"><Select id="f-cclu" value={r.route.cluster} onValue={(v) => setRoute({ cluster: v })} options={(c.clusters ?? []).map((x) => x.name)} /></Field>
      <div className="row">
        <Field id="f-cpr" label="Prefix rewrite" help="Needs a prefix match."><TextInput id="f-cpr" placeholder="Unchanged" value={r.route.prefix_rewrite} onValue={(v) => setRoute({ prefix_rewrite: v })} /></Field>
        <Field id="f-cto" label="Timeout (ms)"><NumInput id="f-cto" placeholder="60000" value={r.route.timeout_ms} onValue={(v) => setRoute({ timeout_ms: v })} /></Field>
      </div></div>}
  </EditorFrame>;
}
