import { useState } from "react";
import { useStore } from "../store";
import { autoName, conflicts, ensureGw, gw, gwHandles, isHttp, lbText, limitText, matchKind, methodLabel } from "../model";
import { METHODS, type GwRoute } from "../types";
import { Button, CardOption, Check, Field, LinkBtn, Legend, Seg, Select, Tag, TextInput } from "../components/ui";

type Dest = "cluster" | "redirect" | "respond";
interface Form {
  methods: string[]; path: string; hosts: string; name: string; dest: Dest; cluster: string;
  location: string; code: string; status: string; body: string; auth: string[]; rateOn: boolean; limit: string; newRps: string;
}
const KIND_HELP = { Exact: "Only this path.", Parameter: "One value per :name segment, like /v1/refunds/42.", Wildcard: "This path and everything below it." };

export function AddRoutePage() {
  const { draft, ui, update, setUi, changes } = useStore();
  const c = draft!;
  const l = c.listeners.find((x) => x.name === ui.listener && isHttp(x)) ?? c.listeners.find(isHttp);
  const [f, setF] = useState<Form>(() => ({
    methods: ["GET"], path: "/", hosts: "", name: "", dest: "cluster", cluster: c.clusters?.[0]?.name ?? "",
    location: "", code: "308", status: "200", body: "", auth: [], rateOn: false, limit: "", newRps: "100",
  }));
  const [added, setAdded] = useState<{ line: string; dest: string } | null>(null);
  const set = (p: Partial<Form>) => setF((x) => ({ ...x, ...p }));

  const head = <div><a href="#routes" className="small">Back to routes</a>
    <p className="eyebrow" style={{ marginTop: 14 }}>Routes on {l?.name}</p><h1>Add route</h1>
    <p className="lede muted" style={{ marginTop: 8 }}>The route is added to the draft. Workers only pick it up after you publish.</p></div>;
  if (!l) return <>{head}<div className="notice dashed">Add an HTTP listener first.</div></>;
  if (added) {
    const n = changes.length;
    return <>{head}<section className="panel panel-body" style={{ background: "var(--lime)" }}>
      <h2>Added to draft</h2>
      <p style={{ margin: "6px 0 16px" }}><span className="mono">{added.line}</span> now {added.dest}. The draft has {n} change{n === 1 ? "" : "s"} that {n === 1 ? "is" : "are"} not published.</p>
      <div className="actions"><LinkBtn kind="pri" href="#publish">Review and publish</LinkBtn>
        <Button kind="sec" onClick={() => { setAdded(null); set({ path: "/", name: "" }); }}>Add another route</Button>
        <LinkBtn kind="sec" href="#routes">Back to routes</LinkBtn></div>
    </section></>;
  }

  const gwOn = gwHandles(c, l);
  const g = gw(c);
  const lims = g?.rate_limits ?? [];
  const kind = matchKind(f.path);
  const slashErr = f.path !== "" && !f.path.startsWith("/");
  const hosts = f.hosts.split(",").map((s) => s.trim()).filter(Boolean);
  const can = !slashErr && f.path !== "" && (f.dest !== "cluster" || !!f.cluster) && (f.dest !== "redirect" || !!f.location);
  const line = `${methodLabel(f.methods)} ${f.path}`;
  const destLabel = f.dest === "cluster" ? f.cluster : f.dest === "redirect" ? `${f.code} to ${f.location || "…"}` : `${f.status}${f.body ? " with a body" : ""}`;
  const steps: string[] = [];
  if (gwOn) {
    if (f.auth.length) steps.push("Check " + f.auth.join(" or "));
    if (f.rateOn) { const lim = lims.find((x) => x.name === f.limit); steps.push("Rate limit, " + (lim ? limitText(lim) : `${f.newRps} per second, by client IP`)); }
  }
  steps.push(f.dest === "cluster" ? "Forward upstream" : f.dest === "redirect" ? "Redirect " + f.code : "Respond " + f.status);

  const cs = gwOn ? conflicts({ methods: f.methods, hosts, path: f.path }, g!.routes) : [];
  const dup = cs.find((x) => x.t === "dup"), loses = cs.find((x) => x.t === "loses"), wins = cs.find((x) => x.t === "wins");

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!can) return;
    if (gwOn) {
      const r: GwRoute = { name: f.name || autoName(c, f.methods, f.path), path: f.path };
      if (f.methods.length) r.methods = [...f.methods];
      if (hosts.length) r.hosts = hosts;
      if (f.auth.length) r.auth = [...f.auth];
      if (f.dest === "cluster") r.cluster = f.cluster;
      if (f.dest === "redirect") r.redirect = { status: Number(f.code), location: f.location };
      if (f.dest === "respond") { r.respond = { status: Number(f.status) || 200 }; if (f.body) r.respond.body = f.body; }
      update((d) => {
        const gg = ensureGw(d);
        if (f.rateOn) {
          let name = f.limit;
          if (!name) { name = r.name + "-limit"; (gg.rate_limits ??= []).push({ name, requests: Math.max(1, Number(f.newRps) || 1), per: "second", key: "client_ip" }); }
          r.rate_limits = [name];
        }
        gg.routes.push(r);
      });
      setUi({ route: "route:" + r.name, listener: l.name });
      setAdded({ line: `${methodLabel(r.methods)} ${r.path}`, dest: f.dest === "cluster" ? "sends to " + f.cluster : f.dest === "redirect" ? "redirects to " + f.location : "is answered by the proxy" });
    } else {
      const rc = c.route_configs?.find((x) => x.name === l.route_config);
      if (!rc?.virtual_hosts.length) { alert("This listener's route config has no virtual host."); return; }
      const ri = c.route_configs!.indexOf(rc);
      const match = f.path.endsWith("/*") ? { prefix: f.path.slice(0, -1) } : { path: f.path };
      update((d) => { d.route_configs![ri].virtual_hosts[0].routes.push({ match: f.methods.length ? { ...match, methods: [...f.methods] } : match, route: { cluster: f.cluster } }); });
      setAdded({ line: `${methodLabel(f.methods)} ${f.path}`, dest: "sends to " + f.cluster });
    }
  };

  const toggleMethod = (m: string) => { const s = new Set(f.methods); s.has(m) ? s.delete(m) : s.add(m); set({ methods: METHODS.filter((x) => s.has(x)) }); };
  const auths: [string, string][] = [["", "Anyone"], ...(g?.jwt ?? []).map((x): [string, string] => [x.name, "JWT " + x.name]), ...(g?.api_keys ?? []).map((x): [string, string] => [x.name, "API key " + x.name])];

  return <>{head}<div className="cols">
    <form className="main-col" onSubmit={submit} noValidate>
      <section className="panel panel-body stack" aria-labelledby="s-match">
        <div><h2 id="s-match">Which requests</h2><p className="small muted">On listener <span className="mono">{l.name}</span>, {l.address}.</p></div>
        <fieldset><Legend>Methods</Legend><Seg label="Methods" multi value={f.methods} options={METHODS.map((m) => [m, m])} onValue={toggleMethod} />
          {!f.methods.length && <p className="help" style={{ marginTop: 6 }}>None selected: every method matches.</p>}</fieldset>
        <Field id="a-path" label="Path" help={gwOn ? <>Use <span className="mono">:name</span> for one segment, or end with <span className="mono">*rest</span> to match everything below.</> : <>End with <span className="mono">/*</span> to match everything below (a prefix route).</>}>
          <TextInput id="a-path" value={f.path} onValue={(v) => set({ path: v })} /></Field>
        {slashErr && <p className="err-text">Start the path with a slash, like /v1/refunds.</p>}
        {gwOn && <>
          <div style={{ display: "flex", gap: 12, alignItems: "baseline", flexWrap: "wrap" }}><span className="small muted">Detected match</span><Tag>{kind}</Tag><span className="small">{KIND_HELP[kind]}</span></div>
          <div className="row">
            <Field id="a-hosts" label="Hosts (optional)"><TextInput id="a-hosts" placeholder="Any host" value={f.hosts} onValue={(v) => set({ hosts: v })} /></Field>
            <Field id="a-name" label="Name" help="Left empty, one is made from the method and path."><TextInput id="a-name" placeholder={autoName(c, f.methods, f.path)} value={f.name} onValue={(v) => set({ name: v })} /></Field>
          </div></>}
      </section>

      <section className="panel panel-body stack" aria-labelledby="s-dest">
        <h2 id="s-dest">Where they go</h2>
        {gwOn && <div className="stack" style={{ gap: 8 }}>
          {([["cluster", "A cluster", "Forward to one of your clusters."], ["redirect", "A redirect", "Send the client to another URL."], ["respond", "A direct response", "The proxy answers by itself, for health checks or stubs."]] as [Dest, string, string][])
            .map(([id, t, h]) => <CardOption key={id} name="dest" checked={f.dest === id} onChange={() => set({ dest: id })} title={t} help={h} />)}</div>}
        {f.dest === "cluster" && <fieldset><Legend>Cluster</Legend><div className="stack" style={{ gap: 6 }}>
          {(c.clusters ?? []).map((x) => <CardOption key={x.name} name="cluster" checked={f.cluster === x.name} onChange={() => set({ cluster: x.name })}
            title={<span className="mono">{x.name}</span>} help={`${x.endpoints.length} endpoints, ${(lbText[x.lb_policy ?? "least_request"] ?? "").toLowerCase()}`} />)}
          {!(c.clusters ?? []).length && <p className="help">No clusters yet.</p>}</div>
          <p className="help" style={{ marginTop: 8 }}>Need a new one? <a href="#clusters">Add a cluster</a> first, then come back.</p></fieldset>}
        {f.dest === "redirect" && <div className="row">
          <Field id="a-loc" label="Redirect to"><TextInput id="a-loc" placeholder="https://{host}/v2/{rest}" value={f.location} onValue={(v) => set({ location: v })} /></Field>
          <div className="field" style={{ flex: "0 1 160px" }}><label htmlFor="a-code">Status</label>
            <Select id="a-code" value={f.code} onValue={(v) => set({ code: v })} options={[["308", "308 Permanent"], ["307", "307 Temporary"], ["301", "301"], ["302", "302"]]} /></div></div>}
        {f.dest === "respond" && <div className="row">
          <div className="field" style={{ flex: "0 1 140px" }}><label htmlFor="a-st">Status code</label><TextInput id="a-st" inputMode="numeric" value={f.status} onValue={(v) => set({ status: v })} /></div>
          <Field id="a-body" label="Body (optional)"><TextInput id="a-body" mono={false} placeholder="Left empty, the response has no body" value={f.body} onValue={(v) => set({ body: v })} /></Field></div>}
      </section>

      {gwOn && <section className="panel panel-body stack" aria-labelledby="s-acc">
        <h2 id="s-acc">Access and limits</h2>
        <fieldset><Legend>Who can call it</Legend>
          <div className="seg" role="group" aria-label="Who can call it">{auths.map(([id, label]) => <button key={id || "anyone"} type="button" aria-pressed={id === "" ? !f.auth.length : f.auth.includes(id)}
            onClick={() => { if (!id) set({ auth: [] }); else { const s = new Set(f.auth); s.has(id) ? s.delete(id) : s.add(id); set({ auth: [...s] }); } }}>{label}</button>)}</div>
          <p className="help" style={{ marginTop: 6 }}>{f.auth.length ? `Callers need valid credentials from ${f.auth.join(" or ")}.` : "No check. Anyone can call this route."}</p></fieldset>
        <Check checked={f.rateOn} onChange={(v) => set({ rateOn: v })}>Limit requests</Check>
        {f.rateOn && <>
          <Field id="a-lim" label="Limit"><Select id="a-lim" value={f.limit} onValue={(v) => set({ limit: v })}
            options={[["", "New: requests per second by client IP"], ...lims.map((x): [string, string] => [x.name, `${x.name}: ${limitText(x)}`])]} /></Field>
          {!f.limit && <Field id="a-rps" label="Requests per second" help="Shared by all workers of the proxy."><TextInput id="a-rps" inputMode="numeric" style={{ width: 160 }} value={f.newRps} onValue={(v) => set({ newRps: v })} /></Field>}
        </>}
        <p className="help">Timeouts, header rules and match conditions can be set on the route once it is added.</p>
      </section>}

      <div className="actions" style={{ justifyContent: "flex-end" }}><LinkBtn kind="sec" href="#routes">Cancel</LinkBtn><button type="submit" className="btn pri" disabled={!can}>Add to draft</button></div>
    </form>

    <aside className="stack" aria-labelledby="pv" style={{ flex: "1 1 380px", maxWidth: 460 }}>
      <div className="panel panel-body"><h2 id="pv" style={{ marginBottom: 12 }}>Preview</h2>
        <div className="box route" style={{ border: "2px solid var(--ink)", background: "var(--lime)", padding: "12px 14px" }}>
          <div className="mono" style={{ fontSize: 13, fontWeight: 700 }}>{line}</div>
          <ol className="steps">{steps.map((s, i) => <li key={i}><span className="n">{i + 1}</span><span>{s}</span></li>)}</ol></div>
        <div aria-hidden="true" style={{ width: 2, height: 20, background: "var(--ink)", marginLeft: 24 }} />
        <div style={{ border: "2px solid var(--ink)", background: "var(--paper)", padding: "12px 14px" }}>
          <div className="small muted">{f.dest === "cluster" ? "Cluster" : f.dest === "redirect" ? "Redirect" : "Direct response"}</div>
          <div className="mono" style={{ fontSize: 13, fontWeight: 500 }}>{destLabel}</div></div>
      </div>
      <div className="panel panel-body"><h2 style={{ marginBottom: 10 }}>Overlap with existing routes</h2>
        {!gwOn ? <p className="small muted">Core routes are tried in order; this one is added at the end.</p>
          : dup ? <p className="small" style={{ display: "flex", gap: 10 }}><Tag kind="err">Clash</Tag><span><span className="mono">{dup.other.name}</span> already handles {methodLabel(dup.other.methods)} on this path and is tried first. Edit that route instead, or change the method or path.</span></p>
          : loses ? <p className="small" style={{ display: "flex", gap: 10 }}><Tag kind="warn">Note</Tag><span>Some of these requests also match <span className="mono">{loses.other.name}</span> ({loses.other.path}), which wins for them because its path is more specific.</span></p>
          : wins ? <p className="small" style={{ display: "flex", gap: 10 }}><Tag kind="warn">Note</Tag><span>These requests also match <span className="mono">{wins.other.name}</span>. Your route wins because a more specific path is matched first.</span></p>
          : <p className="small" style={{ display: "flex", gap: 10 }}><Tag kind="ok">Clear</Tag><span>No other route matches these requests.</span></p>}
      </div>
    </aside>
  </div></>;
}
