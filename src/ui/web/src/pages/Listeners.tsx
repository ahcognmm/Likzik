import { useState } from "react";
import { useStore } from "../store";
import { clone, entities, gw, gwHandles, isHttp, same } from "../model";
import { Aside, SchemaForm, prune, type FieldDef } from "../components/Form";
import { Button, DraftActions, DraftBanner, Icon, PageHead, Panel, Tag } from "../components/ui";
import type { Config, Listener } from "../types";

type Obj = Record<string, unknown>;
const schema = (c: Config): FieldDef[] => [
  { k: "name", label: "Name", kind: "mono" },
  { k: "address", label: "Address", kind: "mono", help: "IP and port, like 0.0.0.0:443 or [::]:443." },
  { k: "protocol", label: "Protocol", kind: "seg", def: "http", opts: [["http", "HTTP"], ["tcp", "TCP passthrough"]] },
  { k: "route_config", label: "Route config", kind: "select", opts: (c.route_configs ?? []).map((r) => r.name), show: (o) => (o.protocol ?? "http") === "http",
    help: "Core routes for requests the API gateway does not handle." },
  { k: "cluster", label: "Send connections to cluster", kind: "select", opts: (c.clusters ?? []).map((x) => x.name), show: (o) => o.protocol === "tcp" },
  { k: "idle_timeout_ms", label: "Idle timeout (ms)", kind: "num", show: (o) => o.protocol === "tcp" },
  { k: "trust_forwarded_headers", label: "Trust X-Forwarded-For from clients", kind: "bool", help: "Only behind another proxy you control. Otherwise the client's address replaces it.", show: (o) => (o.protocol ?? "http") === "http" },
  { k: "_gateway", label: "Handled by the API gateway", kind: "bool", help: "Gateway routes, auth and rate limits apply on this listener.", show: (o) => (o.protocol ?? "http") === "http" && !!gw(c) },
  { k: "_tls", label: "Terminate TLS", kind: "bool", show: (o) => (o.protocol ?? "http") === "http" },
  { k: "tls.certificates", label: "Certificates", kind: "rows", add: "Add certificate", show: (o) => !!o._tls, blank: { certificate_chain: "", private_key: "" },
    cols: [{ k: "certificate_chain", label: "Certificate chain (PEM path)" }, { k: "private_key", label: "Private key (PEM path)" }, { k: "server_names", label: "SNI names, comma separated", type: "csv" }],
    help: "The first certificate is the default; others are picked by SNI name." },
];

function Editor({ index }: { index: number | null }) {
  const { draft, update, setUi } = useStore();
  const c = draft!;
  const orig = index == null ? null : c.listeners[index];
  const [obj, setObj] = useState<Obj>(() => {
    if (!orig) return { name: "", address: "", route_config: c.route_configs?.[0]?.name, _gateway: !!gw(c), _tls: false, tls: { certificates: [] } };
    const o = clone(orig) as unknown as Obj;
    o._tls = !!orig.tls; o._gateway = gwHandles(c, orig); if (!orig.tls) o.tls = { certificates: [] };
    return o;
  });
  const [err, setErr] = useState("");
  const close = () => setUi({ aside: null });

  const save = () => {
    const o = clone(obj) as Obj & Listener;
    if (!o.name || !o.address) return setErr("Enter a name and an address.");
    if (c.listeners.some((x, i) => i !== index && x.name === o.name)) return setErr(`Another listener is already called ${o.name}.`);
    const proto = o.protocol ?? "http";
    if (proto === "tcp") { delete o.route_config; delete o.trust_forwarded_headers; delete o.tls; if (!o.cluster) return setErr("Choose a cluster."); }
    else { delete o.cluster; delete o.idle_timeout_ms; delete o.protocol; if (!o.route_config) return setErr("Choose a route config."); }
    if (proto === "http" && o._tls) {
      const cs = o.tls!.certificates;
      if (!cs.length || cs.some((x) => !x.certificate_chain || !x.private_key)) return setErr("Each certificate needs a chain and a key path.");
      cs.forEach((x) => { if (!x.server_names?.length) delete x.server_names; });
    } else delete o.tls;
    if (!o.trust_forwarded_headers) delete o.trust_forwarded_headers;
    const wanted = !!o._gateway;
    prune(o);
    update((d) => {
      const g = gw(d);
      const before = g ? new Set(g.listeners ?? d.listeners.filter(isHttp).map((x) => x.name)) : null;
      if (index == null) d.listeners.push(o); else d.listeners[index] = o;
      if (g && before) {
        if (orig) before.delete(orig.name);
        if (proto === "http" && wanted) before.add(o.name);
        const all = d.listeners.filter(isHttp).map((x) => x.name);
        const want = [...before].filter((n) => all.includes(n));
        if (want.length === all.length) delete g.listeners; else g.listeners = want;
      }
    });
    close();
  };
  const del = () => {
    if (!orig || !confirm(`Delete listener ${orig.name}? Open connections finish after you publish.`)) return;
    update((d) => { d.listeners.splice(index!, 1); const g = gw(d); if (g?.listeners) g.listeners = g.listeners.filter((n) => n !== orig.name); });
    close();
  };
  return <Aside title={orig ? orig.name : "New listener"} kind="Listener" error={err} onSave={save} onCancel={close} onDelete={orig ? del : undefined}>
    <SchemaForm schema={schema(c)} obj={obj} onChange={setObj} /></Aside>;
}

export function ListenersPage() {
  const { draft, live, ui, setUi } = useStore();
  const c = draft!, was = entities(live);
  const a = ui.aside?.type === "listener" ? ui.aside : null;
  return <>
    <PageHead title="Listeners" lede="Where the proxy accepts connections. Changing an address rebinds it on publish; connections on removed listeners finish first." actions={<DraftActions />} />
    <DraftBanner />
    <div className="cols"><section className="main-col">
      <Panel title="Listeners" action={<Button kind="sec" small onClick={() => setUi({ aside: { type: "listener", index: null } })}><Icon name="plus" size={14} width={2.2} />Add listener</Button>}>
        <div className="tw"><table>
          <thead><tr><th>Name</th><th>Address</th><th>Protocol</th><th>TLS</th><th>Handled by</th></tr></thead>
          <tbody>{c.listeners.map((l, i) => {
            const old = was.get("listener:" + l.name), flag = !old ? "New" : !same(old.obj, l) ? "Edited" : "";
            return <tr key={i} className={a?.index === i ? "sel" : ""}>
              <td><button type="button" className="linkbtn" onClick={() => setUi({ aside: { type: "listener", index: i } })}>{l.name}</button>{flag && <> <Tag kind="warn">{flag}</Tag></>}</td>
              <td className="mono small">{l.address}</td><td>{isHttp(l) ? "HTTP" : "TCP"}</td>
              <td>{l.tls ? <Tag kind="ok">{l.tls.certificates.length} certificate{l.tls.certificates.length > 1 ? "s" : ""}</Tag> : <span className="muted">None</span>}</td>
              <td className="small">{!isHttp(l) ? <>Cluster <span className="mono">{l.cluster}</span></> : gwHandles(c, l) ? "API gateway" : <>Core routes <span className="mono">{l.route_config}</span></>}</td>
            </tr>;
          })}
          {!c.listeners.length && <tr><td colSpan={5} className="muted">No listeners. Add one so the proxy accepts connections.</td></tr>}</tbody>
        </table></div>
      </Panel>
    </section>
    {a && <Editor key={String(a.index)} index={a.index} />}</div>
  </>;
}
