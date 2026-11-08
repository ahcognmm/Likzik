import { useState } from "react";
import { useStore } from "../store";
import { clone, entities, lbText, renameCluster, same, usedByCluster } from "../model";
import { Aside, SchemaForm, prune, type FieldDef } from "../components/Form";
import { Button, DraftActions, DraftBanner, Icon, PageHead, Panel, Tag } from "../components/ui";
import type { Cluster } from "../types";

type Obj = Record<string, unknown>;
const SCHEMA: FieldDef[] = [
  { k: "name", label: "Name", kind: "mono" },
  { k: "lb_policy", label: "Load balancing", kind: "seg", def: "least_request", opts: [["least_request", "Least request"], ["round_robin", "Round robin"], ["random", "Random"]], help: "Least request picks the less busy of two random endpoints." },
  { k: "endpoints", label: "Endpoints", kind: "rows", add: "Add endpoint", blank: { address: "" }, cols: [{ k: "address", label: "Address (ip:port)", flex: "3 1 160px" }, { k: "weight", label: "Weight", type: "num", flex: "1 1 70px" }] },
  { k: "connect_timeout_ms", label: "Connect timeout (ms)", kind: "num", ph: "2000" },
  { k: "max_connect_attempts", label: "Connect attempts", kind: "num", ph: "2", help: "Connect failures move on to another endpoint, up to this many tries." },
  { k: "eject_after_failures", label: "Eject after consecutive failures", kind: "num", ph: "3" },
  { k: "eject_ms", label: "Ejection time (ms)", kind: "num", ph: "10000", help: "Doubles on repeated ejections." },
  { k: "idle_timeout_ms", label: "Idle connection timeout (ms)", kind: "num", ph: "30000" },
  { k: "max_idle_per_endpoint", label: "Idle connections kept per endpoint", kind: "num", ph: "64" },
  { k: "_tls", label: "Use TLS to the endpoints", kind: "bool" },
  { k: "tls.sni", label: "Server name (SNI)", kind: "mono", show: (o) => !!o._tls, help: "Also checked against the endpoint's certificate." },
  { k: "_verify", label: "Verify the endpoint's certificate", kind: "bool", show: (o) => !!o._tls },
  { k: "tls.ca_file", label: "CA bundle (PEM path)", kind: "mono", ph: "System trust store", show: (o) => !!o._tls },
];

function Editor({ index }: { index: number | null }) {
  const { draft, update, setUi } = useStore();
  const c = draft!, list = c.clusters ?? [];
  const orig = index == null ? null : list[index];
  const [obj, setObj] = useState<Obj>(() => {
    if (!orig) return { name: "", endpoints: [{ address: "" }], _tls: false, _verify: true, tls: {} };
    const o = clone(orig) as unknown as Obj;
    o._tls = !!orig.tls; o._verify = orig.tls?.verify !== false; if (!orig.tls) o.tls = {};
    return o;
  });
  const [err, setErr] = useState("");
  const close = () => setUi({ aside: null });
  const used = orig ? usedByCluster(c, orig.name) : [];

  const save = () => {
    const o = clone(obj) as Obj & Cluster;
    if (!o.name) return setErr("Enter a name.");
    if (list.some((x, i) => i !== index && x.name === o.name)) return setErr(`Another cluster is already called ${o.name}.`);
    o.endpoints = (o.endpoints ?? []).filter((e) => e.address);
    if (!o.endpoints.length) return setErr("Add at least one endpoint.");
    o.endpoints.forEach((e) => { if (!e.weight || e.weight === 1) delete e.weight; });
    if (!o._tls) delete o.tls;
    else {
      const t = o.tls ?? {};
      if (o._verify && !t.sni) return setErr("Certificate verification needs a server name (SNI).");
      if (!o._verify) t.verify = false; else delete t.verify;
      if (!t.ca_file) delete t.ca_file;
      if (!t.sni) delete t.sni;
      o.tls = t;
    }
    prune(o);
    update((d) => {
      d.clusters = d.clusters ?? [];
      if (index == null) d.clusters.push(o); else d.clusters[index] = o;
      if (orig && orig.name !== o.name) renameCluster(d, orig.name, o.name);
    });
    close();
  };
  const del = () => {
    if (!orig) return;
    if (used.length) return setErr(`Still used by ${used.join(", ")}. Point those at another cluster first.`);
    if (!confirm(`Delete cluster ${orig.name}?`)) return;
    update((d) => { d.clusters!.splice(index!, 1); });
    close();
  };
  return <Aside title={orig ? orig.name : "New cluster"} kind="Cluster" error={err} onSave={save} onCancel={close} onDelete={orig ? del : undefined}>
    <SchemaForm schema={SCHEMA} obj={obj} onChange={setObj} />
    {used.length > 0 && <p className="help">Used by {used.join(", ")}. Renaming updates them too.</p>}
  </Aside>;
}

export function ClustersPage() {
  const { draft, live, ui, setUi } = useStore();
  const c = draft!, was = entities(live);
  const a = ui.aside?.type === "cluster" ? ui.aside : null;
  return <>
    <PageHead title="Clusters" lede="Groups of upstream endpoints, with load balancing, ejection of failing endpoints and pooled connections." actions={<DraftActions />} />
    <DraftBanner />
    <div className="cols"><section className="main-col">
      <Panel title="Clusters" action={<Button kind="sec" small onClick={() => setUi({ aside: { type: "cluster", index: null } })}><Icon name="plus" size={14} width={2.2} />Add cluster</Button>}>
        <div className="tw"><table>
          <thead><tr><th>Name</th><th>Endpoints</th><th>Balancing</th><th>Used by</th></tr></thead>
          <tbody>{(c.clusters ?? []).map((x, i) => {
            const old = was.get("cluster:" + x.name), flag = !old ? "New" : !same(old.obj, x) ? "Edited" : "";
            const used = usedByCluster(c, x.name);
            return <tr key={i} className={a?.index === i ? "sel" : ""}>
              <td><button type="button" className="linkbtn" onClick={() => setUi({ aside: { type: "cluster", index: i } })}>{x.name}</button>
                {flag && <> <Tag kind="warn">{flag}</Tag></>}{x.tls && <> <Tag>TLS</Tag></>}</td>
              <td><span className="tags">{x.endpoints.map((e, j) => <Tag key={j} mono>{e.address}{(e.weight ?? 1) > 1 ? " ×" + e.weight : ""}</Tag>)}</span></td>
              <td className="small">{lbText[x.lb_policy ?? "least_request"]}</td>
              <td className="small">{used.length ? `${used.length} ${used.length === 1 ? "user" : "users"}` : <Tag kind="warn">Unused</Tag>}</td>
            </tr>;
          })}
          {!c.clusters?.length && <tr><td colSpan={4} className="muted">No clusters. Add one, then point routes at it.</td></tr>}</tbody>
        </table></div>
      </Panel>
    </section>
    {a && <Editor key={String(a.index)} index={a.index} />}</div>
  </>;
}
