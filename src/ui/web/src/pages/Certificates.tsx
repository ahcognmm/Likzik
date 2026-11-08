import { useStore } from "../store";
import { Check, DraftActions, DraftBanner, PageHead, Panel, Tag } from "../components/ui";

export function CertificatesPage() {
  const { draft, update, setUi, go } = useStore();
  const c = draft!;
  const rows = c.listeners.flatMap((l, li) => (l.tls?.certificates ?? []).map((ct, i) => ({ l, li, ct, i })));
  const up = (c.clusters ?? []).filter((x) => x.tls);
  const kt = c.tls?.require_ktls !== false;
  const open = (li: number) => { setUi({ aside: { type: "listener", index: li } }); go("listeners"); };
  return <>
    <PageHead title="Certificates" lede="TLS certificates the listeners present, and how upstream servers are checked. Files are read when the configuration is published; a missing or broken file is rejected before anything changes." actions={<DraftActions />} />
    <DraftBanner />
    <Panel title="Served by listeners">
      <div className="tw"><table>
        <thead><tr><th>Listener</th><th>Names (SNI)</th><th>Certificate chain</th><th>Private key</th></tr></thead>
        <tbody>{rows.map(({ l, li, ct, i }) => <tr key={`${li}-${i}`}>
          <td><button type="button" className="linkbtn" onClick={() => open(li)}>{l.name}</button>{i === 0 && <> <Tag>Default</Tag></>}</td>
          <td className="mono small">{ct.server_names?.join(", ") || "Any name"}</td>
          <td className="mono small">{ct.certificate_chain}</td><td className="mono small">{ct.private_key}</td></tr>)}
        {!rows.length && <tr><td colSpan={4} className="muted">No listener terminates TLS. Turn it on in a listener's settings.</td></tr>}</tbody>
      </table></div>
    </Panel>
    <Panel title="Checked on upstreams">
      <div className="tw"><table>
        <thead><tr><th>Cluster</th><th>Server name</th><th>Verification</th><th>CA bundle</th></tr></thead>
        <tbody>{up.map((x) => <tr key={x.name}>
          <td className="mono small">{x.name}</td><td className="mono small">{x.tls!.sni ?? "None"}</td>
          <td>{x.tls!.verify === false ? <Tag kind="warn">Off</Tag> : <Tag kind="ok">On</Tag>}</td>
          <td className="mono small">{x.tls!.ca_file ?? "System trust store"}</td></tr>)}
        {!up.length && <tr><td colSpan={4} className="muted">No cluster uses TLS to its endpoints.</td></tr>}</tbody>
      </table></div>
    </Panel>
    <div className="panel panel-body stack"><h2>Kernel TLS</h2>
      <p>After the handshake, likzik hands encryption to the kernel (kTLS), so HTTPS uses the same fast path as plain HTTP.</p>
      <Check checked={kt} onChange={(on) => update((d) => { if (on) { if (d.tls) { delete d.tls.require_ktls; if (!Object.keys(d.tls).length) delete d.tls; } } else d.tls = { ...(d.tls ?? {}), require_ktls: false }; })}
        help="When on, a configuration with TLS is rejected if the kernel's tls module is not loaded. When off, TLS falls back to slower userspace encryption.">Require kernel TLS</Check>
    </div>
  </>;
}
