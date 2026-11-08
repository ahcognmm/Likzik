import { useEffect, useState } from "react";
import { useStore } from "../store";
import { Button, PageHead, Tag, fmtNum } from "../components/ui";
import { HistoryPanel } from "../components/History";

const ago = (ms: number) => { const s = Math.round((Date.now() - ms) / 1000); return s < 90 ? `${s} s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`; };
const pct = (a: number, b: number) => (b ? ((100 * a) / b).toFixed(1) + "%" : "None yet");

export function StatusPage() {
  const { server: si, stats, adminUp, path, history, refreshHistory, rps } = useStore();
  const [errOpen, setErrOpen] = useState(false);
  useEffect(() => { refreshHistory(); }, [refreshHistory]);
  const st = stats ?? {};
  const ws = si?.worker_generations ?? [];
  const gen = si?.config.generation;
  const tlsTotal = (st.tls_ktls ?? 0) + (st.tls_userspace ?? 0);
  const signals: [string, string, string, boolean][] = [
    ["TLS handled in the kernel", "Share of TLS connections on kTLS. The rest use slower userspace TLS.", tlsTotal ? pct(st.tls_ktls ?? 0, tlsTotal) : "No TLS yet", tlsTotal > 0 && (st.tls_userspace ?? 0) > 0],
    ["Receive buffers ran out", "Times a worker had no free buffer for incoming data, since the proxy started.", fmtNum(st.buffer_ring_enobufs), (st.buffer_ring_enobufs ?? 0) > 0],
    ["Upstream connections reused", "Requests sent on an existing upstream connection.", pct(st.upstream_cx_pool_hit ?? 0, st.upstream_rq_total ?? 0), false],
    ["Workers on the live generation", "Workers that have picked up the latest configuration.", si ? `${ws.filter((x) => x === gen).length} of ${ws.length}` : "Unknown", !!si && ws.some((x) => x !== gen)],
    ["Upstream connect failures", "Connections to endpoints that failed, since the proxy started.", fmtNum(st.upstream_cx_connect_fail), (st.upstream_cx_connect_fail ?? 0) > 0],
    ["Requests per second", "Measured while this page is open.", rps == null ? "Measuring" : fmtNum(rps), false],
  ];
  return <>
    <PageHead title="Sources and status" lede="Every source feeds the same validator. A change that fails validation is rejected and the proxy keeps running the last good generation." />
    <div className="sources">
      <section className="panel panel-body">
        <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center" }}><h2>Config file</h2>
          <Tag kind={adminUp ? "ok" : "err"}>{adminUp ? "Watching" : adminUp === false ? "Proxy unreachable" : "Checking"}</Tag></div>
        <p className="mono small" style={{ marginTop: 6, wordBreak: "break-all" }}>{path}</p>
        <dl className="facts">
          <dt>Owns</dt><dd>Listeners, routes, clusters and the gateway, edited in this console</dd>
          <dt>Picks up</dt><dd>Every save of the file, within a second</dd>
          <dt>Last applied</dt><dd>{si ? `Generation ${gen}${history[0] ? ", " + ago(history[0].time_ms) : ""}` : "Unknown"}</dd>
          <dt>Reloads</dt><dd>{si ? `${si.config.reloads_ok} applied, ${si.config.reloads_failed} rejected since the proxy started` : "Unknown"}</dd>
        </dl>
      </section>
      <section className="panel panel-body" style={{ borderStyle: "dashed" }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center" }}><h2>Control plane (xDS)</h2><Tag>Not available</Tag></div>
        <p className="small" style={{ marginTop: 10 }}>This version reads its configuration from the file only. An Envoy-compatible xDS control plane is planned; when it arrives it will feed the same validator and show up here.</p>
      </section>
    </div>

    <section className="panel" aria-labelledby="ver">
      <div className="panel-head"><div><h2 id="ver">What each worker is running</h2><p className="small muted">A rejected reload leaves every worker on the previous generation.</p></div></div>
      <div className="tw"><table>
        <thead><tr><th scope="col">Worker</th><th scope="col">Generation</th><th scope="col">State</th></tr></thead>
        <tbody>
          {ws.map((x, i) => <tr key={i} style={x !== gen ? { background: "var(--warn-bg)" } : undefined}>
            <td className="mono" style={{ fontWeight: 600 }}>w{i}</td><td className="mono">{x}</td>
            <td>{x === gen ? <Tag kind="ok">Live</Tag> : <Tag kind="warn">Finishing requests on an older generation</Tag>}</td></tr>)}
          {!ws.length && <tr><td colSpan={3} className="muted">{adminUp === false ? "The proxy's admin endpoint does not answer. Check that likzik is running and that its admin address is reachable." : "Waiting for the proxy…"}</td></tr>}
        </tbody>
      </table></div>
      {si?.config.last_error && <div style={{ margin: "0 20px 20px", border: "2px solid var(--err-line)", background: "var(--err-bg)", padding: "12px 16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}><strong>The last reload was rejected</strong>
          <Button kind="sec" small aria-expanded={errOpen} onClick={() => setErrOpen(!errOpen)}>{errOpen ? "Hide details" : "Show details"}</Button></div>
        <p className="small" style={{ marginTop: 6 }}>Workers stay on generation {gen}. Fix the file and save it again, or publish from this console.</p>
        {errOpen && <pre className="detail">{si.config.last_error}</pre>}
      </div>}
    </section>

    <div className="sources">
      <section className="panel panel-body" aria-labelledby="drn"><h2 id="drn">Draining</h2>
        {si?.state === "draining" ? <p style={{ marginTop: 8 }}>The proxy is draining: listeners are closed and open connections are finishing before it exits.</p>
          : <p className="small muted" style={{ marginTop: 4 }}>Nothing is draining. Removed listeners stop accepting and let open connections finish; the proxy does not report per-listener progress yet.</p>}
      </section>
      <section className="panel panel-body" aria-labelledby="hl"><h2 id="hl">Runtime checks</h2>
        <p className="small muted" style={{ margin: "2px 0 8px" }}>Signals that the fast path is still the fast path.</p>
        <ul className="signals">{signals.map(([n, h, v, w]) => <li key={n}><span><b>{n}</b><span className="small muted">{h}</span></span><span className={`val ${w ? "warn" : ""}`}>{v}</span></li>)}</ul>
      </section>
    </div>
    <HistoryPanel />
  </>;
}
