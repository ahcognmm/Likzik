import { useEffect, useState } from "react";
import { useStore } from "../store";
import * as api from "../api";
import { changeSummary, clientChecks, flatten, same, showVal } from "../model";
import { Button, LinkBtn, PageHead, Tag } from "../components/ui";
import { HistoryPanel } from "../components/History";

const STEPS: [string, string][] = [
  ["Validate", "The proxy's own --check reads the draft, including certificate and JWKS files."],
  ["Keep history", "The live file is saved in the change history with your note."],
  ["Write", "The config file is replaced in one atomic rename."],
  ["Reload", "The proxy builds the new generation in one piece. A rejected file changes nothing."],
  ["Switch", "Each worker moves at its next request; requests in flight finish on the old generation."],
];
interface Done { generation: number; previous: number | null; note: string; historyId: number | null; rolledBack?: boolean }

export function PublishPage() {
  const { draft, changes, server, etag, reload, refreshStatus, refreshHistory, history } = useStore();
  const [check, setCheck] = useState<{ text: string; ok: boolean; message: string } | null>(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState<Done | null>(null);
  const text = api.serialize(draft);
  const g = server?.config.generation ?? null;

  useEffect(() => { refreshHistory(); }, [refreshHistory]);
  useEffect(() => {
    if (!changes.length || done) return;
    let gone = false;
    api.validate(text).then((r) => !gone && setCheck({ text, ...r })).catch(() => !gone && setCheck({ text, ok: false, message: "The console server did not answer." }));
    return () => { gone = true; };
  }, [text, changes.length, done]);
  const checking = !check || check.text !== text;

  const publish = async () => {
    setBusy(true); setError("");
    const r = await api.apply(text, etag, note);
    setBusy(false);
    if (!r.ok) {
      setError(r.conflict ? "Someone changed the config file since you loaded it. Reload the page to start from the current file." : "The proxy rejected the draft, nothing was written: " + r.message);
      return;
    }
    await Promise.all([reload(), refreshStatus()]);
    const h = await api.history();
    await refreshHistory();
    setDone({ generation: r.generation ?? (g ?? 0) + 1, previous: r.previous_generation ?? g, note, historyId: h[0]?.id ?? null });
    setNote("");
  };
  const rollback = async () => {
    if (!done?.historyId || !confirm(`Publish the configuration of generation ${done.previous} again?`)) return;
    try {
      const old = await api.historyVersion(done.historyId);
      const f = await api.getConfig();
      const r = await api.apply(old, f.etag, `Roll back to generation ${done.previous}`);
      if (!r.ok) { alert("Roll back was rejected: " + r.message); return; }
      await Promise.all([reload(), refreshStatus(), refreshHistory()]);
      setDone({ generation: r.generation ?? 0, previous: r.previous_generation ?? done.generation, note: "", historyId: null, rolledBack: true });
    } catch (e) { alert(e instanceof Error ? e.message : String(e)); }
  };

  const next = done ? done.generation : g != null ? g + 1 : null;
  const workers = server?.worker_generations ?? [];
  const target = done ? done.generation : g;
  const onTarget = workers.filter((x) => x === target).length;
  const chips = <>{g != null && <span className="gen">Live {g}</span>}{!done && changes.length > 0 && next != null && <span className="gen draft">Draft {next}</span>}</>;

  if (!done && !changes.length) return <>
    <PageHead title="Review and publish" lede="The draft matches the live configuration." actions={chips} />
    <div className="notice dashed">Nothing to publish. Edit <a href="#routes">routes</a>, <a href="#clusters">clusters</a> or <a href="#listeners">listeners</a>, and the changes show up here.</div>
    <HistoryPanel />
  </>;

  const results = [
    checking ? (["Running", "The proxy is checking the draft…"] as const) : check!.ok ? (["Passed", "The proxy accepts this configuration: every reference, certificate and key file checks out."] as const) : (["Failed", check!.message] as const),
    ...clientChecks(draft!),
  ];
  return <>
    <PageHead title={done ? (done.rolledBack ? `Rolled back to generation ${done.generation}` : "Rolling out") : next != null ? `Review generation ${next}` : "Review and publish"}
      lede={done ? `New requests use generation ${done.generation}. Requests already in flight finish on ${done.previous}.` : `${changes.length} change${changes.length > 1 ? "s" : ""} since the live generation. Nothing reaches workers until you publish.`}
      actions={chips} />
    <div className="cols">
      <section className="main-col" aria-labelledby="chg">
        {done ? <div className="notice ok"><strong>{done.rolledBack ? "Rolled back" : "Published"} generation {done.generation}</strong>{done.note && <div className="small" style={{ marginTop: 4 }}>{done.note}</div>}</div> : <>
          <h2 id="chg" style={{ margin: 0, fontSize: 16 }}>What changes</h2>
          {changes.map((x) => {
            if (x.op === "Edited") {
              const a = flatten(x.before), b = flatten(x.obj);
              const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].filter((k) => !same(a[k], b[k]));
              return <article key={x.key} className="change"><div className="ch-head"><Tag kind="warn">Edited {x.kind}</Tag><h3>{x.label}</h3></div>
                <div className="tw"><table><thead><tr><th>Setting</th><th>Before</th><th>After</th></tr></thead>
                  <tbody>{keys.map((k) => <tr key={k}><td className="k">{k}</td><td><del>{showVal(k, a[k])}</del></td><td>{showVal(k, b[k])}</td></tr>)}</tbody></table></div></article>;
            }
            return <article key={x.key} className="change flat"><div className="ch-head"><Tag kind={x.op === "New" ? "ok" : "err"}>{x.op} {x.kind}</Tag>
              <h3>{x.op === "Removed" ? <del>{x.label}</del> : x.label}</h3><span className="small muted">{changeSummary(x)}</span></div></article>;
          })}
          <h2 style={{ margin: "8px 0 0", fontSize: 16 }}>Checks</h2>
          <div className="panel panel-body"><ul className="checks">{results.map(([res, t], i) =>
            <li key={i}><span className={`badge tag ${res === "Passed" ? "ok" : res === "Failed" ? "err" : res === "Warning" ? "warn" : ""}`}>{res}</span><span>{t}</span></li>)}</ul></div>
        </>}
        <HistoryPanel />
      </section>
      <aside className="stack" style={{ flex: "1 1 380px", maxWidth: 460 }}>
        <div className="panel panel-body"><h2 id="ap">Apply order</h2>
          <p className="small muted" style={{ margin: "2px 0 14px" }}>The proxy swaps the whole configuration at once, so a route never points at a cluster that is not there yet.</p>
          <ol className="applysteps">{STEPS.map(([l, n], i) => <li key={l} className={done ? "done" : ""}><span className="num">{i + 1}</span><span><b>{l}</b><span className="small muted">{n}</span></span></li>)}</ol></div>
        <div className="panel panel-body"><h2>Workers</h2>
          <p className="small" style={{ margin: "2px 0 12px" }}>{!server ? "The proxy is not reachable, so worker state is unknown."
            : done ? `${onTarget} of ${workers.length} workers on generation ${target}.${onTarget < workers.length ? " The others are finishing requests that started earlier." : ""}`
            : `All ${workers.length} workers serve generation ${g}.`}</p>
          <div className="workers">{workers.map((x, i) => <div key={i} className={done && x === target ? "on" : ""}><span className="id">w{i}</span><span className="g">{x}</span></div>)}</div>
          {!done && <p className="help" style={{ marginTop: 12 }}>After you publish, each worker picks up the new generation at its next request.</p>}</div>
        <div className="panel panel-body stack" style={{ gap: 12 }}>
          {!done ? <>
            <div className="field"><label htmlFor="note">Note for the change history</label>
              <textarea id="note" className="input" rows={2} placeholder="What this change is for" value={note} onChange={(e) => setNote(e.target.value)} /></div>
            <Button kind="pri" onClick={publish} disabled={checking || !check?.ok || busy}>{busy ? "Publishing…" : `Publish generation ${next ?? ""}`}</Button>
            {!checking && !check?.ok && <p className="err-text">Fix the failed check to publish.</p>}
            {error && <p className="err-text" role="alert">{error}</p>}
          </> : <>
            {done.historyId != null && !done.rolledBack && history.length > 0 && <Button kind="danger" onClick={rollback}>Roll back to generation {done.previous}</Button>}
            <LinkBtn kind="sec" href="#routes">Back to routes</LinkBtn>
          </>}
        </div>
      </aside>
    </div>
  </>;
}
