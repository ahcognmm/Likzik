// Schema-driven forms for the table + aside screens (listeners, clusters, auth).
import type { ReactNode } from "react";
import { getPath, setPath, clone } from "../model";
import { Button, Check, Field, Seg } from "./ui";

type Obj = Record<string, unknown>;
export interface Col { k?: string; label?: string; type?: "num" | "csv"; flex?: string; text?: (row: Obj) => string }
export type FieldDef = { k: string; label: string; help?: ReactNode; ph?: string; show?: (o: Obj) => boolean } & (
  | { kind: "text" | "mono" | "num" | "csv" | "secret" | "bool" }
  | { kind: "seg"; def: string; opts: [string, string][] }
  | { kind: "select"; opts: string[] }
  | { kind: "rows"; cols: Col[]; add: string; onAdd?: () => void; blank?: Obj }
);

const toText = (kind: string, v: unknown) => (kind === "csv" ? ((v as string[]) ?? []).join(", ") : v == null ? "" : String(v));
const fromText = (kind: string | undefined, t: string): unknown =>
  kind === "num" ? (t.trim() === "" ? undefined : Number(t)) : kind === "csv" ? t.split(",").map((s) => s.trim()).filter(Boolean) : t;

export function SchemaForm({ schema, obj, onChange }: { schema: FieldDef[]; obj: Obj; onChange: (o: Obj) => void }) {
  const set = (p: string, v: unknown) => { const o = clone(obj); setPath(o, p, v); onChange(o); };
  return <div className="stack">{schema.map((f) => {
    if (f.show && !f.show(obj)) return null;
    const id = "f-" + f.k.replace(/\W/g, "_"), v = getPath(obj, f.k);
    switch (f.kind) {
      case "bool": return <Check key={f.k} checked={!!v} onChange={(on) => set(f.k, on)} help={f.help}>{f.label}</Check>;
      case "seg": return <fieldset key={f.k}><legend className="legend" style={{ marginBottom: 6 }}>{f.label}</legend>
        <Seg label={f.label} value={(v as string) ?? f.def} options={f.opts} onValue={(x) => set(f.k, x)} />
        {f.help && <p className="help" style={{ marginTop: 6 }}>{f.help}</p>}</fieldset>;
      case "select": return <Field key={f.k} id={id} label={f.label} help={f.help}>
        <select id={id} className="select mono" value={(v as string) ?? ""} onChange={(e) => set(f.k, e.target.value)}>
          {!f.opts.includes(v as string) && <option value={(v as string) ?? ""}>{(v as string) || "Choose…"}</option>}
          {f.opts.map((x) => <option key={x}>{x}</option>)}</select></Field>;
      case "rows": {
        const rows = (v as Obj[]) ?? [];
        const setRow = (i: number, k: string, x: unknown) => { const o = clone(obj); setPath(o, `${f.k}.${i}.${k}`, x); onChange(o); };
        const del = (i: number) => set(f.k, rows.filter((_, j) => j !== i));
        return <div key={f.k}><div className="legend" style={{ marginBottom: 6 }}>{f.label}</div>
          <div className="stack" style={{ gap: 8 }}>{rows.map((r, i) => <div className="rule-row" key={i}>
            {f.cols.map((c, ci) => c.text ? <span key={ci} className="small muted" style={{ flex: "1 1 120px" }}>{c.text(r)}</span>
              : <input key={ci} className="input mono" aria-label={c.label} placeholder={c.label} style={c.flex ? { flex: c.flex } : undefined}
                  value={toText(c.type ?? "", r[c.k!])} onChange={(e) => setRow(i, c.k!, fromText(c.type, e.target.value))} autoComplete="off" spellCheck={false} />)}
            <Button kind="danger" small aria-label="Remove" onClick={() => del(i)}>Remove</Button></div>)}</div>
          <div style={{ marginTop: 8 }}><Button kind="sec" small onClick={() => (f.onAdd ? f.onAdd() : set(f.k, [...rows, clone(f.blank ?? {})]))}>{f.add}</Button></div>
          {f.help && <p className="help" style={{ marginTop: 6 }}>{f.help}</p>}</div>;
      }
      default: {
        const secret = f.kind === "secret";
        return <Field key={f.k} id={id} label={f.label} help={f.help}>
          <input id={id} className={`input ${f.kind === "text" ? "" : "mono"}`} type={secret ? "password" : "text"} inputMode={f.kind === "num" ? "numeric" : undefined}
            value={secret ? ((obj["_new_" + f.k] as string) ?? "") : toText(f.kind, v)}
            placeholder={secret ? (v ? "Set; type to replace" : "Not set") : f.ph}
            onChange={(e) => (secret ? set("_new_" + f.k, e.target.value) : set(f.k, fromText(f.kind, e.target.value)))}
            autoComplete="off" spellCheck={false} /></Field>;
      }
    }
  })}</div>;
}

export function Aside({ title, kind, error, onSave, onCancel, onDelete, children }: {
  title: string; kind: string; error: string; onSave: () => void; onCancel: () => void; onDelete?: () => void; children: ReactNode;
}) {
  return <aside className="panel" aria-labelledby="asd" style={{ flex: "1 1 380px", maxWidth: 460 }}>
    <div className="editor-head" style={{ paddingBottom: 16, borderBottom: "2px solid var(--ink)" }}><div className="small muted">{kind}</div><h2 id="asd">{title}</h2></div>
    <div className="editor-body">{children}{error && <p className="err-text" role="alert">{error}</p>}
      <div className="editor-foot">{onDelete && <Button kind="danger" onClick={onDelete}>Delete</Button>}
        <Button kind="sec" onClick={onCancel}>Cancel</Button><Button kind="pri" onClick={onSave}>Save to draft</Button></div></div>
  </aside>;
}

// Drops empty strings, nulls, and (optionally) empty arrays from the top level.
export function prune(o: Obj, keepEmpty: string[] = []) {
  for (const k of Object.keys(o)) {
    const v = o[k];
    if (k.startsWith("_") || v === "" || v == null || (Array.isArray(v) && !v.length && !keepEmpty.includes(k))) delete o[k];
  }
  return o;
}
