// Primitives of the console design system (src/ui/CLAUDE.md).
import type { ReactNode, InputHTMLAttributes, SelectHTMLAttributes } from "react";
import { useStore } from "../store";

const ICONS = {
  status: <path d="M3 12h4l3-7 4 14 3-7h4" />,
  routing: <><circle cx="6" cy="6" r="2" /><circle cx="6" cy="18" r="2" /><circle cx="18" cy="12" r="2" /><path d="M6 8v8M8 6h4a4 4 0 0 1 4 4v0" /></>,
  cert: <path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z" />,
  auth: <><rect x="5" y="11" width="14" height="9" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></>,
  publish: <path d="M12 16V4M7 9l5-5 5 5M5 20h14" />,
  docs: <path d="M4 5h6a2 2 0 0 1 2 2v12a2 2 0 0 0-2-2H4zM20 5h-6a2 2 0 0 0-2 2v12a2 2 0 0 1 2-2h6z" />,
  plus: <path d="M12 5v14M5 12h14" />,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  search: <><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></>,
  up: <path d="M6 15l6-6 6 6" />,
  down: <path d="M6 9l6 6 6-6" />,
};
export type IconName = keyof typeof ICONS;
export function Icon({ name, size = 18, width = 1.8 }: { name: IconName; size?: number; width?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={width} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{ICONS[name]}</svg>;
}

type BtnKind = "pri" | "sec" | "danger" | "plain";
export function Button({ kind = "plain", small, children, ...rest }: { kind?: BtnKind; small?: boolean; children: ReactNode } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button type="button" className={`btn ${kind === "plain" ? "" : kind} ${small ? "sm" : ""}`} {...rest}>{children}</button>;
}
export function LinkBtn({ kind = "plain", small, href, children }: { kind?: BtnKind; small?: boolean; href: string; children: ReactNode }) {
  return <a className={`btn ${kind === "plain" ? "" : kind} ${small ? "sm" : ""}`} href={href}>{children}</a>;
}

export function Field({ id, label, help, children }: { id: string; label: ReactNode; help?: ReactNode; children: ReactNode }) {
  return <div className="field"><label htmlFor={id}>{label}</label>{children}{help && <p className="help">{help}</p>}</div>;
}
export function TextInput({ mono = true, value, onValue, ...rest }: { mono?: boolean; value: string | number | undefined; onValue: (v: string) => void } & Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">) {
  return <input className={`input ${mono ? "mono" : ""}`} value={value ?? ""} onChange={(e) => onValue(e.target.value)} autoComplete="off" spellCheck={false} {...rest} />;
}
export function NumInput({ value, onValue, ...rest }: { value: number | undefined; onValue: (v: number | undefined) => void } & Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">) {
  return <input className="input mono" inputMode="numeric" value={value ?? ""} onChange={(e) => { const t = e.target.value.trim(); onValue(t === "" ? undefined : Number(t)); }} autoComplete="off" {...rest} />;
}
export function Select({ value, onValue, options, ...rest }: { value: string | undefined; onValue: (v: string) => void; options: (string | [string, string])[] } & Omit<SelectHTMLAttributes<HTMLSelectElement>, "value" | "onChange">) {
  const opts = options.map((o) => (Array.isArray(o) ? o : [o, o]));
  const known = opts.some(([v]) => v === value);
  return <select className="select mono" value={value ?? ""} onChange={(e) => onValue(e.target.value)} {...rest}>
    {!known && <option value={value ?? ""}>{value || "Choose…"}</option>}
    {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
  </select>;
}
export function Seg<T extends string>({ label, value, options, onValue, multi }: { label: string; value: T | T[] | undefined; options: [T, string][]; onValue: (v: T) => void; multi?: boolean }) {
  const on = (v: T) => (multi ? ((value as T[]) ?? []).includes(v) : value === v);
  return <div className="seg" role="group" aria-label={label}>{options.map(([v, l]) => <button key={v} type="button" aria-pressed={on(v)} onClick={() => onValue(v)}>{l}</button>)}</div>;
}
export function CardOption({ type = "radio", name, checked, onChange, title, help }: { type?: "radio" | "checkbox"; name?: string; checked: boolean; onChange: (on: boolean) => void; title: ReactNode; help?: ReactNode }) {
  return <label className={`card-opt ${checked ? "on" : ""}`}><input type={type} name={name} checked={checked} onChange={(e) => onChange(e.target.checked)} /><span><b>{title}</b>{help && <span className="h">{help}</span>}</span></label>;
}
export function Check({ checked, onChange, children, help }: { checked: boolean; onChange: (on: boolean) => void; children: ReactNode; help?: ReactNode }) {
  return <label className="check"><input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} /><span>{children}{help && <span className="help" style={{ display: "block" }}>{help}</span>}</span></label>;
}
export function Tag({ kind, children, mono }: { kind?: "ok" | "warn" | "err"; children: ReactNode; mono?: boolean }) {
  return <span className={`tag ${kind ?? ""} ${mono ? "mono" : ""}`}>{children}</span>;
}
export function Legend({ children }: { children: ReactNode }) { return <legend className="legend" style={{ marginBottom: 6 }}>{children}</legend>; }

export function PageHead({ title, lede, actions }: { title: string; lede?: ReactNode; actions?: ReactNode }) {
  return <div className="head"><div><p className="eyebrow">Gateway console</p><h1>{title}</h1>{lede && <p className="lede muted">{lede}</p>}</div>{actions && <div className="actions">{actions}</div>}</div>;
}
export function DraftBanner() {
  const { changes, server } = useStore();
  if (!changes.length) return null;
  const g = server?.config.generation;
  return <div className="banner"><strong>{changes.length} change{changes.length > 1 ? "s" : ""} not published</strong>
    <span>{g != null ? `You are editing a draft of generation ${g + 1}. Workers keep serving generation ${g} until you publish.` : "You are editing a draft. Workers keep serving the live configuration until you publish."}</span></div>;
}
export function DraftActions() {
  const { changes, discard } = useStore();
  return <>{changes.length > 0 && <Button onClick={() => { if (confirm("Discard every unpublished change?")) discard(); }}>Discard draft</Button>}<LinkBtn kind="pri" href="#publish">Review and publish</LinkBtn></>;
}
export function Panel({ title, sub, action, children, id }: { title?: ReactNode; sub?: ReactNode; action?: ReactNode; children: ReactNode; id?: string }) {
  return <div className="panel">{title && <div className="panel-head"><div><h2 id={id}>{title}</h2>{sub && <p className="small muted">{sub}</p>}</div>{action}</div>}{children}</div>;
}
export const fmtNum = (n: number | null | undefined) => n == null || Number.isNaN(n) ? "Unknown" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e4 ? (n / 1e3).toFixed(1) + "k" : String(Math.round(n));
