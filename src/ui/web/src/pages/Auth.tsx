import { useState } from "react";
import { useStore } from "../store";
import { clone, ensureGw, gw, limitText } from "../model";
import { Aside, SchemaForm, prune, type FieldDef } from "../components/Form";
import { Button, DraftActions, DraftBanner, Icon, PageHead, Panel, Tag } from "../components/ui";
import type { ApiKeySet, JwtProvider, RateLimit } from "../types";

type Obj = Record<string, unknown>;
type Kind = "jwt" | "api_keys" | "rate_limits";
const LABEL: Record<Kind, string> = { jwt: "JWT provider", api_keys: "API key set", rate_limits: "Rate limit" };

const JWT: FieldDef[] = [
  { k: "name", label: "Name", kind: "mono" },
  { k: "algorithms", label: "Allowed algorithms", kind: "csv", help: "Any of RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA, HS256, HS384, HS512." },
  { k: "issuer", label: "Issuer", kind: "mono", ph: "Not checked" },
  { k: "audiences", label: "Audiences", kind: "csv", ph: "Not checked" },
  { k: "jwks_file", label: "JWKS file", kind: "mono", ph: "/etc/likzik/jwks.json", help: "Read when the configuration loads. Publish again to pick up rotated keys." },
  { k: "hs_secret", label: "Shared secret for HS algorithms", kind: "secret", help: "At least 32 bytes." },
  { k: "consumer_claim", label: "Claim that names the consumer", kind: "mono", ph: "sub" },
  { k: "claims_to_headers", label: "Claims copied to headers", kind: "rows", add: "Add claim", blank: { claim: "", header: "" }, cols: [{ k: "claim", label: "Claim" }, { k: "header", label: "Header" }] },
  { k: "leeway_s", label: "Clock leeway (seconds)", kind: "num", ph: "30" },
  { k: "forward_token", label: "Forward the token upstream", kind: "bool" },
];
const LIMIT: FieldDef[] = [
  { k: "name", label: "Name", kind: "mono" },
  { k: "requests", label: "Requests", kind: "num" },
  { k: "per", label: "Per", kind: "seg", def: "second", opts: [["second", "Second"], ["minute", "Minute"], ["hour", "Hour"]] },
  { k: "burst", label: "Burst", kind: "num", ph: "Same as requests" },
  { k: "key", label: "Counted per", kind: "mono", ph: "client_ip", help: "client_ip, consumer, route, or header:Name." },
];
const keysetSchema = (onAdd: () => void): FieldDef[] => [
  { k: "name", label: "Name", kind: "mono" },
  { k: "header", label: "Header", kind: "mono", ph: "X-API-Key" },
  { k: "query", label: "Query parameter (optional)", kind: "mono", ph: "Not accepted" },
  { k: "strip", label: "Remove the key before forwarding", kind: "bool" },
  { k: "keys", label: "Consumers", kind: "rows", add: "Add consumer with a new key", onAdd,
    cols: [{ k: "consumer", label: "Consumer" }, { text: (r) => (r.sha256 ? "Key stored as a hash" : r.key ? "Plain key in the config file" : "No key") }],
    help: "New keys are generated here and stored as SHA-256 hashes; the key itself is shown once." },
];

const hex = (b: ArrayBuffer | Uint8Array) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
async function newKey(): Promise<{ key: string; sha256: string } | null> {
  const bytes = new Uint8Array(24); crypto.getRandomValues(bytes);
  const key = "lkz_" + hex(bytes);
  if (!crypto.subtle) return null; // only in a secure context (https or localhost)
  return { key, sha256: hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key))) };
}

function Editor({ kind, index }: { kind: Kind; index: number | null }) {
  const { draft, update, setUi } = useStore();
  const g = gw(draft)!;
  const list = (g[kind] ?? []) as { name: string }[];
  const orig = index == null ? null : list[index];
  const [obj, setObj] = useState<Obj>(() => orig ? clone(orig) as unknown as Obj
    : kind === "jwt" ? { name: "", algorithms: ["RS256"] } : kind === "api_keys" ? { name: "", header: "X-API-Key", strip: true, keys: [] } : { name: "", requests: 100, per: "second" });
  const [err, setErr] = useState("");
  const [shown, setShown] = useState<{ key: string; consumer: string } | null>(null);
  const close = () => setUi({ aside: null });

  const addKey = async () => {
    const consumer = prompt("Consumer name for the new key:")?.trim();
    if (!consumer) return;
    const k = await newKey();
    if (!k) return setErr("This browser can hash keys only on https or localhost. Open the console there to add keys.");
    setObj((o) => ({ ...o, keys: [...((o.keys as Obj[]) ?? []), { consumer, sha256: k.sha256 }] }));
    setShown({ key: k.key, consumer });
  };
  const schema = kind === "jwt" ? JWT : kind === "rate_limits" ? LIMIT : keysetSchema(addKey);

  const save = () => {
    const o = clone(obj);
    const name = o.name as string;
    if (!name) return setErr("Enter a name.");
    const space = kind === "rate_limits" ? (g.rate_limits ?? []) : [...(g.jwt ?? []), ...(g.api_keys ?? [])];
    if (space.some((x) => x.name === name && x !== orig)) return setErr(`The name ${name} is already used.`);
    if (kind === "jwt") {
      const j = o as Obj & JwtProvider;
      if (o._new_hs_secret) j.hs_secret = o._new_hs_secret as string;
      if (!j.algorithms?.length) return setErr("List at least one allowed algorithm.");
      if (!j.jwks_file && !j.jwks && !j.hs_secret) return setErr("Give a JWKS file or a shared secret.");
      if (j.claims_to_headers) j.claims_to_headers = j.claims_to_headers.filter((x) => x.claim && x.header);
      if (!j.forward_token) delete j.forward_token;
    }
    if (kind === "api_keys") {
      const s = o as Obj & ApiKeySet;
      s.keys = (s.keys ?? []).filter((k) => k.consumer);
      if (!s.keys.length) return setErr("Add at least one consumer.");
    }
    if (kind === "rate_limits" && !((o as Obj & RateLimit).requests > 0)) return setErr("Requests must be more than 0.");
    prune(o, ["keys"]);
    update((d) => {
      const gg = ensureGw(d);
      const bag = gg as unknown as Record<Kind, Obj[] | undefined>;
      const l = (bag[kind] = bag[kind] ?? []);
      if (index == null) l.push(o); else l[index] = o;
      if (orig && orig.name !== name) {
        const f = kind === "rate_limits" ? "rate_limits" : "auth";
        for (const r of gg.routes ?? []) if (r[f]) r[f] = r[f]!.map((n) => (n === orig.name ? name : n));
      }
    });
    close();
  };
  const del = () => {
    if (!orig) return;
    const f = kind === "rate_limits" ? "rate_limits" : "auth";
    const users = (g.routes ?? []).filter((r) => r[f]?.includes(orig.name)).map((r) => r.name);
    if (users.length) return setErr(`Still used by ${users.join(", ")}. Remove it from those routes first.`);
    if (!confirm(`Delete ${LABEL[kind].toLowerCase()} ${orig.name}?`)) return;
    update((d) => { (gw(d)![kind] as unknown[]).splice(index!, 1); });
    close();
  };
  return <Aside title={orig ? orig.name : "New " + LABEL[kind].toLowerCase()} kind={LABEL[kind]} error={err} onSave={save} onCancel={close} onDelete={orig ? del : undefined}>
    {shown && <div className="notice warn stack" style={{ gap: 8 }} role="status"><strong>Copy this key now: only its hash is saved</strong>
      <div className="keyshow">{shown.key}</div><span>For consumer <span className="mono">{shown.consumer}</span>. It works after you publish.</span></div>}
    <SchemaForm schema={schema} obj={obj} onChange={setObj} />
  </Aside>;
}

export function AuthPage() {
  const { draft, ui, setUi, update } = useStore();
  const g = gw(draft);
  const head = <PageHead title="Auth providers" lede="API keys, JWT providers and rate limits used by gateway routes. Routes refer to them by name." actions={<DraftActions />} />;
  if (!g) return <>{head}<DraftBanner />
    <div className="notice dashed stack"><p>This configuration has no API gateway section, so routes cannot use auth or rate limits. Run the proxy as <span className="mono">likzik-gw</span> and add the gateway.</p>
      <div><Button kind="pri" small onClick={() => update((d) => { ensureGw(d); })}>Add the API gateway</Button></div></div></>;

  const a = ui.aside && ["jwt", "api_keys", "rate_limits"].includes(ui.aside.type) ? (ui.aside as { type: Kind; index: number | null }) : null;
  const usedBy = (n: string, f: "auth" | "rate_limits") => (g.routes ?? []).filter((r) => r[f]?.includes(n)).map((r) => r.name);
  const table = <T extends { name: string }>(kind: Kind, title: string, list: T[], settings: (x: T) => React.ReactNode) =>
    <Panel title={title} action={<Button kind="sec" small onClick={() => setUi({ aside: { type: kind, index: null } })}><Icon name="plus" size={14} width={2.2} />Add</Button>}>
      <div className="tw"><table>
        <thead><tr><th>Name</th><th>Settings</th><th>Used by</th></tr></thead>
        <tbody>{list.map((x, i) => { const u = usedBy(x.name, kind === "rate_limits" ? "rate_limits" : "auth");
          return <tr key={i} className={a?.type === kind && a.index === i ? "sel" : ""}>
            <td><button type="button" className="linkbtn" onClick={() => setUi({ aside: { type: kind, index: i } })}>{x.name}</button></td>
            <td className="small">{settings(x)}</td>
            <td className="small">{u.length ? u.join(", ") : <Tag kind="warn">Unused</Tag>}</td></tr>; })}
        {!list.length && <tr><td colSpan={3} className="muted">None yet.</td></tr>}</tbody>
      </table></div>
    </Panel>;
  return <>{head}<DraftBanner />
    <div className="cols"><section className="main-col">
      {table("jwt", "JWT providers", g.jwt ?? [], (x) => <>{x.algorithms.join(", ")}{x.issuer && <>, issuer <span className="mono">{x.issuer}</span></>}</>)}
      {table("api_keys", "API keys", g.api_keys ?? [], (x) => `${x.keys.length} consumer${x.keys.length === 1 ? "" : "s"}: ${x.keys.map((k) => k.consumer).join(", ")}`)}
      {table("rate_limits", "Rate limits", g.rate_limits ?? [], (x) => limitText(x))}
      <p className="small muted">Rate limits are counted by each worker on its own. A limit shared across machines (a rate limit service) is not available in this version.</p>
    </section>
    {a && <Editor key={a.type + String(a.index)} kind={a.type} index={a.index} />}</div>
  </>;
}
