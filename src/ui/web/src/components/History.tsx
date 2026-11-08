import { useStore } from "../store";
import * as api from "../api";
import { Button } from "./ui";
import type { Config } from "../types";

export function HistoryPanel({ limit = 10 }: { limit?: number }) {
  const { history, changes, replaceDraft, go } = useStore();
  if (!history.length) return null;
  const load = async (id: number) => {
    try {
      const text = await api.historyVersion(id);
      if (changes.length && !confirm("Replace the current draft with this earlier version?")) return;
      replaceDraft(JSON.parse(text) as Config);
      go("publish");
    } catch (e) { alert(e instanceof Error ? e.message : String(e)); }
  };
  return <div className="panel">
    <div className="panel-head"><div><h2>Change history</h2><p className="small muted">Each publish keeps the version it replaced. Load one to review it and publish it again.</p></div></div>
    <div className="tw"><table>
      <thead><tr><th>Published</th><th>Note</th><th>Kept version</th><th /></tr></thead>
      <tbody>{history.slice(0, limit).map((e) => <tr key={e.id}>
        <td className="small" style={{ whiteSpace: "nowrap" }}>{new Date(e.time_ms).toLocaleString()}</td>
        <td className="small">{e.note || "No note"}</td>
        <td className="mono small">{e.replaced_generation != null ? "gen " + e.replaced_generation : ""}</td>
        <td style={{ textAlign: "right" }}><Button kind="sec" small onClick={() => load(e.id)}>{e.replaced_generation != null ? `Load generation ${e.replaced_generation}` : "Load into draft"}</Button></td>
      </tr>)}</tbody>
    </table></div>
  </div>;
}
