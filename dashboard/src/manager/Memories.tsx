import { useState } from "preact/hooks";
import { api, ApiError } from "./api";
import type { Memory } from "./api";
import { Err } from "./common";
import { useLoad } from "./useApi";

const KIND_LABEL: Record<string, string> = { false_positive: "judged harmless", confirmed: "confirmed real", accepted_risk: "accepted risk", context: "project note" };

/** Team memories: short notes the model reviewer sees when a similar finding comes up. */
export function Memories({ projectId, projectName }: { projectId: string; projectName: string }) {
  const base = `/api/projects/${projectId}/memories`;
  const { data, error, reload } = useLoad(() => api<Memory[]>("GET", base), [projectId]);
  const [text, setText] = useState("");
  const [path, setPath] = useState("");
  const [kind, setKind] = useState("context");
  const [msg, setMsg] = useState("");
  const add = async (e: Event) => {
    e.preventDefault();
    try { await api("POST", base, { text, path, kind }); setText(""); setPath(""); setMsg(""); reload(); }
    catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); }
  };
  const toggle = async (m: Memory) => { try { await api("PUT", `${base}/${m.id}`, { enabled: !m.enabled }); reload(); } catch (x) { setMsg(String(x)); } };
  const remove = async (m: Memory) => { try { await api("DELETE", `${base}/${m.id}`); reload(); } catch (x) { setMsg(String(x)); } };
  return (
    <section class="cc-card" style="margin-top:16px" aria-labelledby="mem-h">
      <h2 class="big" id="mem-h">Team memories · {projectName}</h2>
      <p class="cc-note" style="margin-top:-6px">Short notes the model reviewer sees when a similar finding comes up: what is deployed, what you already judged safe or real. They are context, never proof, and cannot override GapScan's safety rules. A reviewer decision with a note creates one automatically, and every verdict lists the memories it used.</p>
      <Err text={msg || error} />
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Note</th><th>Kind</th><th>Applies to</th><th>Source</th><th /></tr></thead><tbody>
        {data?.map((m) => (
          <tr key={m.id} style={m.enabled ? "" : "opacity:0.5"}>
            <td>{m.text}</td><td><span class="badge2">{KIND_LABEL[m.kind] ?? m.kind}</span></td>
            <td class="mono" style="font-size:12px">{[m.rule && `rule ${m.rule}`, m.path && `under ${m.path}`, m.cwe].filter(Boolean).join(", ") || "whole project"}</td>
            <td class="cc-note">{m.source.startsWith("decision:") ? "reviewer decision" : m.source}</td>
            <td style="white-space:nowrap"><button class="btn sm" onClick={() => toggle(m)}>{m.enabled ? "Disable" : "Enable"}</button> <button class="btn sm warn" onClick={() => remove(m)}>Delete</button></td>
          </tr>
        ))}
        {data?.length === 0 && <tr><td colSpan={5} class="cc-note" style="padding:12px">No memories yet.</td></tr>}
      </tbody></table></div>
      <form onSubmit={add} style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-top:14px">
        <label class="cc-field" style="margin:0;flex:2;min-width:260px"><span>Note (at least 12 characters)</span><input class="cc-input" value={text} onInput={(e) => setText(e.currentTarget.value)} aria-label="Memory note" /></label>
        <label class="cc-field" style="margin:0;flex:1;min-width:140px"><span>Only under folder (optional)</span><input class="cc-input mono" value={path} onInput={(e) => setPath(e.currentTarget.value)} placeholder="src/logs" aria-label="Memory folder" /></label>
        <label class="cc-field" style="margin:0"><span>Kind</span><select class="cc-select" value={kind} onChange={(e) => setKind(e.currentTarget.value)} aria-label="Memory kind">{Object.entries(KIND_LABEL).map(([k, v]) => <option value={k} key={k}>{v}</option>)}</select></label>
        <button class="btn primary" type="submit" disabled={text.trim().length < 12}>Add memory</button>
      </form>
    </section>
  );
}
