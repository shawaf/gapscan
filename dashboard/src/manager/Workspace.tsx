import { useState } from "preact/hooks";
import { api, ApiError } from "./api";
import type { SendResult, WorkspaceLink, WorkspaceProject } from "./api";
import { Err } from "./common";
import { Icon } from "./icons";
import { useLoad } from "./useApi";

const message = (x: unknown) => (x instanceof ApiError ? x.message : String(x));

async function copy(text: string, done: (m: string) => void) {
  try { await navigator.clipboard.writeText(text); done("Copied."); } catch { done("Select the text to copy it."); }
}

/** Settings card: the team workspace this install sends runs to, and this install's key. */
export function WorkspaceCard() {
  const link = useLoad(() => api<WorkspaceLink>("GET", "/api/workspace"), []);
  const [url, setUrl] = useState<string | null>(null);
  const [token, setToken] = useState("");
  const [msg, setMsg] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const data = link.data;
  const shownUrl = url ?? data?.url ?? "";
  const who = data?.identity && typeof data.identity === "object" ? data.identity : null;

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    try { await fn(); setMsg(""); setNote(ok); setToken(""); setUrl(null); link.reload(); }
    catch (x) { setNote(""); setMsg(message(x)); }
    finally { setBusy(false); }
  };

  return (
    <section class="cc-card">
      <h2 class="big">Team workspace</h2>
      <p class="cc-note" style="margin-top:-6px">Send finished runs to your team's GapScan server as signed "local run" reports. Nothing is sent unless you press Send on a run, and never while a scan runs.</p>
      <Err text={msg || link.error} />
      {data?.connected && who && (
        <div class="fd-banner" role="status"><b><Icon name="check" size={12} /> Connected as {who.name} ({who.role})</b><p class="mono" style="margin:4px 0 0">{data.url}</p></div>
      )}
      <form onSubmit={(e) => { e.preventDefault(); void run(() => api("PUT", "/api/workspace", { url: shownUrl, token }), "Saved. The server accepted this token."); }}>
        <label class="cc-field"><span>Team server address</span>
          <input class="cc-input mono" value={shownUrl} placeholder="https://gapscan.example.internal" onInput={(e) => setUrl(e.currentTarget.value)} /></label>
        <label class="cc-field"><span>Your token</span>
          <input class="cc-input mono" type="password" autoComplete="off" value={token} placeholder={data?.connected ? "saved (paste a new one to replace it)" : "from the workspace admin"} onInput={(e) => setToken(e.currentTarget.value)} />
          <span class="cc-note">Kept in this computer's GapScan data folder, readable only by you. It is never shown again.</span></label>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn primary" type="submit" disabled={busy || !shownUrl}>{data?.connected ? "Save and check" : "Connect"}</button>
          {data?.connected && <button class="btn" type="button" disabled={busy} onClick={() => run(() => api("DELETE", "/api/workspace"), "Disconnected. The token was deleted.")}>Disconnect</button>}
        </div>
      </form>
      <h3 style="font-size:13px;margin:16px 0 6px">This install's key</h3>
      {data?.key ? (
        <>
          <p class="cc-note" style="margin:0 0 6px">Give the public key to your workspace admin; they register it under your name. Reports this install signs are accepted only then. The private key never leaves this computer.</p>
          <p class="mono" style="font-size:12px;word-break:break-all;margin:0">{data.key.public_key}</p>
          <p class="cc-note mono" style="margin:4px 0 8px">{data.key.fingerprint}</p>
          <button class="btn sm" type="button" onClick={() => copy(data.key?.public_key ?? "", setNote)}>Copy public key</button>
        </>
      ) : (
        <>
          <p class="cc-note" style="margin:0 0 8px">No key yet. Create it once; your admin registers its public half.</p>
          <button class="btn" type="button" disabled={busy} onClick={() => run(() => api("POST", "/api/workspace/key"), "Key created. Copy the public key for your admin.")}>Create key</button>
        </>
      )}
      {note && <p class="cc-note" role="status" style="margin-top:8px">{note}</p>}
    </section>
  );
}

/** Run drawer panel: send this finished run to a project of the team workspace. */
export function SendToWorkspace({ runId, projectId }: { runId: number; projectId: number }) {
  const link = useLoad(() => api<WorkspaceLink>("GET", "/api/workspace"), []);
  const ready = !!link.data?.connected && !!link.data?.key;
  const projects = useLoad(() => (ready ? api<WorkspaceProject[]>("GET", "/api/workspace/projects") : Promise.resolve([] as WorkspaceProject[])), [ready]);
  const [picked, setPicked] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const [done, setDone] = useState<SendResult | null>(null);
  const [busy, setBusy] = useState(false);
  if (!link.data) return null;
  if (!ready) {
    return <p class="cc-note" style="margin:0 0 14px">To send runs to your team, connect a workspace and create this install's key in Settings.</p>;
  }
  const choice = picked ?? link.data.projects[String(projectId)] ?? projects.data?.[0]?.id ?? "";
  const send = async () => {
    setBusy(true);
    try { setDone(await api<SendResult>("POST", `/api/scans/${runId}/send`, { project_id: choice })); setMsg(""); }
    catch (x) { setMsg(message(x)); }
    finally { setBusy(false); }
  };
  return (
    <div class="cc-card" style="margin-bottom:14px">
      <h3 style="font-size:13px;margin:0 0 6px">Send to team workspace</h3>
      <Err text={msg || projects.error} />
      {done ? (
        <p class="fd-banner" role="status" style="margin:0"><b><Icon name="check" size={12} /> Imported as a local run</b> · {done.new} new, {done.unchanged} unchanged, {done.resolved} resolved · signed by {done.install} ({done.owner})</p>
      ) : (
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
          <label class="cc-field" style="margin:0;flex:1;min-width:180px"><span>Workspace project</span>
            <select class="cc-input" value={choice} onChange={(e) => setPicked(e.currentTarget.value)}>
              {(projects.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select></label>
          <button class="btn primary" type="button" disabled={busy || !choice} onClick={send}>{busy ? "Sending..." : "Send"}</button>
        </div>
      )}
      <p class="cc-note" style="margin:8px 0 0">Signed with this install's key. Findings and their evidence only: no SBOM, no raw scanner output, no folder path. The workspace admin decides whether imports are accepted.</p>
    </div>
  );
}
