import { useEffect, useState } from "preact/hooks";
import { Patch } from "../components/Patch";
import { api, ApiError } from "./api";
import type { FsListing, GitHead, Project } from "./api";
import { ConfirmDialog, Err, Grade, Segmented, StatusBadge } from "./common";
import { Icon } from "./icons";
import { projectPage } from "./Targets";
import { useLoad, when } from "./useApi";
import { navigate } from "../store";

export function Home({ projects, error, reload }: { projects: Project[] | null; error: string; reload: () => void }) {
  const [view, setView] = useState<"cards" | "table">(() => { try { return localStorage.getItem("gapscan.home") === "table" ? "table" : "cards"; } catch { return "cards"; } });
  const pick = (v: "cards" | "table") => { setView(v); try { localStorage.setItem("gapscan.home", v); } catch { /* ignore */ } };
  const [del, setDel] = useState<{ p: Project; decisions: number } | null>(null);
  const [creating, setCreating] = useState(false);
  const [msg, setMsg] = useState("");
  const askDelete = async (p: Project) => {
    let decisions = 0;
    try { decisions = (await api<unknown[]>("GET", `/api/projects/${p.id}/decisions`)).length; } catch { /* count is a courtesy */ }
    setDel({ p, decisions });
  };
  const doDelete = async () => {
    if (!del) return;
    try { await api("DELETE", `/api/projects/${del.p.id}`); setDel(null); reload(); }
    catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); setDel(null); }
  };
  const archive = async (p: Project, archived: boolean) => {
    try { await api("PUT", `/api/projects/${p.id}`, { archived }); reload(); }
    catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); }
  };
  const active = (projects ?? []).filter((p) => !p.archived);
  const archivedList = (projects ?? []).filter((p) => p.archived);
  const [showArchived, setShowArchived] = useState(false);
  const empty = projects?.length === 0;
  return (
    <>
      <div class="cc-h patch-tip" style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap">
        {empty && <Patch state="greet" size={96} />}<div style="flex:1"><h1>{empty ? "Welcome to GapScan" : "Projects"}</h1>
          <p>{empty ? "Add the folder of a project to measure it against its target standards and find its gaps. In local mode everything stays on this computer and nothing in the folder is executed." : "Pick a project to see its gaps. Only folders you add here are ever scanned."}</p></div>
        {!empty && <button class="btn primary" onClick={() => setCreating(true)} aria-label="Add a new project"><Icon name="plus" size={14} /> New project</button>}
      </div>
      <Err text={error || msg} />
      {empty ? (
        <div class="cc-card cc-empty" style="padding:40px 24px;text-align:center">
          <Icon name="overview" size={30} /><h2>No projects yet</h2>
          <p>A project is a folder on this computer. Add one to scan it against its standards and see its gaps.</p>
          <button class="btn primary" style="margin-top:4px" onClick={() => setCreating(true)}><Icon name="plus" size={14} /> Add your first project</button>
        </div>
      ) : (
        <>
          {active.length > 0 && <div style="margin-bottom:12px"><Segmented label="View" value={view} onChange={pick} options={[{ id: "cards", label: "Cards" }, { id: "table", label: "Table" }]} /></div>}
          {view === "table" && active.length > 0 && (
            <section class="cc-card" style="padding:0;margin-bottom:16px"><div class="tbl-wrap" style="border:0"><table class="tbl"><thead><tr><th>Project</th><th>Folder</th><th>Grade</th><th class="num">Open gaps</th><th>Last run</th><th /></tr></thead><tbody>
              {active.map((p) => (
                <tr key={p.id} class="click" onClick={() => navigate(projectPage(), null, String(p.id))}>
                  <td><b>{p.name}</b></td><td class="mono" style="font-size:12px">{p.path}</td>
                  <td>{p.active ? <StatusBadge s="running" /> : <Grade g={p.latest_done?.grade ?? null} n={p.latest_done?.score ?? null} />}</td>
                  <td class="num">{p.latest_done?.open_findings ?? "-"}</td><td>{p.latest ? when(p.latest.finished_at) : "Never scanned"}</td>
                  <td style="white-space:nowrap"><button class="btn ghost sm" onClick={(e) => { e.stopPropagation(); void archive(p, true); }} aria-label={`Archive project ${p.name}`}>Archive</button>
                    <button class="btn ghost sm" style="color:var(--sev-high)" onClick={(e) => { e.stopPropagation(); void askDelete(p); }} aria-label={`Delete project ${p.name}`}>Delete</button></td>
                </tr>
              ))}</tbody></table></div></section>
          )}
          {view === "cards" && (
            <div class="cc-grid g2">
              {active.map((p) => (
                <a key={p.id} class="cc-card" href={`#/p/${p.id}/${projectPage()}`} style="text-decoration:none;color:inherit;display:block">
                  <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start">
                    <div><b style="font-size:15px">{p.name}</b><div class="mono cc-note" style="word-break:break-all">{p.path}</div></div>
                    {p.active ? <StatusBadge s="running" /> : <span style="font-size:18px;white-space:nowrap"><Grade g={p.latest_done?.grade ?? null} n={p.latest_done?.score ?? null} /></span>}
                  </div>
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px"><p class="cc-note" style="margin:0">{p.latest_done ? `${p.latest_done.open_findings} open gaps of ${p.latest_done.findings} found` : "Never scanned"}</p>
                    <span style="display:flex;gap:4px"><button class="btn ghost sm" onClick={(e) => { e.preventDefault(); e.stopPropagation(); void archive(p, true); }} aria-label={`Archive project ${p.name}`}>Archive</button>
                      <button class="btn ghost sm" style="color:var(--sev-high)" onClick={(e) => { e.preventDefault(); e.stopPropagation(); void askDelete(p); }} aria-label={`Delete project ${p.name}`}>Delete</button></span></div>
                </a>
              ))}
            </div>
          )}
          {archivedList.length > 0 && (
            <section class="cc-card" style="margin-top:16px" aria-label="Archived projects">
              <button class="btn ghost sm" style="padding:0" aria-expanded={showArchived} onClick={() => setShowArchived(!showArchived)}>{showArchived ? "▾" : "▸"} Archived projects · {archivedList.length}</button>
              {showArchived && (
                <div class="tbl-wrap" style="margin-top:10px"><table class="tbl"><tbody>
                  {archivedList.map((p) => (
                    <tr key={p.id} style="opacity:0.8"><td><b>{p.name}</b><span class="sub mono">{p.path}</span></td><td class="cc-note">History and decisions are kept. Runs are blocked while archived.</td>
                      <td style="white-space:nowrap"><button class="btn sm" onClick={() => navigate("overview", null, String(p.id))}>View history</button> <button class="btn sm" onClick={() => void archive(p, false)} aria-label={`Restore project ${p.name}`}>Restore</button>
                        <button class="btn ghost sm" style="color:var(--sev-high)" onClick={() => void askDelete(p)} aria-label={`Delete project ${p.name}`}>Delete</button></td></tr>
                  ))}</tbody></table></div>
              )}
            </section>
          )}
        </>
      )}
      {del && (
        <ConfirmDialog title={`Delete project ${del.p.name}?`} confirm="Delete project" danger typed={del.p.name} onCancel={() => setDel(null)} onConfirm={() => void doDelete()}>
          This removes its run history and {del.decisions} reviewer decision{del.decisions === 1 ? "" : "s"} from this machine. Your source files are not touched. This cannot be undone.
        </ConfirmDialog>
      )}
      {creating && <NewProjectDialog onClose={() => setCreating(false)} onCreated={(p) => { setCreating(false); reload(); navigate("runs", null, String(p.id)); }} />}
    </>
  );
}

/** The create-project wizard: a folder (typed or browsed) and an optional name, in a modal. */
function NewProjectDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (p: Project) => void }) {
  const [path, setPath] = useState("");
  const [name, setName] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [native, setNative] = useState(false);
  const [browsing, setBrowsing] = useState(false);
  const [head, setHead] = useState<GitHead | null>(null);
  useEffect(() => { api<{ folder_picker: boolean }>("GET", "/api/desktop").then((d) => setNative(d.folder_picker)).catch(() => setNative(false)); }, []);
  // Show which branch/commit the chosen folder is on, so you know what you are registering.
  useEffect(() => {
    if (!path.trim()) { setHead(null); return; }
    let live = true;  // ignore a slow reply for a path the field has already moved off
    const t = window.setTimeout(() => {
      api<GitHead>("GET", `/api/git-head?path=${encodeURIComponent(path)}`).then((h) => { if (live) setHead(h); }).catch(() => { if (live) setHead(null); });
    }, 400);
    return () => { live = false; window.clearTimeout(t); };
  }, [path]);
  const browse = async () => {
    if (!native) { setBrowsing(true); return; }
    try { const r = await api<{ path: string | null }>("POST", "/api/desktop/choose-folder", {}); if (r.path) setPath(r.path); }
    catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); }
  };
  const add = async (e: Event) => {
    e.preventDefault();
    setBusy(true); setMsg("");
    try { onCreated(await api<Project>("POST", "/api/projects", { path, name: name || undefined })); }
    catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); setBusy(false); }
  };
  return (
    <>
      <div class="cc-drawer-bg" onClick={onClose} />
      <div class="dlg" role="dialog" aria-modal="true" aria-label="Add a project" style="width:min(560px,92vw)">
        <form onSubmit={add}>
          <h2>Add a project</h2>
          <p class="cc-note" style="margin:0 0 14px">Register a project folder to scan it against its standards. Nothing in it is executed, built or imported.</p>
          <label class="cc-field"><span>Folder (type a path or browse)</span><span style="display:flex;gap:8px"><input class="cc-input mono" style="flex:1" autoFocus value={path} onInput={(e) => setPath(e.currentTarget.value)} placeholder="/Users/me/code/my-app" aria-label="Project folder" /><button type="button" class="btn" onClick={browse}>Browse…</button></span>
            {head?.git && <p class="cc-note" style="margin:6px 0 0;display:flex;gap:6px;align-items:center"><Icon name="check" size={13} />On branch <b>{head.branch || "detached HEAD"}</b>{head.commit ? <> at <code class="mono">{head.commit}</code></> : null}{head.dirty ? " · uncommitted changes" : null}</p>}
            {head && !head.git && path.trim() ? <p class="cc-note" style="margin:6px 0 0">Not a git repository — GapScan will still scan the folder.</p> : null}</label>
          <label class="cc-field"><span>Name (optional)</span><input class="cc-input" value={name} onInput={(e) => setName(e.currentTarget.value)} placeholder="Defaults to the folder name" aria-label="Project name" /></label>
          <Err text={msg} />
          <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px">
            <button class="btn" type="button" onClick={onClose}>Cancel</button>
            <button class="btn primary" type="submit" disabled={!path || busy}><Icon name="plus" size={14} /> Add project</button>
          </div>
        </form>
      </div>
      {browsing && <FolderPicker start={path} onPick={(p) => { setPath(p); setBrowsing(false); }} onClose={() => setBrowsing(false)} />}
    </>
  );
}

/** Walk the server's folders in the browser (no native dialog): directories only, read-only. */
function FolderPicker({ start, onPick, onClose }: { start: string; onPick: (p: string) => void; onClose: () => void }) {
  const [cur, setCur] = useState(start.startsWith("/") ? start : "");
  const { data, error } = useLoad(() => api<FsListing>("GET", `/api/fs?path=${encodeURIComponent(cur)}`), [cur]);
  const join = (dir: string, name: string) => `${dir.replace(/\/$/, "")}/${name}`;
  return (
    <>
      <div class="cc-drawer-bg" onClick={onClose} />
      <div class="dlg" role="dialog" aria-modal="true" aria-label="Choose a folder" style="width:min(580px,92vw)">
        <h2>Choose a folder</h2>
        <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px">
          <button class="btn sm" type="button" onClick={() => setCur("")} title="Home"><Icon name="home" size={13} /></button>
          <button class="btn sm" type="button" disabled={!data?.parent} onClick={() => data?.parent && setCur(data.parent)} title="Up one folder">↑ Up</button>
          <span class="cc-input mono" style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:6px 10px">{data?.path ?? cur ?? "…"}</span>
        </div>
        <Err text={error} />
        <div class="tbl-wrap" style="max-height:320px;overflow:auto;margin-bottom:4px">
          {data && data.entries.length === 0 && <p class="cc-note" style="padding:14px">No sub-folders here. Use "Select this folder" to pick it.</p>}
          {data?.entries.map((e) => (
            <button key={e.name} type="button" class="fp-row" onClick={() => setCur(join(data.path, e.name))}
              style="display:flex;width:100%;gap:8px;align-items:center;padding:7px 10px;background:none;border:0;border-bottom:1px solid var(--line);color:inherit;text-align:left;cursor:pointer;font-size:13px">
              <Icon name="folder" size={14} /><span style="flex:1">{e.name}</span>
              {e.git && <span class="av" style="font-size:11px"><Icon name="check" size={11} />git</span>}
              <span class="cc-note">›</span>
            </button>
          ))}
          {!data && !error && <p class="cc-note" style="padding:14px">Loading…</p>}
        </div>
        {data?.truncated && <p class="cc-note" style="margin:0 0 6px">Many folders here — only the first {data.entries.length} are shown. Type the path to reach others.</p>}
        {data?.head.git && <p class="cc-note" style="margin:6px 0 0;display:flex;gap:6px;align-items:center"><Icon name="check" size={13} />This folder is on <b>{data.head.branch || "detached HEAD"}</b>{data.head.commit ? <> at <code class="mono">{data.head.commit}</code></> : null}{data.head.dirty ? " · uncommitted changes" : null}.</p>}
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px">
          <button class="btn" type="button" onClick={onClose}>Cancel</button>
          <button class="btn primary" type="button" disabled={!data} onClick={() => data && onPick(data.path)}>Select this folder</button>
        </div>
      </div>
    </>
  );
}
