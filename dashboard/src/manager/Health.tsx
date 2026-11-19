import { useState } from "preact/hooks";
import { api, ApiError } from "./api";
import type { Benchmark, DataInfo, Doctor, Models, Task } from "./api";
import { Err, PageHead, Skeleton, StatusBadge } from "./common";
import { Icon, Spinner } from "./icons";
import { useLoad } from "./useApi";

const GB = (n: number | null): string => (n ? `${n.toFixed(1)} GB` : "-");

function Status({ s }: { s: "ok" | "warn" | "problem" }) {
  return s === "ok" ? <span class="badge2 ok"><Icon name="check" size={12} />OK</span> : s === "warn" ? <span class="badge2 warn"><Icon name="warn" size={12} />Warning</span> : <span class="badge2 bad"><Icon name="x" size={12} />Problem</span>;
}

function BenchCell({ b }: { b?: Benchmark }) {
  if (!b) return <span class="cc-note">Not benchmarked yet</span>;
  if (b.status === "queued") return <span class="cc-note">Waiting in the queue</span>;
  if (b.status === "running") return <span class="cc-note"><Spinner size={12} /> Benchmarking {b.progress_done} of {b.progress_total} cases</span>;
  if (b.status === "failed") return <span style="color:var(--sev-high);font-size:12px">Failed: {b.error}</span>;
  if (b.status !== "done" || b.summary.accuracy == null) return <span class="cc-note">Not benchmarked yet ({b.status})</span>;
  const n = b.summary.cases ?? 0;
  return <><span style="font-size:13px">{Math.round(b.summary.accuracy * n)} of {n} match · {b.summary.median_seconds ?? "-"} s per finding</span><span class="cc-note" style="display:block">{(b.finished_at ?? "").slice(0, 10)} · false alarms removed {Math.round((b.summary.false_positives_removed ?? 0) * 100)}%</span></>;
}

export function HealthPage() {
  const doctor = useLoad(() => api<Doctor>("GET", "/api/doctor"), []);
  const info = useLoad(() => api<DataInfo>("GET", "/api/data"), []);
  const models = useLoad(() => api<Models>("GET", "/api/models"), []);
  const bench = useLoad(() => api<Record<string, Benchmark>>("GET", "/api/benchmarks"), [], (b) => Object.values(b).some((x) => x.status === "queued" || x.status === "running"), 2000);
  const [path, setPath] = useState("");
  const [force, setForce] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [msg, setMsg] = useState("");
  const task = useLoad<Task | null>(() => (taskId ? api<Task>("GET", `/api/tasks/${taskId}`) : Promise.resolve(null)), [taskId], (t) => t?.status === "running");
  const [outPath, setOutPath] = useState("");
  const [buildId, setBuildId] = useState<string | null>(null);
  const [buildMsg, setBuildMsg] = useState("");
  const build = useLoad<Task | null>(() => (buildId ? api<Task>("GET", `/api/tasks/${buildId}`) : Promise.resolve(null)), [buildId], (t) => t?.status === "running");
  const makeBundle = async () => {
    try { const r = await api<{ id: string }>("POST", "/api/data/build", { path: outPath }); setBuildId(r.id); setBuildMsg(""); }
    catch (x) { setBuildMsg(x instanceof ApiError ? x.message : String(x)); }
  };
  const run = async (verify_only: boolean) => {
    try { const r = await api<{ id: string }>("POST", "/api/data/bundle", { path, verify_only, force }); setTaskId(r.id); setMsg(""); }
    catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); }
  };
  const recheck = () => { doctor.reload(); info.reload(); models.reload(); };
  const sum = doctor.data?.summary;
  const bundle = info.data?.bundle as { bundle_created_at?: string; created_at?: string; snapshots?: Record<string, string> } | null | undefined;
  const checked = doctor.data ? new Date(doctor.data.checked_at).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) : "";
  const profile = (name: string) => name[0]?.toUpperCase() + name.slice(1);
  return (
    <>
      <PageHead title="System Health" sub={doctor.data ? `Checked today ${checked}. Every tool, data set and model below runs on this machine.` : "Checking tools, data and models..."}
        actions={<>
          {sum && <span style="display:flex;gap:6px"><span class="badge2 ok"><Icon name="check" size={12} />{sum.ok} OK</span>{sum.warn > 0 && <span class="badge2 warn"><Icon name="warn" size={12} />{sum.warn} warning{sum.warn === 1 ? "" : "s"}</span>}{sum.problem > 0 && <span class="badge2 bad"><Icon name="x" size={12} />{sum.problem} problem{sum.problem === 1 ? "" : "s"}</span>}</span>}
          <button class="btn" onClick={recheck}>Re-check all</button></>} />
      <Err text={doctor.error || info.error} />
      <section class="cc-card" style="padding:0;margin-bottom:16px" aria-labelledby="chk-h">
        <h2 id="chk-h" style="padding:16px 16px 0">Checklist</h2>
        {!doctor.data ? <Skeleton rows={6} /> : (
          <div class="tbl-wrap" style="border:0"><table class="tbl"><thead><tr><th>Status</th><th>Component</th><th>Version</th><th>Detail</th><th>How to fix</th></tr></thead><tbody>
            {doctor.data.items.map((c) => (
              <tr key={c.name}>
                <td><Status s={c.status} /></td>
                <td><b>{c.component}</b><span class="sub">{c.group}</span></td>
                <td class="mono" style="font-size:12px">{c.version}</td>
                <td style="max-width:340px;overflow-wrap:anywhere">{c.detail}</td>
                <td style="max-width:320px;overflow-wrap:anywhere">{c.fix ? (/^(pip|brew|ollama|gapscan)\b/.test(c.fix) && !c.fix.includes(" or ") ? <span class="mono" style="font-size:12px">{c.fix}</span> : c.fix) : <span class="cc-note">Nothing to do</span>}</td>
              </tr>
            ))}
          </tbody></table></div>
        )}
      </section>
      <div class="cc-grid g2" style="margin-bottom:16px">
        <section class="cc-card" aria-labelledby="fresh-h">
          <h2 id="fresh-h">Data freshness<span style="text-transform:none;letter-spacing:0">Amber after {info.data?.max_age_days ?? 30} days</span></h2>
          {info.data && info.data.freshness.length === 0 && <p class="cc-note">No dated snapshots yet. Import an offline bundle, or run <span class="mono">gapscan data fetch</span> on a connected machine.</p>}
          {info.data?.freshness.map((f) => (
            <div key={f.name} style="display:grid;grid-template-columns:1fr 92px 120px 64px;gap:10px;align-items:center;padding:9px 0;border-top:1px solid var(--line);font-size:13px">
              <b>{f.name.replace(/_/g, " ")}</b><span class="mono cc-note">{f.value}</span>
              <span class="bar2" role="meter" aria-label={`${f.name} age`} aria-valuenow={Math.round((f.used ?? 0) * 100)} aria-valuemin={0} aria-valuemax={100}><i style={`width:${(f.used ?? 0) * 100}%;background:${f.stale ? "var(--sev-medium-fill)" : "var(--ok-fill)"}`} /></span>
              <span class="mono" style="text-align:right;font-size:12px">{f.age_days == null ? "-" : `${f.age_days} days`}</span>
            </div>
          ))}
          <p class="cc-note" style="margin:10px 0 0">Snapshots only change when you import a bundle. Nothing is fetched.</p>
        </section>
        <section class="cc-card" aria-labelledby="bun-h">
          <h2 id="bun-h">Offline bundle</h2>
          <div style="border:1px solid var(--line);border-radius:8px;padding:12px 14px">
            <b style="font-size:13px">Import a bundle</b>
            <p class="cc-note" style="margin:4px 0 8px">{bundle ? <>Last import {String(bundle.bundle_created_at ?? bundle.created_at ?? "").slice(0, 10)}. Files are checked against the manifest before anything is installed.</> : "No bundle imported yet. Files are checked against the manifest before anything is installed."}</p>
            <label class="cc-field" style="margin-bottom:8px"><span>Bundle file (.tar.gz) on this machine</span><input class="cc-input mono" value={path} onInput={(e) => setPath(e.currentTarget.value)} placeholder="/path/to/gapscan-bundle.tar.gz" /></label>
            <label style="display:flex;gap:8px;font-size:13px;margin-bottom:10px"><input type="checkbox" checked={force} onChange={(e) => setForce(e.currentTarget.checked)} style="accent-color:var(--accent)" /> Allow an older bundle</label>
            <div style="display:flex;gap:8px"><button class="btn" disabled={!path} onClick={() => run(true)}>Verify only</button><button class="btn primary" disabled={!path} onClick={() => run(false)}>Verify and install</button></div>
            <Err text={msg} />
            {task.data && <><p style="margin:10px 0 6px"><StatusBadge s={task.data.status === "running" ? "running" : task.data.status === "done" ? "done" : "failed"} /></p><pre class="logbox">{task.data.log.join("\n")}</pre></>}
          </div>
          <div style="border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin-top:12px">
            <b style="font-size:13px">Build a bundle</b>
            <p class="cc-note" style="margin:4px 0 8px">Packs the data already on this machine for carrying to another one. Nothing is downloaded. To fetch fresh data first, run <span class="mono">gapscan bundle</span> on a connected machine.</p>
            <label class="cc-field" style="margin-bottom:10px"><span>Save as (folder or .tar.gz file)</span><input class="cc-input mono" value={outPath} onInput={(e) => setOutPath(e.currentTarget.value)} placeholder="Your home folder, gapscan-bundle-<date>.tar.gz" /></label>
            <button class="btn primary" disabled={build.data?.status === "running"} onClick={makeBundle}>Build bundle</button>
            <Err text={buildMsg} />
            {build.data && <><p style="margin:10px 0 6px"><StatusBadge s={build.data.status === "running" ? "running" : build.data.status === "done" ? "done" : "failed"} /></p><pre class="logbox">{build.data.log.join("\n")}</pre></>}
          </div>
        </section>
      </div>
      <section class="cc-card" style="padding:0" aria-labelledby="mm-h">
        <div style="padding:16px 16px 8px;display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap"><h2 id="mm-h" style="margin:0">Model manager</h2>
          <span class="cc-note">Compare models on the labeled findings with <span class="mono">gapscan model bench</span></span></div>
        {models.data?.error && <div class="fd-banner bad" style="margin:0 16px 12px"><b><Icon name="x" size={12} /> The local model server is not answering</b><p>AI review is off until it is back. Scans still run with scanners only, and verdicts from earlier runs stay visible. {models.data.error}</p></div>}
        <div class="tbl-wrap" style="border:0;border-top:1px solid var(--line)"><table class="tbl"><thead><tr><th>Model</th><th>Profile</th><th class="num">Size</th><th>Status</th><th>Last benchmark</th><th>Action</th></tr></thead><tbody>
          {models.data?.profiles.map((p) => (
            <tr key={p.name} style={p.selected ? "background:var(--accent-weak)" : ""}>
              <td class="mono" style="font-weight:600">{p.model}</td><td>{profile(p.name)}{p.selected && <span class="sub" style="color:var(--accent);font-weight:600">Active profile</span>}</td>
              <td class="num">{GB(p.size_gb)}</td><td>{p.installed ? "Installed" : <span style="color:var(--sev-high)">Not installed</span>}</td><td style="max-width:300px"><BenchCell b={bench.data?.[p.model]} /></td>
              <td style="white-space:nowrap;display:flex;gap:6px;flex-direction:column;align-items:flex-start">
                <button class="btn sm" disabled={!p.installed || ["queued", "running"].includes(bench.data?.[p.model]?.status ?? "")} onClick={async () => { try { await api("POST", "/api/benchmarks", { model: p.model }); setMsg(""); bench.reload(); } catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); } }}>Benchmark this model</button>
                {p.selected ? <span class="cc-note">In use</span> : <button class="btn sm" disabled={!p.installed} onClick={async () => { await api("PUT", "/api/settings", { profile: p.name }); models.reload(); }}>Use this profile</button>}</td>
            </tr>
          ))}
          {!models.data && <tr><td colSpan={6} class="cc-note" style="padding:16px">Loading models...</td></tr>}
        </tbody></table></div>
        <p class="cc-note" style="padding:10px 16px">A benchmark waits in the run queue, so it never competes with a scan for the model. A model is pulled on the connected machine with <span class="mono">ollama pull</span> and moved over with the bundle.</p>
      </section>
    </>
  );
}
