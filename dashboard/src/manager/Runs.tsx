import { useEffect, useState } from "preact/hooks";
import { ACTIVE, api, ApiError } from "./api";
import type { GitRefs, Models, ProjectDetail, QueueRun, Scan, ScannerAvail, Settings } from "./api";
import { ConfirmDialog, Drawer, Err, Grade, Pipeline, Segmented, StatusBadge, duration, elapsed, presetLabel, stepLabel, stepsFor } from "./common";
import { Icon, Spinner } from "./icons";
import { fetchScan, useLoad, when } from "./useApi";
import { SendToWorkspace } from "./Workspace";
import { VERDICT_LABEL } from "../format";
import type { VerdictKey } from "../types";
import { navigate } from "../store";

type Preset = "full" | "scanners" | "dry";
const PROFILE_ORDER = ["best", "balanced", "small", "tiny"];
const EXPORT_LABEL: Record<string, string> = { "report.sarif": "SARIF", "findings.csv": "CSV", "report.md": "Markdown", "sbom.cdx.json": "SBOM", "report.json": "JSON", "report.pdf": "PDF" };

export function Runs({ project, queue, reload }: { project: ProjectDetail; queue: QueueRun[]; reload: () => void }) {
  const scanners = useLoad(() => api<ScannerAvail[]>("GET", "/api/scanners"), []);
  const models = useLoad(() => api<Models>("GET", "/api/models"), []);
  const settings = useLoad(() => api<Settings>("GET", "/api/settings"), []);
  const refs = useLoad(() => api<GitRefs>("GET", `/api/projects/${project.id}/refs`), [project.id]);
  const [preset, setPreset] = useState<Preset>("full");
  const [picked, setPicked] = useState<Set<string> | null>(null);
  const [profile, setProfile] = useState("");
  const [limit, setLimit] = useState(40);
  const [calls, setCalls] = useState(4);
  const [deep, setDeep] = useState(true);
  const [deepLimit, setDeepLimit] = useState(5);
  const [baseline, setBaseline] = useState("previous");
  const [base, setBase] = useState("");
  const [asvs, setAsvs] = useState(2);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const [filter, setFilter] = useState<"all" | "done" | "failed" | "cancelled">("all");
  const [showAll, setShowAll] = useState(false);
  const [confirmCancel, setConfirmCancel] = useState<number | null>(null);

  const available = scanners.data?.filter((s) => s.available).map((s) => s.name) ?? [];
  const chosen = picked ?? new Set(scanners.data?.filter((s) => s.available && s.default).map((s) => s.name) ?? []);
  const activeProfile = profile || models.data?.profiles.find((p) => p.selected)?.name || "";
  const profileInfo = models.data?.profiles.find((p) => p.name === activeProfile);
  useEffect(() => {
    if (!settings.data) return;
    setLimit(settings.data.triage_limit); setCalls(settings.data.max_tool_calls); setAsvs(settings.data.asvs_level); setPreset(settings.data.default_preset);
    setDeep(settings.data.deep_dive); setDeepLimit(settings.data.deep_dive_limit);
  }, [settings.data]);

  const scans = project.scans.filter((s) => s.kind === "scan" || s.kind === "dryrun");
  const runs = scans.filter((s) => s.kind === "scan");
  const live = runs.find((s) => s.status === "running") ?? null;
  const waiting = queue.filter((q) => q.status === "queued" && (q.project_id === project.id || q.kind === "benchmark"));
  const benchmarking = queue.find((q) => q.kind === "benchmark" && q.status === "running") ?? null;
  const doneRuns = runs.filter((s) => s.status === "done");
  const counts = { all: scans.length, done: scans.filter((s) => s.status === "done").length, failed: scans.filter((s) => s.status === "failed" || s.status === "interrupted").length, cancelled: scans.filter((s) => s.status === "cancelled").length };
  const shown = scans.filter((s) => filter === "all" || (filter === "failed" ? s.status === "failed" || s.status === "interrupted" : s.status === filter));
  const rows = showAll ? shown : shown.slice(0, 7);

  const toggle = (name: string) => {
    const next = new Set(chosen);
    if (next.has(name)) next.delete(name); else next.add(name);
    setPicked(next);
  };
  const reset = () => { setPreset(settings.data?.default_preset ?? "full"); setPicked(null); setProfile(""); setCalls(settings.data?.max_tool_calls ?? 4); setBaseline("previous"); setBase(""); setAsvs(settings.data?.asvs_level ?? 2); setLimit(settings.data?.triage_limit ?? 40); setDeep(settings.data?.deep_dive ?? true); setDeepLimit(settings.data?.deep_dive_limit ?? 5); setMsg(""); };
  const ahead = (live ? 1 : 0) + waiting.length;

  const start = async () => {
    setBusy(true); setMsg("");
    try {
      const body: Record<string, unknown> = { triage: preset !== "scanners", limit, scanners: [...chosen], asvs_level: asvs, dry_run: preset === "dry" };
      if (preset !== "scanners") { body.profile = activeProfile || undefined; body.max_tool_calls = calls; body.deep_dive = deep; body.deep_dive_limit = deepLimit; }
      if (baseline !== "previous") body.baseline = Number(baseline);
      if (base) body.base = base;
      await api("POST", `/api/projects/${project.id}/scans`, body);
      reload();
    } catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); }
    setBusy(false);
  };
  const cancel = async (id: number) => { try { await api("POST", `/api/scans/${id}/cancel`); reload(); } catch (x) { setMsg(String(x)); } };
  const cancelBenchmark = async (id: number) => { try { await api("POST", `/api/benchmarks/${id}/cancel`); reload(); } catch (x) { setMsg(String(x)); } };

  return (
    <>
      <div class="cc-h"><div><h1>Runs</h1><p>Start, queue and watch scans. A run never blocks the rest of the app.</p></div></div>
      <Err text={msg || scanners.error || models.error} />
      <div class="cc-grid g-runs">
        <section class="cc-card" aria-labelledby="start-h">
          <h2 class="big" id="start-h">Start a run</h2>
          <div class="cc-field"><span class="lbl">Preset</span>
            <Segmented block label="Preset" value={preset} onChange={setPreset} options={[{ id: "full", label: "Full scan" }, { id: "scanners", label: "Scanners only" }, { id: "dry", label: "Dry run" }]} />
            <p class="cc-note" style="margin-top:6px">{preset === "full" ? "Scanners, then the local model reviews each finding." : preset === "scanners" ? "Scanners only: no model, much faster, findings stay unreviewed." : "Dry run lists what would execute and changes nothing."}</p></div>
          <div class="cc-field"><span class="lbl">Target folder</span>
            <input class="cc-input mono" value={project.path} readOnly aria-label="Target folder" />
            {refs.data?.git
              ? <p class="cc-note" style="margin-top:6px;display:flex;gap:6px;align-items:center"><Icon name="info" size={13} />Scans what is checked out now: <b>{refs.data.branch || "detached HEAD"}</b>{refs.data.commit ? <> at <code class="mono">{refs.data.commit}</code></> : null}{refs.data.dirty ? " · uncommitted changes included" : null}. GapScan never checks out, fetches or pulls.</p>
              : <p class="cc-note" style="margin-top:6px">Read only. Nothing in it is executed, built or imported.{refs.data && !refs.data.git ? " Not a git repository." : ""}</p>}</div>
          {refs.data?.git && refs.data.refs.length > 0 && (
            <label class="cc-field"><span>Scope</span>
              <select class="cc-select" value={base} onChange={(e) => setBase(e.currentTarget.value)}>
                <option value="">Whole project</option>
                {refs.data.refs.map((r) => <option key={r} value={r}>Only findings introduced since {r}</option>)}
              </select>
              <p class="cc-note" style="margin-top:6px">{base ? <>Scans everything, then keeps only findings on lines your branch changed since <code class="mono">{base}</code> (a read-only <code class="mono">git diff</code>).</> : "Reports every finding in the folder."}</p></label>
          )}
          <div class="cc-field"><span class="lbl" style="display:flex;justify-content:space-between">Scanners <span class="cc-note">{available.length} of {scanners.data?.length ?? 6} available</span></span>
            <div class="cc-scanners">
              {scanners.data?.map((s) => (
                <label key={s.name}>
                  <input type="checkbox" checked={chosen.has(s.name) && s.available} disabled={!s.available} onChange={() => toggle(s.name)} />
                  <span><span class="nm">{s.name}</span><span class="ds">{s.description}</span></span>
                  {s.available ? <span class="av"><Icon name="check" size={12} />Available{s.version ? ` · ${s.version}` : ""}</span> : <span class="av no"><Icon name="x" size={12} />Unavailable</span>}
                </label>
              ))}
              {!scanners.data && <label><span class="cc-note">Checking scanners...</span></label>}
            </div>
            {scanners.data?.some((s) => !s.available) && <p class="cc-note" style="margin-top:6px">{scanners.data.filter((s) => !s.available).map((s) => s.name).join(", ")} not found on PATH. <a href="#/health" onClick={(e) => { e.preventDefault(); navigate("health"); }}>How to fix</a></p>}
          </div>
          {preset !== "scanners" && (
            <>
              <div class="cc-field"><span class="lbl">Model profile</span>
                <Segmented block label="Model profile" value={activeProfile} onChange={setProfile}
                  options={[...(models.data?.profiles ?? [])].sort((a, b) => PROFILE_ORDER.indexOf(a.name) - PROFILE_ORDER.indexOf(b.name)).map((p) => ({ id: p.name, label: p.name[0]?.toUpperCase() + p.name.slice(1) }))} />
                <p class="cc-note" style="margin-top:6px">{profileInfo ? <>Uses <code class="mono">{profileInfo.model}</code> · {profileInfo.installed ? "installed on the local model server" : <b style="color:var(--sev-high)">not installed on the local model server</b>}</> : "Loading profiles..."}</p></div>
              <div class="cc-row2">
                <label class="cc-field"><span>Max findings to review <span class="cc-note">(0 = all)</span></span><input class="cc-input mono" type="number" min={0} max={100000} value={limit} onInput={(e) => setLimit(Number(e.currentTarget.value))} /></label>
                <label class="cc-field"><span>Tool calls per finding</span><input class="cc-input mono" type="number" min={0} max={10} value={calls} onInput={(e) => setCalls(Number(e.currentTarget.value))} /></label>
              </div>
              <div class="cc-switchrow"><button class="cc-toggle" role="switch" aria-checked={deep} aria-label="Deep dive into confirmed issues" onClick={() => setDeep(!deep)} />
                <span><b style="font-size:13px">Deep dive into confirmed issues</b><span class="cc-note" style="display:block">After the review, investigate the top confirmed issues in depth: where it is protected, what is missing, related places, ordered fix. About 20 seconds each.</span></span></div>
              {deep && <label class="cc-field"><span>Issues to investigate</span><input class="cc-input mono" type="number" min={1} max={100} value={deepLimit} onInput={(e) => setDeepLimit(Number(e.currentTarget.value))} /></label>}
            </>
          )}
          <label class="cc-field"><span>Baseline to compare against</span>
            <select class="cc-select" value={baseline} onChange={(e) => setBaseline(e.currentTarget.value)}>
              <option value="previous">Previous finished run{doneRuns[0] ? ` · #${doneRuns[0].id}` : ""}</option>
              {doneRuns.map((r) => <option key={r.id} value={r.id}>Run #{r.id} · {when(r.finished_at)}{r.score != null ? ` · score ${r.score.toFixed(0)}` : ""}</option>)}
            </select></label>
          <div class="cc-field"><span class="lbl">ASVS level</span>
            <Segmented block label="ASVS level" value={String(asvs)} onChange={(v) => setAsvs(Number(v))} options={[{ id: "1", label: "L1" }, { id: "2", label: "L2" }, { id: "3", label: "L3" }]} /></div>
          <div style="border-top:1px solid var(--line);padding-top:12px">
            <p class="cc-note" style="display:flex;gap:8px;margin-bottom:10px"><Icon name="info" size={14} />{ahead ? `${live ? `Run #${live.id} is in progress` : "Runs are waiting"}, so this run joins the queue at position ${ahead + 1}.` : "Nothing is running, so this run starts now."}{doneRuns[0] ? ` The last run took ${duration(doneRuns[0].started_at, doneRuns[0].finished_at)}.` : ""}</p>
            <div style="display:flex;gap:8px"><button class="btn primary" style="flex:1" disabled={busy || project.archived || !scanners.data || chosen.size === 0} onClick={start}>{preset === "dry" ? "Show the plan" : ahead ? "Add to queue" : "Start run"}</button><button class="btn" onClick={reset}>Reset</button></div>
            {scanners.data && chosen.size === 0 && <p class="cc-note" style="margin-top:6px">Pick at least one available scanner.</p>}
          </div>
        </section>

        <div class="cc-grid">
          {!live && benchmarking && (
            <section class="cc-card live" aria-label="Benchmark in progress">
              <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap"><h2 class="big" style="margin:0;font-size:18px">Model benchmark</h2><StatusBadge s="running" />
                <span class="cc-note" style="flex:1">{benchmarking.options.model} · {benchmarking.progress_done} of {benchmarking.progress_total} labeled cases</span>
                <button class="btn warn" onClick={() => cancelBenchmark(benchmarking.id)}>Cancel benchmark</button></div>
              <div class="bar2" style="margin-top:10px" role="progressbar" aria-valuenow={benchmarking.progress_total ? Math.round((100 * benchmarking.progress_done) / benchmarking.progress_total) : 0}><i style={`width:${benchmarking.progress_total ? (100 * benchmarking.progress_done) / benchmarking.progress_total : 0}%`} /></div>
            </section>
          )}
          {live ? <LiveRun run={live} project={project} onOpen={() => setOpen(live.id)} onCancel={() => setConfirmCancel(live.id)} /> : benchmarking ? null : (
            <section class="cc-card"><div class="cc-empty" style="padding:24px"><Icon name="runs" size={24} /><h2>No run in progress</h2><p>Start one on the left, or open a finished run below.</p></div></section>
          )}
          {waiting.length > 0 && (
            <section class="cc-card" aria-label="Waiting in queue">
              <h2>Waiting in queue · {waiting.length}<span class="cc-note" style="text-transform:none;letter-spacing:0">Runs start one at a time, in order</span></h2>
              {waiting.map((q) => (
                <div key={q.id} style="display:flex;align-items:center;gap:12px;padding:8px 0;border-top:1px solid var(--line);font-size:13px">
                  <b>{q.kind === "benchmark" ? "Benchmark" : `#${q.id}`}</b><StatusBadge s="queued" /><span style="flex:1">Position {q.position} · {q.kind === "benchmark" ? `Model benchmark · ${q.options.model}` : presetLabel(q.options, q.kind)} · starts after the run in front · added {when(q.created_at)}</span>
                  <button class="btn sm" onClick={() => (q.kind === "benchmark" ? cancelBenchmark(q.id) : cancel(q.id))}>Remove</button>
                </div>
              ))}
            </section>
          )}
          <section class="cc-card" aria-labelledby="hist-h" style="padding:0">
            <div style="padding:16px 16px 12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
              <h2 id="hist-h" style="margin:0">History</h2>
              <div class="cc-chips">{(["all", "done", "failed", "cancelled"] as const).map((k) => (
                <button key={k} class="cc-chip" aria-pressed={filter === k} onClick={() => setFilter(k)}>{{ all: "All", done: "Succeeded", failed: "Failed", cancelled: "Cancelled" }[k]} {counts[k]}</button>))}</div>
            </div>
            <div class="tbl-wrap" style="border:0;border-top:1px solid var(--line);border-radius:0 0 8px 8px">
              <table class="tbl"><thead><tr><th>Run</th><th>Status</th><th>Started</th><th class="num">Duration</th><th class="num">Findings</th><th class="num">Score</th><th>Note</th></tr></thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} class="click" onClick={() => setOpen(r.id)}>
                      <td><a href={`#/p/${project.id}/runs/${r.id}`} onClick={(e) => { e.preventDefault(); setOpen(r.id); }}><b>#{r.id}</b></a><span class="sub">{presetLabel(r.options, r.kind)}{r.started_by ? ` · by ${r.started_by}` : ""}</span></td>
                      <td><StatusBadge s={r.status} /></td><td>{when(r.started_at ?? r.created_at)}</td>
                      <td class="num">{r.started_at ? duration(r.started_at, r.finished_at) : "-"}</td>
                      <td class="num">{r.findings ?? "-"}</td><td class="num">{r.grade ? <Grade g={r.grade} n={r.score} /> : "-"}</td>
                      <td style="max-width:220px">{r.error ? <span class="sub" style="color:var(--sev-high)">{r.error}</span> : r.stats.plan ? <span class="sub">{r.stats.plan.scanners.filter((x) => x.will_run).length} of {r.stats.plan.scanners.length} scanners · {r.stats.plan.scannable} files</span> : <span class="sub">{r.model || ""}</span>}</td>
                    </tr>
                  ))}
                  {rows.length === 0 && <tr><td colSpan={7} class="cc-note" style="padding:16px">No runs match.</td></tr>}
                </tbody></table>
              <div style="padding:10px 16px;border-top:1px solid var(--line);display:flex;justify-content:space-between;font-size:12px;color:var(--text-2)">
                <span>Showing {rows.length} of {shown.length} runs</span>
                {shown.length > 7 && <button class="btn ghost sm" onClick={() => setShowAll(!showAll)}>{showAll ? "Show fewer" : "Show older runs"}</button>}
              </div>
            </div>
          </section>
        </div>
      </div>
      {confirmCancel != null && (
        <ConfirmDialog title={`Cancel run #${confirmCancel}?`} confirm="Cancel run" danger onCancel={() => setConfirmCancel(null)} onConfirm={() => { void cancel(confirmCancel); setConfirmCancel(null); }}>
          The run stops after the finding in progress. An unfinished run is not saved, so it will not appear in Compare or on Overview.{waiting.length ? ` Run #${waiting[0]?.id} then starts.` : ""}
        </ConfirmDialog>
      )}
      {open != null && <RunDrawer id={open} project={project} onClose={() => setOpen(null)} reload={reload} />}
    </>
  );
}

function LiveRun({ run, onOpen, onCancel }: { run: Scan; project: ProjectDetail; onOpen: () => void; onCancel: () => void }) {
  const [, tick] = useState(0);
  useEffect(() => { const t = window.setInterval(() => tick((n) => n + 1), 1000); return () => window.clearInterval(t); }, []);
  const v = run.stats.verdicts ?? {};
  const pct = run.progress_total ? Math.round((100 * run.progress_done) / run.progress_total) : 0;
  const triaging = run.phase === "triaging";
  return (
    <section class="cc-card live" aria-label={`Run ${run.id} in progress`}>
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <h2 class="big" style="margin:0;font-size:18px">Run #{run.id}</h2><StatusBadge s="running" />
        <span class="cc-note" style="flex:1">Started {when(run.started_at)} · {presetLabel(run.options)}{run.options.profile ? ` · ${run.options.profile}` : ""}</span>
        <b style="font-family:var(--mono)">{elapsed(run)}</b>
      </div>
      <Pipeline run={run} />
      {triaging && (
        <>
          <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:6px"><b>AI review · {run.progress_done} of {run.progress_total} findings</b>
            <span class="cc-note">{run.stats.seconds_per_finding ? `${run.stats.seconds_per_finding} s per finding` : ""}{run.stats.seconds_left ? ` · about ${Math.max(1, Math.round(run.stats.seconds_left / 60))} min left` : ""}{run.stats.tokens ? ` · ${run.stats.tokens.toLocaleString("en-US")} tokens` : ""}</span></div>
          <div class="bar2" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}><i style={`width:${pct}%`} /></div>
          <p class="cc-note" style="margin:8px 0 0">{(["true_positive", "likely_true_positive", "needs_review", "false_positive", "triage_failed"] as const).filter((k) => v[k]).map((k) => `${VERDICT_LABEL[k as VerdictKey]} ${v[k]}`).join("  ·  ") || "Waiting for the first verdict..."}</p>
        </>
      )}
      {!triaging && <p class="cc-note" style="display:flex;gap:8px;align-items:center"><Spinner />{stepLabel(run)}</p>}
      <div style="display:flex;justify-content:space-between;margin-top:14px">
        <button class="btn" onClick={onOpen}>Open details and live log</button><button class="btn warn" onClick={onCancel}>Cancel run</button>
      </div>
    </section>
  );
}

const failedStep = (run: Scan): string => stepsFor(run.options).find((x) => x.id === run.stats.failed_at)?.label ?? "";

function PlanView({ run }: { run: Scan }) {
  const plan = run.stats.plan;
  if (!plan) return <p class="cc-note">The plan is not ready yet.</p>;
  const langs = Object.entries(plan.by_language);
  return (
    <div style="margin-bottom:14px">
      <div class="fd-banner grey" role="note" style="margin-top:0"><b><Icon name="info" size={13} /> This is a plan, not a result</b><p>{plan.changes}</p></div>
      {!plan.exists && <Err text="The project folder no longer exists." />}
      <div class="stat3" style="margin-bottom:12px"><div><span class="v">{plan.scannable}</span><span class="l">scannable files of {plan.files}{plan.truncated ? " (counting stopped early)" : ""}</span></div>
        <div><span class="v">{plan.scanners.filter((x) => x.will_run).length}/{plan.scanners.length}</span><span class="l">scanners would run</span></div>
        <div><span class="v">{plan.estimate_seconds ? (plan.estimate_seconds < 90 ? `${Math.round(plan.estimate_seconds)} s` : `${Math.round(plan.estimate_seconds / 60)} min`) : "-"}</span><span class="l">{plan.estimate_seconds ? "from the last similar run" : "no earlier run to estimate from"}</span></div></div>
      {langs.length > 0 && <p style="font-size:13px"><b>Languages</b> {langs.map(([k, v]) => `${k} ${v}`).join(" · ")}</p>}
      <div class="tbl-wrap" style="margin-bottom:12px"><table class="tbl"><thead><tr><th>Scanner</th><th>Would</th><th>Detail</th></tr></thead><tbody>
        {plan.scanners.map((x) => <tr key={x.name}><td>{x.name}</td><td>{x.will_run ? <span class="badge2 ok"><Icon name="check" size={12} />Run</span> : <span class="badge2 bad"><Icon name="x" size={12} />Skip</span>}</td><td class="cc-note">{x.will_run ? x.version : x.why}</td></tr>)}
      </tbody></table></div>
      <p style="font-size:13px"><b>AI review</b> {plan.ai.enabled ? <>would review {plan.ai.limit === 0 ? <b>every finding</b> : <>up to <b>{plan.ai.limit}</b> findings</>} with <span class="mono">{plan.ai.model}</span> ({plan.ai.profile}), up to {plan.ai.tool_calls} tool calls each.{plan.ai.installed === false && <span style="color:var(--sev-high)"> The model is not installed.</span>}{plan.ai.error && <span style="color:var(--sev-high)"> {plan.ai.error}</span>}</> : "is off."}</p>
      {plan.ignore.file && <p style="font-size:13px"><b>.gapscanignore</b> drops findings in {plan.ignore.paths} path patterns and {plan.ignore.rules} rules.</p>}
    </div>
  );
}

export function RunDrawer({ id, project, onClose, reload }: { id: number; project: ProjectDetail; onClose: () => void; reload: () => void }) {
  const { data: run, error, reload: again } = useLoad(() => fetchScan(id), [id], (s) => ACTIVE.includes(s.status));
  const [msg, setMsg] = useState("");
  if (!run) return <Drawer title={`Run #${id}`} onClose={onClose}><Err text={error} /><p class="cc-note">Loading...</p></Drawer>;
  const act = async (path: string) => { try { await api("POST", path); setMsg(""); again(); reload(); } catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); } };
  const active = ACTIVE.includes(run.status);
  return (
    <Drawer title={<span style="display:flex;gap:10px;align-items:center">Run #{run.id} <StatusBadge s={run.status} /></span>} onClose={onClose}>
      <Err text={msg || error} />
      {(run.status === "failed" || run.status === "interrupted") && (
        <div class="fd-banner bad" role="status" style="margin-top:0"><b><Icon name="x" size={13} /> {run.status === "interrupted" ? `Run #${run.id} was interrupted` : `Run #${run.id} failed${failedStep(run) ? ` at ${failedStep(run)}` : ""}`}</b>
          <p>{run.status === "interrupted" ? "The app was restarted while this run was working, so it could not finish." : run.error || "The run stopped with an error. The log below has the detail."} Nothing from this run changes your earlier results or history.</p></div>
      )}
      <p class="cc-note" style="margin-top:0">{presetLabel(run.options, run.kind)}{run.options.profile ? ` · ${run.options.profile}` : ""}{run.branch ? ` · ${run.branch}${run.commit_sha ? ` @ ${run.commit_sha}` : ""}` : ""}{run.options.base ? ` · since ${run.options.base}` : ""} · started {when(run.started_at ?? run.created_at)} · {run.started_at ? duration(run.started_at, run.finished_at) : "not started"}</p>
      {run.kind === "dryrun" ? <PlanView run={run} /> : <Pipeline run={run} />}
      {run.status === "done" && run.kind !== "dryrun" && (
        <div class="stat3" style="margin-bottom:14px">
          <div><span class="v">{run.grade}</span><span class="l">Grade · {run.score?.toFixed(0)}/100</span></div>
          <div><span class="v">{run.open_findings}</span><span class="l">Open findings</span></div>
          <div><span class="v">{run.findings}</span><span class="l">All findings</span></div>
        </div>
      )}
      {run.stats.scanners && run.stats.scanners.length > 0 && (
        <div class="tbl-wrap" style="margin-bottom:14px"><table class="tbl"><thead><tr><th>Scanner</th><th>Status</th><th class="num">Findings</th><th class="num">Seconds</th></tr></thead>
          <tbody>{run.stats.scanners.map((s) => <tr key={s.name}><td>{s.name}</td><td>{s.status === "ok" ? <span class="badge2 ok"><Icon name="check" size={12} />OK</span> : <span class="badge2 bad">{s.status}</span>}</td><td class="num">{s.findings}</td><td class="num">{s.seconds.toFixed(1)}</td></tr>)}</tbody></table></div>
      )}
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
        {run.status === "done" && run.kind !== "dryrun" && <button class="btn primary" onClick={() => { onClose(); navigate("overview", null, String(project.id)); }}>Open results</button>}
        {run.has_report && <a class="btn" href={`/api/scans/${run.id}/report.html`} target="_blank" rel="noopener">Open full report <Icon name="external" size={12} /></a>}
        {run.exports?.map((n) => <a class="btn sm" key={n} href={`/api/scans/${run.id}/exports/${n}`} download={n}>{EXPORT_LABEL[n] ?? n}</a>)}
        {run.status === "done" && run.kind !== "dryrun" && <button class="btn" onClick={() => act(`/api/scans/${run.id}/rebuild`)}>Rebuild report</button>}
        {active && <button class="btn warn" onClick={() => act(`/api/scans/${run.id}/cancel`)}>Cancel run</button>}
      </div>
      {run.status === "done" && run.kind !== "dryrun" && <SendToWorkspace runId={run.id} projectId={project.id} />}
      <h3 style="font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:var(--text-3)">Log</h3>
      <pre class="logbox">{run.log || "(empty)"}</pre>
    </Drawer>
  );
}
