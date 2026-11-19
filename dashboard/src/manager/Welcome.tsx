import { useState } from "preact/hooks";
import { Patch } from "../components/Patch";
import { api, ApiError } from "./api";
import type { DataInfo, PlanStep, Project, SetupStatus } from "./api";
import { Err, Skeleton } from "./common";
import { Icon, Spinner } from "./icons";
import { navigate } from "../store";
import { useSetupQueue } from "./setupQueue";
import type { Item } from "./setupQueue";
import { useLoad } from "./useApi";

const mb = (bytes: number): string => (bytes < 1e9 ? `${Math.max(1, Math.round(bytes / 1e6))} MB` : `${(bytes / 1e9).toFixed(1)} GB`);
const AI_STEPS = ["engine", "model", "embedding"];

function RowState({ step, plan, current, waiting, failed }: { step: PlanStep; plan: PlanStep[]; current: string; waiting: string[]; failed: boolean }) {
  void plan;
  if (step.done) return <span class="badge2 ok"><Icon name="check" size={12} />Ready</span>;
  if (current === step.step && failed) return <span class="badge2 bad"><Icon name="x" size={12} />Failed</span>;
  if (current === step.step) return <span class="badge2 warn"><Spinner size={12} /> Working</span>;
  if (waiting.includes(step.step)) return <span class="cc-note">Waiting</span>;
  return <span class="cc-note">{step.size === 0 ? "Nothing to download" : step.size == null ? "Several hundred MB" : mb(step.size)}</span>;
}

export function WelcomePage() {
  const st = useLoad(() => api<SetupStatus>("GET", "/api/setup"), []);
  const info = useLoad(() => api<DataInfo>("GET", "/api/data"), []);
  const [withAI, setWithAI] = useState(true);
  const [withData, setWithData] = useState(true);
  const [err, setErr] = useState("");
  const q = useSetupQueue(() => { st.reload(); info.reload(); }, st.data?.task);

  const d = st.data;
  const hasData = (info.data?.freshness.length ?? 0) > 0 || !!info.data?.bundle;
  const plan: PlanStep[] = (d?.plan ?? []).map((p) => (p.step === "data" ? { ...p, done: p.done || hasData } : p));
  const aiPossible = plan.some((p) => p.step === "model");
  const chosen = (p: PlanStep) => (AI_STEPS.includes(p.step) ? withAI && aiPossible : p.step === "data" ? withData : true);
  const shown = plan.filter((p) => chosen(p));
  const todo = shown.filter((p) => !p.done);
  const total = todo.reduce((n, p) => n + (p.size ?? 0), 0);
  const items: Item[] = todo.map((p) => ({ step: p.step, pack: p.pack, label: p.label }));
  const tier = d?.tiers.find((t) => t.id === (d.selected ?? d.recommended));
  const everythingReady = !!d && todo.length === 0;
  const finishedOk = q.finished === "done" || (everythingReady && !q.running);

  const markDone = async (value: "done" | "skipped") => { try { await api("POST", "/api/setup/welcome", { value }); } catch { /* the page still moves on */ } };
  const skip = async () => { await markDone("skipped"); navigate("security", null, null); };
  const addOwn = async () => { await markDone("done"); navigate("security", null, null); };
  const trySample = async () => {
    try {
      const p = await api<Project>("POST", "/api/sample", {});
      await api("POST", `/api/projects/${p.id}/scans`, { triage: false });
      await markDone("done");
      navigate("runs", null, String(p.id));
    } catch (x) { setErr(x instanceof ApiError ? x.message : String(x)); }
  };

  const pct = q.task?.progress && q.task.progress.total ? Math.round((100 * q.task.progress.done) / q.task.progress.total) : 0;
  if (!d) return <>{st.error ? <Err text={st.error} /> : <Skeleton rows={6} />}</>;

  return (
    <div style="max-width:760px;margin:0 auto">
      <div class="cc-h patch-tip" style="margin-bottom:8px"><Patch state="greet" size={96} /><div><h1>Welcome to GapScan</h1>
        <p class="sub">Find the gaps between your code and the standard it answers to, prove them with evidence, and prove when they are closed. GapScan starts with application security: OWASP ASVS 5.0 and Top 10:2025. This is local mode: nothing is uploaded, and nothing in your projects is ever run.</p></div></div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:12px 0 16px">
        {[["asvs", "Measured", "Every gap is a control from a standard that your code does not meet."], ["findings", "Proven", "Each gap links to its evidence: the code, the scanner result and a fix."], ["lock", "Local", "Your code never leaves this computer. Scans run without a network."]].map(([icon, title, text]) => (
          <div class="cc-card" key={title} style="padding:12px 14px"><b style="display:flex;gap:6px;align-items:center"><Icon name={icon as never} size={14} />{title}</b><p class="cc-note" style="margin:4px 0 0">{text}</p></div>
        ))}
      </div>

      <section class="cc-card" aria-labelledby="w-h">
        <h2 id="w-h" style="margin-top:0">Set up this computer</h2>
        <p class="cc-note" style="margin:0 0 12px">
          {tier ? <>This computer has {d.hardware.ram_gb} GB of memory, enough for the AI model <b class="mono">{tier.alias}</b>. </> : <>This computer has {d.hardware.ram_gb} GB of memory, which is too little for an AI model, so GapScan will use its scanners only. </>}
          Everything is downloaded once, here.
        </p>
        <div class="tbl-wrap" style="border:0"><table class="tbl"><tbody>
          {plan.map((p) => (
            <tr key={p.step} style={chosen(p) ? "" : "opacity:.45"}>
              <td style="width:26px">{AI_STEPS.includes(p.step) || p.step === "data" ? <input type="checkbox" aria-label={`Include ${p.label}`} disabled={q.running} checked={chosen(p)} style="accent-color:var(--accent)"
                  onChange={(e) => (p.step === "data" ? setWithData(e.currentTarget.checked) : setWithAI(e.currentTarget.checked))} /> : <Icon name="check" size={12} />}</td>
              <td><b>{p.label}</b>{p.note ? <span class="sub">{p.note}</span> : p.optional ? <span class="sub">Needed for dependency checks and AI explanations. Skip it if you will import a bundle.</span> : null}</td>
              <td class="num"><RowState step={p} plan={plan} current={q.current} waiting={q.waiting} failed={q.finished === "failed"} /></td>
            </tr>
          ))}
        </tbody></table></div>

        {q.running && q.task?.status === "running" && (
          <div style="margin:12px 0" aria-live="polite">
            <b>{q.label}</b>
            {q.task.progress && q.task.progress.total > 0 ? <><div class="bar2" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} style="margin:6px 0"><i style={`width:${pct}%`} /></div>
              <span class="cc-note">{pct}% · {mb(q.task.progress.done)} of {mb(q.task.progress.total)}. If you stop, what is downloaded is kept.</span></> : <p class="cc-note"><Spinner size={12} /> Working ...</p>}
          </div>
        )}
        {q.finished === "failed" && (
          <div class="fd-banner bad" role="alert" style="margin:12px 0"><b><Icon name="x" size={12} /> A step did not finish</b>
            <p>{q.msg || q.task?.log.slice(-1)[0] || "See the Setup page for details."} You can try the rest again, or carry on and finish later in Setup.</p></div>
        )}
        <Err text={err} />

        {!finishedOk ? (
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
            <button class="btn primary" disabled={q.running || items.length === 0} onClick={() => q.begin(items)}>
              {q.running ? "Setting up ..." : q.finished === "failed" ? "Try again" : total > 0 ? `Set up (${mb(total)}${withData && !hasData && plan.some((p) => p.step === "data" && p.size == null) ? " and security data" : ""})` : "Set up"}</button>
            {q.running && <button class="btn" onClick={q.cancel}>Stop</button>}
            {q.finished === "failed" && <button class="btn" onClick={addOwn}>Carry on anyway</button>}
            {!q.running && <button class="btn ghost" onClick={skip}>Skip for now</button>}
          </div>
        ) : (
          <div class="fd-banner grey" role="status" style="margin:12px 0 0"><b><Icon name="check" size={12} /> You are ready</b>
            <p>Try a sample project to see what a scan finds in a few seconds, or add your own.</p>
            <span style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary" onClick={trySample}>Try the sample project</button><button class="btn" onClick={addOwn}>Add my own project</button></span></div>
        )}
        <p class="cc-note" style="margin:12px 0 0">Setup connects only to {d.hosts.slice(0, 4).join(", ")} and a few more download hosts listed in the app, checks every file against a pinned checksum, and then works offline.</p>
      </section>
    </div>
  );
}
