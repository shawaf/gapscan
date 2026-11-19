import { useState } from "preact/hooks";
import { api, ApiError } from "./api";
import type { ProjectDetail, Scan } from "./api";
import { Drawer, Err, Sev, Verdict } from "./common";
import { Icon } from "./icons";
import { when } from "./useApi";
import { useData } from "../context";
import { SEVERITIES, SEV_LABEL } from "../format";
import { navigate } from "../store";
import type { FindingRow, VerdictKey } from "../types";

const GRADES = ["A", "B", "C", "D", "E", "F"];
const SEV_FILL: Record<string, string> = { critical: "--sev-critical-fill", high: "--sev-high-fill", medium: "--sev-medium-fill", low: "--sev-low-fill", info: "--sev-info-fill" };

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return <p class="cc-note">The trend appears after two scored runs.</p>;
  const w = 320, h = 44, lo = Math.min(...values), hi = Math.max(...values), span = Math.max(hi - lo, 1);
  const pts = values.map((v, i) => `${((i / (values.length - 1)) * w).toFixed(1)},${(h - 4 - ((v - lo) / span) * (h - 8)).toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" role="img" aria-label={`Score over the last ${values.length} scored runs: ${values.join(", ")}`}>
      <polyline points={pts} fill="none" stroke="var(--accent)" stroke-width="2" vector-effect="non-scaling-stroke" />
    </svg>
  );
}

export function Overview({ project, run, reload }: { project: ProjectDetail; run: Scan | null; reload: () => void }) {
  const { data } = useData();
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [why, setWhy] = useState(false);
  const c = data.counts;
  const open = c.open;
  const scored = project.scans.filter((s) => s.kind === "scan" && s.status === "done" && s.score != null).slice(0, 8).reverse();
  const okScanners = data.scanners.filter((s) => s.status === "ok").length;
  const unavailable = data.scanners.filter((s) => s.status !== "ok");
  const prev = data.baseline?.previous_score ?? null;
  const delta = prev != null ? data.score.value - prev : null;
  const gradeIdx = Math.max(0, GRADES.indexOf(data.score.grade));
  const aiOnly = data.findings.filter((f: FindingRow) => f.open && f.llm_only).length;
  const dismissedCarry = data.findings.filter((f: FindingRow) => f.decision);
  const verdictRows: [VerdictKey, number][] = (["true_positive", "likely_true_positive", "needs_review", "false_positive", "not_triaged"] as VerdictKey[]).map((k) => [k, c.by_verdict[k] ?? 0]);
  const maxV = Math.max(1, ...verdictRows.map(([, n]) => n));
  const age = data.freshness.vuln_data_age_days;
  const asvs = data.asvs;
  const post = async (path: string, body?: unknown) => {
    setBusy(true); setMsg("");
    try { await api("POST", path, body); reload(); if (path.endsWith("/scans")) navigate("runs"); } catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); }
    setBusy(false);
  };

  return (
    <>
      <div class="cc-h">
        <div><h1>Overview</h1>
          <p>Last completed run #{run?.id ?? "?"} · {when(run?.finished_at ?? null)} · {okScanners} of {data.scanners.length} scanners · AI review {c.llm_triaged} of {c.total}</p></div>
        <div class="cc-actions">
          {run && <button class="btn ghost" disabled={busy} onClick={() => post(`/api/scans/${run.id}/rebuild`)}>Rebuild report</button>}
          <button class="btn" disabled={busy} onClick={() => post(`/api/projects/${project.id}/scans`, { triage: false })}>Run scan</button>
          <button class="btn primary" disabled={busy} onClick={() => post(`/api/projects/${project.id}/scans`, { triage: true })}>Run scan + AI review</button>
        </div>
      </div>
      <Err text={msg} />
      {data.freshness.stale && (
        <div class="fd-banner warn" role="status" style="margin:0 0 16px"><b><Icon name="warn" size={13} /> Vulnerability data is {age ?? "many"} days old</b>
          <p>Snapshot {Object.values(data.freshness.vuln_data)[0] ?? "unknown"}. Vulnerabilities published after that date are not detected. Standards and the model are unchanged.</p>
          <button class="btn sm" onClick={() => navigate("health")}>Import a newer bundle</button></div>
      )}
      <div class="cc-strip" role="status">
        <span class={age != null && !data.freshness.stale ? "ok" : "warn"} style="display:inline-flex;gap:6px;align-items:center"><Icon name={data.freshness.stale ? "warn" : "check"} size={14} />{data.freshness.stale ? "Data is stale" : age == null ? "Data age unknown" : "Data is fresh"}</span>
        <span>Vulnerability data <b>{age == null ? "unknown age" : `${age} days old`}</b>{Object.values(data.freshness.vuln_data)[0] ? ` · snapshot ${Object.values(data.freshness.vuln_data)[0]}` : ""}</span>
        <span>Standards <b>{Object.entries(data.freshness.owasp).map(([k, v]) => `${k} ${v}`).slice(0, 3).join(" · ") || "OWASP Top 10, ASVS"}</b></span>
        {data.freshness.model && <span>Model <b class="mono">{data.freshness.model}</b></span>}
        <a href="#/health" onClick={(e) => { e.preventDefault(); navigate("health"); }}>Open System Health</a>
      </div>

      <div class="cc-grid g3" style="margin-bottom:16px">
        <section class="cc-card" aria-label="Risk score">
          <h2>Risk score <span style="text-transform:none;letter-spacing:0">lower is better</span></h2>
          <div class="score"><span class="n">{data.score.value.toFixed(0)}</span><span class="of">/100</span>
            <div class="grade-box" aria-label={`Grade ${data.score.grade}`}>{data.score.grade}</div>
            <div><b style="font-size:13px">Grade {data.score.grade}</b>
              {delta != null && <div style={`font-size:13px;color:${delta <= 0 ? "var(--ok)" : "var(--sev-high)"};display:flex;gap:4px;align-items:center`}>{delta <= 0 ? "↓" : "↑"} {delta <= 0 ? "Down" : "Up"} {Math.abs(delta).toFixed(0)} since the previous run</div>}</div></div>
          <div class="scale" aria-hidden="true">{GRADES.map((g, i) => <i key={g} class={i === gradeIdx ? "on" : ""} />)}</div>
          <div class="scale-l">{GRADES.map((g, i) => <span key={g}>{i === gradeIdx ? <b>{g}</b> : g}</span>)}</div>
          <p class="cc-note" style="margin:14px 0 4px">Last {scored.length} scored runs{scored.length > 1 ? ` · ${scored[0]?.score?.toFixed(0)} → ${scored[scored.length - 1]?.score?.toFixed(0)}` : ""}</p>
          <Sparkline values={scored.map((s) => Math.round(s.score ?? 0))} />
          <p style="margin:10px 0 0"><a href="#" onClick={(e) => { e.preventDefault(); setWhy(true); }}>How is this calculated?</a></p>
        </section>

        <section class="cc-card" aria-label="Open gaps by severity">
          <h2>Open gaps by severity <b style="font-size:20px;font-family:var(--mono);color:var(--text)">{open}</b></h2>
          <div class="stack" role="img" aria-label={SEVERITIES.map((s) => `${SEV_LABEL[s]} ${c.by_severity[s] ?? 0}`).join(", ")}>
            {SEVERITIES.map((s) => (c.by_severity[s] ? <i key={s} style={`flex:${c.by_severity[s]};background:var(${SEV_FILL[s]})`} /> : null))}
          </div>
          <div style="margin-top:10px">
            {SEVERITIES.map((s) => (
              <div class="sevrow" key={s}><span><Sev level={s} /></span><span class="n">{c.by_severity[s] ?? 0}</span><span class="p">{open ? Math.round(((c.by_severity[s] ?? 0) / open) * 100) : 0}%</span></div>
            ))}
          </div>
          <p class="cc-note" style="margin:10px 0 0">Scanner-confirmed <b>{open - aiOnly}</b> · AI-only <b>{aiOnly}</b></p>
        </section>

        <section class="cc-card" aria-label="Review verdicts">
          <h2>Review verdicts {data.freshness.model && <span class="ai-tag">AI-generated · {data.freshness.model}</span>}</h2>
          {verdictRows.map(([k, n]) => (
            <div class="verd" key={k}><span><Verdict v={k} /></span><span class="t"><i style={`width:${(n / maxV) * 100}%`} /></span><span class="n">{n}</span></div>
          ))}
          {c.by_verdict["triage_failed"] ? <p class="cc-note" style="margin:8px 0 0">{c.by_verdict["triage_failed"]} reviews failed and need a person.</p> : null}
          <p class="cc-note" style="margin:12px 0 0">Reviewer decisions carried over from earlier scans are not counted as open: {dismissedCarry.filter((f) => f.decision === "accepted_risk").length} accepted risk · {dismissedCarry.filter((f) => f.decision === "false_positive").length} false positive · {dismissedCarry.filter((f) => f.decision === "fixed").length} fixed.</p>
        </section>
      </div>

      <div class="cc-grid g-main">
        <section class="cc-card" style="padding:0" aria-label="Top risks">
          <div style="padding:16px 16px 8px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;align-items:baseline">
            <div><h2 style="margin:0 0 2px">Top {data.top_risks.length} gaps to close first</h2><span class="cc-note">Ranked by severity, verdict confidence and reachability</span></div>
            <span style="display:flex;gap:10px;align-items:center"><span class="ai-tag">“Why it matters” is AI-generated{data.freshness.model ? ` · ${data.freshness.model}` : ""}</span>
              <a href="#/findings" onClick={(e) => { e.preventDefault(); navigate("findings"); }}>View all {open}</a></span>
          </div>
          <div class="tbl-wrap" style="border:0;border-top:1px solid var(--line);border-radius:0 0 8px 8px">
            <table class="tbl"><thead><tr><th>#</th><th>Severity</th><th>Gap and why it matters</th><th>Location</th><th>Verdict and source</th></tr></thead>
              <tbody>
                {data.top_risks.map((t, i) => {
                  const row = data.findings.find((f) => f.id === t.finding_id);
                  return (
                    <tr key={t.finding_id} class="click" onClick={() => navigate("findings", t.finding_id)}>
                      <td class="mono">{i + 1}</td><td><Sev level={t.severity} /></td>
                      <td><a href={`#/findings/${t.finding_id}`} onClick={(e) => { e.preventDefault(); e.stopPropagation(); navigate("findings", t.finding_id); }}><b style="color:var(--text)">{t.title}</b></a><span class="sub">{t.why}</span></td>
                      <td class="mono" style="font-size:12px;word-break:break-all">{t.location}</td>
                      <td><Verdict v={t.verdict} /><span class="sub">{row?.llm_only ? "AI-only, no scanner match" : `Scanner-confirmed · ${row?.scanners.join(", ") ?? ""}`}</span></td>
                    </tr>
                  );
                })}
                {data.top_risks.length === 0 && <tr><td colSpan={5} class="cc-note" style="padding:16px">No open gaps. {c.total ? "Everything was dismissed or fixed." : "This scan found nothing."}</td></tr>}
              </tbody></table>
          </div>
        </section>

        <div class="cc-grid">
          {asvs && (
            <section class="cc-card" aria-label="Target coverage">
              <h2>Target: ASVS {data.freshness.owasp["OWASP ASVS"] ?? "5.0.0"} level {asvs.level}</h2>
              <div class="seg3" role="img" aria-label={`${asvs.evidence_of_failure} failing, ${asvs.no_issue_found_by_tools} no finding, ${asvs.manual_review_required} manual review, of ${asvs.total} controls`}>
                <i class="s-fail" style={`flex:${asvs.evidence_of_failure}`} /><i class="s-ok" style={`flex:${asvs.no_issue_found_by_tools}`} /><i class="s-man" style={`flex:${asvs.manual_review_required}`} /></div>
              <div class="stat3" style="margin-top:12px"><div><span class="v">{asvs.evidence_of_failure}</span><span class="l">Failing</span></div><div><span class="v">{asvs.no_issue_found_by_tools}</span><span class="l">No finding</span></div><div><span class="v">{asvs.manual_review_required}</span><span class="l">Manual</span></div></div>
              <p class="cc-note" style="margin:10px 0 0">Of {asvs.total} controls. "No finding" is not "met": only the weakness classes the scanners report on were checked.</p>
              <p style="margin:8px 0 0"><a href="#/asvs" onClick={(e) => { e.preventDefault(); navigate("asvs"); }}>Open ASVS coverage</a></p>
            </section>
          )}
          <section class="cc-card" aria-label="Change since the previous run">
            <h2>Change since the previous run</h2>
            {data.baseline ? (
              <>
                <div class="stat3"><div><span class="v">{data.baseline.new}</span><span class="l">+ New</span></div><div><span class="v">{data.baseline.fixed}</span><span class="l">✓ Fixed</span></div><div><span class="v">{data.baseline.unchanged}</span><span class="l">= Still open</span></div></div>
                <p style="font-size:13px;margin:12px 0 0">{data.baseline.previous_score != null && <>Score moved from <b>{data.baseline.previous_score.toFixed(0)}</b> to <b>{data.score.value.toFixed(0)}</b>. </>}{data.baseline.fixed_titles.length > 0 && <span class="cc-note">Fixed: {data.baseline.fixed_titles.slice(0, 2).map((f) => f.title).join("; ")}{data.baseline.fixed_titles.length > 2 ? "…" : ""}</span>}</p>
                <p style="margin:10px 0 0"><a href="#/compare" onClick={(e) => { e.preventDefault(); navigate("compare"); }}>Compare runs</a></p>
              </>
            ) : <p class="cc-note">This is the first scan of this project, so there is nothing to compare with yet.</p>}
          </section>
          <section class="cc-card" aria-label="Limits of this result">
            <h2>Limits of this result</h2>
            {unavailable.length > 0 && <div class="limit"><Icon name="warn" size={16} /><span>{unavailable.map((s) => s.name).join(", ")} {unavailable.length === 1 ? "was" : "were"} unavailable, so this run used {okScanners} of {data.scanners.length} scanners. Coverage is reduced.</span></div>}
            {(c.by_verdict["needs_review"] ?? 0) > 0 && <div class="limit"><Icon name="warn" size={16} /><span>{c.by_verdict["needs_review"]} uncertain findings still need a person to decide.</span></div>}
            {data.limitations.slice(0, 3).map((l) => <div class="limit i" key={l}><Icon name="info" size={16} /><span>{l}</span></div>)}
            <div class="limit i"><Icon name="info" size={16} /><span>AI verdicts come from a local model and can be wrong. No gap found does not mean the control is met.</span></div>
          </section>
        </div>
      </div>
      {why && (
        <Drawer title="How the risk score is calculated" onClose={() => setWhy(false)}>
          <p class="cc-note" style="margin-top:0">Computed in Python from the findings, never by the model. Lower is better; A to F are bands of this number.</p>
          <p style="font-size:13px"><b>Score {data.score.value.toFixed(1)}</b> from {data.score.raw_points.toFixed(1)} risk points · grade <b>{data.score.grade}</b></p>
          <ul style="font-size:13px;padding-left:18px">{data.score.explanation.map((l) => <li key={l}>{l}</li>)}</ul>
          <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Component</th><th class="num">Findings</th><th class="num">Points</th><th>Note</th></tr></thead>
            <tbody>{data.score.components.map((k) => <tr key={k.name}><td><b>{k.name}</b></td><td class="num">{k.findings}</td><td class="num">{k.points.toFixed(1)}</td><td class="cc-note">{k.note}</td></tr>)}</tbody></table></div>
        </Drawer>
      )}
    </>
  );
}
