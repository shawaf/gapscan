import type { ComponentChildren } from "preact";
import { useState } from "preact/hooks";
import { api, ApiError } from "./api";
import type { ProjectDetail, Scan, Settings } from "./api";
import { Drawer, Err, verdictShort } from "./common";
import { Icon } from "./icons";
import { LogLines, Monogram, Spark, SevTag, StatTile } from "./tiles";
import { fetchScan, useLoad, when } from "./useApi";
import { useData } from "../context";
import { SEVERITIES, SEV_LABEL, plainTitle } from "../format";
import { navigate } from "../store";
import type { VerdictKey } from "../types";

const SCANNER_JOB: Record<string, string> = {
  semgrep: "code", osv: "dependencies", trivy: "deps and images", checkov: "infrastructure", bandit: "python", gitleaks: "secrets", taint: "data flow", malware: "malicious packages",
};
const VERDICT_TONE: Partial<Record<VerdictKey, string>> = { true_positive: "gap", likely_true_positive: "gap", needs_review: "person", triage_failed: "person", false_positive: "ok" };
const seconds = (s: Scan): number | null => (s.started_at && s.finished_at ? Math.max(0, Math.round((Date.parse(s.finished_at) - Date.parse(s.started_at)) / 1000)) : null);

function Card({ title, note, action, children }: { title: string; note?: ComponentChildren; action?: ComponentChildren; children: ComponentChildren }) {
  return <section class="cc-card mx-list" aria-label={title}><p class="mx-ct"><b>{title}</b>{note && <span>{note}</span>}{action}</p>{children}</section>;
}

export function Overview({ project, run, reload }: { project: ProjectDetail; run: Scan | null; reload: () => void }) {
  const { data } = useData();
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [why, setWhy] = useState(false);
  const settings = useLoad(() => api<Settings>("GET", "/api/settings"), []);
  const full = useLoad<Scan | null>(() => (run ? fetchScan(run.id) : Promise.resolve(null)), [run?.id]);
  const c = data.counts;
  const done = project.scans.filter((s) => s.kind === "scan" && s.status === "done" && s.score != null).slice(0, 7).reverse();
  const ok = data.scanners.filter((s) => s.status === "ok");
  const off = data.scanners.filter((s) => s.status !== "ok");
  const prev = data.baseline?.previous_score ?? null;
  const delta = prev != null ? data.score.value - prev : null;
  const asvs = data.asvs;
  const age = data.freshness.vuln_data_age_days;
  const last = run ? seconds(run) : null;
  const post = async (path: string, body?: unknown) => {
    setBusy(true); setMsg("");
    try { await api("POST", path, body); reload(); if (path.endsWith("/scans")) navigate("runs"); } catch (x) { setMsg(x instanceof ApiError ? x.message : String(x)); }
    setBusy(false);
  };
  const go = (page: string) => (e: Event) => { e.preventDefault(); navigate(page); };
  const worst = (c.by_severity["critical"] ?? 0) > 0 ? "critical" : (SEVERITIES.find((s) => c.by_severity[s]) ?? "critical");
  const trend = delta == null ? "First scored run" : Math.abs(delta) < 0.5 ? "Same as last run" : delta > 0 ? "Worse than last run" : "Better than last run";

  return (
    <>
      <header class="mx-head">
        <Monogram name={project.name} />
        <div><h1>{project.name}</h1><p>Scanned {when(run?.finished_at ?? null)}{asvs ? ` · ASVS level ${asvs.level}` : ""} · OWASP Top 10:{data.freshness.owasp["OWASP Top 10"] ?? "2025"}</p></div>
        <div class="mx-acts">
          {run?.has_report !== false && run && <a class="btn" href={`/api/scans/${run.id}/report.html`} target="_blank" rel="noopener">Open report</a>}
          <button class="btn primary" disabled={busy || !settings.data || project.archived} onClick={() => post(`/api/projects/${project.id}/scans`, { triage: settings.data?.default_preset !== "scanners" })}>Run scan</button>
        </div>
      </header>
      <Err text={msg} />
      {data.freshness.stale && (
        <div class="fd-banner warn" role="status" style="margin:0 0 16px"><b><Icon name="warn" size={13} /> Vulnerability data is {age ?? "many"} days old</b>
          <p>Anything published since then is not detected.</p><button class="btn sm" onClick={() => navigate("health")}>Update the data</button></div>
      )}

      <div class="mx-tiles">
        <StatTile icon="trend" label="Risk score" value={data.score.value.toFixed(0)} unit={`grade ${data.score.grade}`}
          note={<>{trend} · <a href="#" aria-label="How is this calculated?" onClick={(e) => { e.preventDefault(); setWhy(true); }}>How?</a></>}><Spark values={done.map((s) => s.score ?? 0)} label="Risk score" /></StatTile>
        <StatTile icon="findings" label="Open gaps" value={c.open} unit={`of ${c.total}`}
          note={data.baseline ? <>{data.baseline.new} new · {data.baseline.fixed} fixed · <a href="#" onClick={go("compare")}>Compare</a></> : `${c.dismissed} dismissed`}><Spark values={done.map((s) => s.open_findings ?? 0)} label="Open gaps" /></StatTile>
        <StatTile dot={`var(--sev-${worst}-fill)`} label={SEV_LABEL[worst]} value={c.by_severity[worst] ?? 0} unit="gaps"
          note={SEVERITIES.filter((s) => s !== worst && c.by_severity[s]).map((s) => `${c.by_severity[s]} ${SEV_LABEL[s].toLowerCase()}`).join(" · ") || "Nothing else open"}>
          <div class="stack" role="img" aria-label={SEVERITIES.map((s) => `${SEV_LABEL[s]} ${c.by_severity[s] ?? 0}`).join(", ")}>{SEVERITIES.map((s) => (c.by_severity[s] ? <i key={s} style={`flex:${c.by_severity[s]};background:var(--sev-${s}-fill)`} /> : null))}</div></StatTile>
        {asvs && <StatTile icon="asvs" label="ASVS controls" value={asvs.evidence_of_failure} unit="failing"
          note={`${asvs.no_issue_found_by_tools} no issue found · ${asvs.manual_review_required} need a person`}>
          <div class="seg3" role="img" aria-label={`${asvs.evidence_of_failure} failing, ${asvs.no_issue_found_by_tools} no issue found, ${asvs.manual_review_required} need a person`}><i class="s-fail" style={`flex:${asvs.evidence_of_failure}`} /><i class="s-ok" style={`flex:${asvs.no_issue_found_by_tools}`} /><i class="s-man" style={`flex:${asvs.manual_review_required}`} /></div></StatTile>}
        <StatTile icon="runs" label="Scan time" value={last == null ? "-" : last < 120 ? last : Math.round(last / 60)} unit={last == null ? "" : last < 120 ? "s" : "min"}
          note={`${ok.length} of ${data.scanners.length} scanners`}><Spark values={done.map((s) => seconds(s) ?? 0)} label="Scan time in seconds" /></StatTile>
      </div>

      <div class="mx-two">
        <Card title="Fix first" note="ranked by priority" action={<a href="#" onClick={go("findings")}>All gaps</a>}>
          {data.top_risks.slice(0, 8).map((t) => {
            const f = data.findings.find((x) => x.id === t.finding_id);
            return (
              <button class="mx-row" key={t.finding_id} title={t.why} onClick={() => navigate("findings", t.finding_id)}>
                <SevTag level={t.severity} /><span class="tx"><span>{plainTitle(t.title)}</span><span class="mono">{[t.location, f?.cwe[0], f?.owasp[0]?.split(":")[0]].filter(Boolean).join(" · ")}</span></span>
                <span class={`end ${VERDICT_TONE[t.verdict] ?? ""}`}>{verdictShort[t.verdict]}</span>
              </button>
            );
          })}
          {data.top_risks.length === 0 && <p class="cc-note" style="padding:0 8px 8px">No open gaps. {c.total ? "Everything was dismissed or fixed." : "This scan found nothing."}</p>}
        </Card>
        <Card title="Scanners" note={off.length ? `${off.length} unavailable` : `${ok.length} ok`}>
          {data.scanners.map((s) => (
            <div class="mx-row" key={s.name}><span class="mx-dot" style={`background:var(${s.status === "ok" ? "--ok" : "--sev-high-fill"})`} />
              <span class="tx"><span>{s.name}</span><span class="mono">{[SCANNER_JOB[s.name], s.status === "ok" ? (/\d+(\.\d+)+/.exec(s.version)?.[0] ?? "") : s.status].filter(Boolean).join(" · ")}</span></span>
              <span class="end">{s.findings} · {s.seconds.toFixed(1)} s</span></div>
          ))}
        </Card>
      </div>

      {full.data?.log && <section class="cc-card" aria-label="Scan log"><p class="mx-ct"><b>Scan log</b>{data.freshness.model && <span>{data.freshness.model}, local</span>}<a href="#" onClick={go("runs")}>All runs</a></p><LogLines text={full.data.log} tail={8} /></section>}

      <details class="cc-card mx-more"><summary><Icon name="info" size={15} /> About this result</summary>
        <ul>
          {off.length > 0 && <li>{off.map((s) => s.name).join(", ")} did not run, so coverage is reduced.</li>}
          {(c.by_verdict["needs_review"] ?? 0) > 0 && <li>{c.by_verdict["needs_review"]} gaps still need a person to decide.</li>}
          <li>AI reviewed {c.llm_triaged} of {c.total}. Its verdicts come from a local model and can be wrong.</li>
          <li>No gap found does not mean the control is met.</li>
          <li>Vulnerability data: {age == null ? "unknown age" : `${age} days old`}{Object.values(data.freshness.vuln_data)[0] ? `, snapshot ${Object.values(data.freshness.vuln_data)[0]}` : ""}.</li>
          {data.limitations.map((l) => <li key={l}>{l}</li>)}
        </ul>
        {run && <button class="btn sm" disabled={busy} onClick={() => post(`/api/scans/${run.id}/rebuild`)}>Rebuild report</button>}
      </details>

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
