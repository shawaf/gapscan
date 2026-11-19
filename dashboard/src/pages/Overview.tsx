import { useMemo } from "preact/hooks";
import { Patch } from "../components/Patch";
import { AiText, Meter, SeverityBadge, VerdictBadge } from "../components/Badges";
import { EChart, useChartPalette } from "../components/EChart";
import { useData } from "../context";
import { num, pct, SEV_GLYPH, SEV_LABEL, SEVERITIES, shortDate, VERDICT_LABEL, VERDICTS } from "../format";
import { navigate } from "../store";

export function Overview() {
  const { data } = useData();
  const { score, counts, baseline, freshness, narrative } = data;
  const pal = useChartPalette();

  const sevOption = useMemo(() => ({
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } }, grid: { left: 90, right: 30, top: 10, bottom: 24 },
    xAxis: { type: "value" },
    yAxis: { type: "category", inverse: true, data: SEVERITIES.map((s) => `${SEV_GLYPH[s]} ${SEV_LABEL[s]}`) },
    series: [{
      type: "bar", label: { show: true, position: "right" },
      data: SEVERITIES.map((s) => ({ value: counts.by_severity[s] ?? 0, itemStyle: { color: pal.sev[s] } })),
    }],
  }), [counts, pal]);
  const verdictOption = useMemo(() => ({
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } }, grid: { left: 110, right: 20, top: 10, bottom: 24 },
    xAxis: { type: "value" }, yAxis: { type: "category", inverse: true, data: VERDICTS.map((v) => VERDICT_LABEL[v]) },
    series: [{ type: "bar", data: VERDICTS.map((v) => counts.by_verdict[v] ?? 0), itemStyle: { color: pal.accent }, label: { show: true, position: "right" } }],
  }), [counts, pal]);

  return (
    <div>
      <h1>Executive overview</h1>
      <p class="muted">{data.meta.project} · scanned {shortDate(data.meta.scan_created_at)} · report generated {shortDate(data.meta.generated_at)} · GapScan {data.meta.gapscan_version}</p>

      {(freshness.stale || freshness.vuln_data_age_days != null) && (
        <div class={`card${freshness.stale ? " warn" : ""}`} role="status">
          <b>Data freshness.</b>{" "}
          Vulnerability data is {freshness.vuln_data_age_days ?? "?"} {freshness.vuln_data_age_days === 1 ? "day" : "days"} old{freshness.stale ? " (older than the allowed maximum: findings from newer advisories may be missing)" : ""}.
          {" "}{freshness.bundle ? `Data bundle built ${freshness.bundle}. ` : ""}Standards: {Object.entries(freshness.owasp).map(([k, v]) => `${k} ${v}`).join(" · ") || "n/a"}. Model: {freshness.model || "none"}.
        </div>
      )}

      <div class="grid cols-3" style={{ marginTop: "14px" }}>
        <div class="card">
          <div class="score"><span class={`grade grade-${score.grade}`} aria-label={`Grade ${score.grade}`}>{score.grade}</span><div class="kpi"><span class="v">{score.value.toFixed(0)}</span><span class="l">risk score (0 = none, 100 = severe)</span></div></div>
          <Meter value={score.value} label="Risk score" />
          <details><summary>How is this calculated?</summary>
            <ul>{score.explanation.map((l, i) => <li key={i}>{l}</li>)}</ul>
            <table class="t"><thead><tr><th>Category</th><th class="num">Findings</th><th class="num">Points</th></tr></thead>
              <tbody>{score.components.map((c) => <tr key={c.name}><td>{c.name}</td><td class="num">{c.findings}</td><td class="num">{c.points.toFixed(1)}</td></tr>)}</tbody></table>
          </details>
        </div>
        <div class="card kpi"><span class="v">{num(counts.open)}</span><span class="l">open findings ({num(counts.dismissed)} dismissed of {num(counts.total)})</span>
          <p class="muted">{counts.llm_triaged} reviewed by the model · {counts.not_triaged} not reviewed</p></div>
        {baseline ? (
          <div class="card"><h2>Change vs previous scan</h2>
            <div class="grid cols-3"><div class="kpi"><span class="v">{baseline.new}</span><span class="l">new</span></div><div class="kpi"><span class="v">{baseline.fixed}</span><span class="l">fixed</span></div><div class="kpi"><span class="v">{baseline.unchanged}</span><span class="l">still open</span></div></div>
            <p class="muted">{baseline.previous_score != null ? `Previous score ${baseline.previous_score.toFixed(0)}. ` : ""}<a href="#/trends">Details</a></p></div>
        ) : <div class="card"><h2>Change vs previous scan</h2><p class="muted">No baseline given. Pass <span class="mono">--baseline previous-scan.json</span> to <span class="mono">gapscan report</span> to see what is new and what was fixed.</p></div>}
      </div>

      <div class="grid cols-2" style={{ marginTop: "14px" }}>
        <div class="card"><h2>Open findings by severity</h2><EChart option={sevOption} label="Open findings by severity" /></div>
        <div class="card"><h2>Review verdicts (all findings)</h2><EChart option={verdictOption} label="Findings by review verdict" /></div>
      </div>

      {narrative?.headline && (
        <div class="card" style={{ marginTop: "14px" }}>
          <AiText model={freshness.model}>
            <h2>Summary</h2><p>{narrative.headline}</p>
            {narrative.themes.length > 0 && <p><b>Themes:</b> {narrative.themes.join(" · ")}</p>}
            {narrative.recommended_priorities.length > 0 && <><b>Recommended order of work</b><ol>{narrative.recommended_priorities.map((p, i) => <li key={i}>{p}</li>)}</ol></>}
          </AiText>
        </div>
      )}

      <div class="card" style={{ marginTop: "14px" }}>
        <h2>Top 10 risks to fix first</h2>
        {data.top_risks.length === 0 ? <div class="empty patch-tip"><Patch state="done" size={72} label="Patch: no open findings" /><span>No open findings. Checked with no finding is not the same as secure: see the coverage page for controls that need a person.</span></div> : (
          <table class="t" aria-label="Top 10 risks"><thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Why it matters</th><th>Review</th></tr></thead>
            <tbody>{data.top_risks.map((t, i) => (
              <tr key={t.finding_id}><td>{i + 1}</td><td><SeverityBadge severity={t.severity} /></td>
                <td><a href={`#/findings/${encodeURIComponent(t.finding_id)}`} onClick={(e) => { e.preventDefault(); navigate("findings", t.finding_id); }}>{t.title}</a><br /><span class="mono muted">{t.location}</span></td>
                <td>{t.why}</td><td><VerdictBadge verdict={t.verdict} /></td></tr>
            ))}</tbody></table>
        )}
        <p class="muted">Ranked by the deterministic risk score. “Why it matters” is {narrative && !narrative.failed ? "from the AI summary where it covers the finding, else" : ""} the model's review or the scanner's own message.</p>
      </div>
      <p class="print-only">Scanned {data.stats.files_scanned} files, {num(data.stats.loc_total)} lines. {pct(data.asvs?.tool_verifiable_pct ?? 0)} of ASVS L{data.meta.asvs_level} requirements are checkable by tools.</p>
    </div>
  );
}
