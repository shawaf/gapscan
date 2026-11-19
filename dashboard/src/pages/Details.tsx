import { useData } from "../context";
import { num, shortDate } from "../format";

export function Details() {
  const { data } = useData();
  const f = data.freshness;
  return (
    <div>
      <h1>Scan details &amp; limitations</h1>
      <div class="card warn"><h2>What this scan cannot detect</h2><ul>{data.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul></div>
      <div class="grid cols-2" style={{ marginTop: "14px" }}>
        <div class="card"><h2>Scanners</h2>
          <table class="t"><thead><tr><th>Tool</th><th>Status</th><th class="num">Findings</th><th class="num">Seconds</th></tr></thead>
            <tbody>{data.scanners.map((s) => <tr key={s.name}><td><b>{s.name}</b><br /><span class="muted mono">{s.version}</span></td><td>{s.status}{s.error ? <><br /><span class="muted">{s.error}</span></> : null}{s.note ? <><br /><span class="muted">Note: {s.note}</span></> : null}</td><td class="num">{s.findings}</td><td class="num">{s.seconds.toFixed(1)}</td></tr>)}</tbody></table>
          {data.scanners.some((s) => s.status !== "ok") && <p class="card warn">Some scanners did not run, so their findings are missing from this report.</p>}
        </div>
        <div class="card"><h2>Coverage</h2>
          <p>{data.stats.files_scanned} source files, {num(data.stats.loc_total)} lines of code; {data.stats.files_skipped} skipped.</p>
          <table class="t"><tbody>{Object.entries(data.stats.loc_by_language).sort((a, b) => b[1] - a[1]).map(([l, n]) => <tr key={l}><td>{l}</td><td class="num">{num(n)}</td></tr>)}</tbody></table>
          <p class="muted">Scan time {data.stats.duration_s}s (scanners, summed).</p></div>
        <div class="card"><h2>Data and standards</h2>
          <table class="t"><tbody>
            {Object.entries(f.vuln_data).map(([k, v]) => <tr key={k}><td>{k} snapshot</td><td>{shortDate(v)}</td></tr>)}
            {Object.entries(f.owasp).map(([k, v]) => <tr key={k}><td>{k}</td><td>{v}</td></tr>)}
            <tr><td>Report schema</td><td>v{data.meta.report_schema_version} (scan v{data.meta.scan_schema_version})</td></tr>
            <tr><td>GapScan</td><td>{data.meta.gapscan_version}</td></tr></tbody></table></div>
        <div class="card"><h2>AI review</h2>
          <table class="t"><tbody><tr><td>Model</td><td>{f.model || "none"}</td></tr><tr><td>Prompts</td><td>{f.prompt_versions.join(", ") || "-"}</td></tr>
            <tr><td>Knowledge base embeddings</td><td>{f.embedding_model || "-"}</td></tr><tr><td>Reviewed</td><td>{data.counts.llm_triaged} of {data.counts.total} findings</td></tr></tbody></table>
          <p class="muted">Model-written text is labeled “AI-generated” wherever it appears. Scores and counts are computed without the model.</p></div>
      </div>
      <div class="card" style={{ marginTop: "14px" }}><h2>Keyboard shortcuts</h2>
        <p><kbd>1</kbd>–<kbd>9</kbd> switch pages · <kbd>/</kbd> search findings · <kbd>j</kbd>/<kbd>k</kbd> next/previous finding · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close · <kbd>t</kbd> theme</p></div>
    </div>
  );
}
