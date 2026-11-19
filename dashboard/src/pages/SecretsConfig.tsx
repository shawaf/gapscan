import { SeverityBadge, VerdictBadge } from "../components/Badges";
import { useData } from "../context";
import { effectiveSeverity, location } from "../format";
import { navigate } from "../store";
import type { FindingRow } from "../types";

function Table({ rows, empty }: { rows: FindingRow[]; empty: string }) {
  if (!rows.length) return <div class="empty">{empty}</div>;
  return (
    <table class="t"><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Review</th><th>Reported by</th></tr></thead>
      <tbody>{rows.map((r) => (
        <tr key={r.id}><td><SeverityBadge severity={effectiveSeverity(r)} /></td>
          <td><a href={`#/findings/${encodeURIComponent(r.id)}`} onClick={(e) => { e.preventDefault(); navigate("findings", r.id); }}>{r.title}</a><br /><span class="mono muted">{r.rule_id}</span></td>
          <td class="mono">{location(r)}</td><td><VerdictBadge verdict={r.verdict} /></td><td>{r.scanners.join(", ")}</td></tr>
      ))}</tbody></table>
  );
}

export function SecretsConfig() {
  const { data } = useData();
  const open = data.findings.filter((f) => f.open);
  return (
    <div>
      <h1>Secrets</h1>
      <h2>Possible secrets ({open.filter((f) => f.category === "secret").length})</h2>
      <div class="card">
        <Table rows={open.filter((f) => f.category === "secret")} empty="No secrets found." />
        <p class="muted">Secret values are never stored or shown anywhere in this report: only the place, the rule and the review. Rotate any real secret, even after removing it from the code.</p>
      </div>
      <p class="muted">Infrastructure and configuration issues have their own page: <a href="#/iac">Infrastructure</a>.</p>
    </div>
  );
}
