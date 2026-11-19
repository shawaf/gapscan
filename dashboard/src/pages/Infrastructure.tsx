import { SeverityBadge } from "../components/Badges";
import { useData } from "../context";
import { SEVERITIES } from "../format";
import { emptyCriteria } from "../filters";
import { navigate } from "../store";
import type { Severity } from "../types";
import { findingsUi } from "./Findings";

/** Open the findings list filtered to one file or image (the filter stays visible and editable there). */
export function showPath(path: string) {
  findingsUi.set((p) => ({ ...p, criteria: { ...emptyCriteria(), path }, cursor: 0 }));
  navigate("findings");
}

export function SevCounts({ counts }: { counts: Record<string, number> }) {
  const shown = SEVERITIES.filter((s) => (counts[s] ?? 0) > 0);
  if (!shown.length) return <span class="muted">none</span>;
  return <span class="sevcounts">{shown.map((s) => <span key={s}><SeverityBadge severity={s as Severity} /> {counts[s]}</span>)}</span>;
}

export function Infrastructure() {
  const { data } = useData();
  const groups = data.infrastructure ?? [];
  const total = groups.reduce((n, g) => n + g.files.reduce((m, f) => m + f.findings, 0), 0);
  return (
    <div>
      <h1>Infrastructure as code</h1>
      <p class="muted">{total} open finding{total === 1 ? "" : "s"} in Dockerfiles, Kubernetes and Helm manifests, Terraform, Compose files and CI pipelines, grouped by kind of file. Worst first.</p>
      {groups.length === 0 ? <div class="card"><div class="empty">No infrastructure or configuration issues found.</div></div> : groups.map((g) => (
        <section key={g.kind} class="card" style={{ marginBottom: "14px" }} aria-labelledby={`iac-${g.kind}`}>
          <h2 id={`iac-${g.kind}`} style={{ marginTop: 0 }}>{g.kind} <SevCounts counts={g.by_severity} /></h2>
          <table class="t"><thead><tr><th>File</th><th>Worst</th><th class="num">Findings</th><th></th></tr></thead>
            <tbody>{g.files.map((f) => (
              <tr key={f.file}><td class="mono">{f.file}</td><td><SeverityBadge severity={f.max_severity} /></td><td class="num">{f.findings}</td>
                <td><a href="#/findings" onClick={(e) => { e.preventDefault(); showPath(f.file); }}>show findings</a></td></tr>
            ))}</tbody></table>
        </section>
      ))}
      <p class="muted">From Checkov, Trivy and Semgrep configuration rules. Helm and Kubernetes templates are checked as written, so a value set at install time can make a finding moot.</p>
    </div>
  );
}
