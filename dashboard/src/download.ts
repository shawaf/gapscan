import { csvEscape, effectiveSeverity, location } from "./format";
import type { Decision, FindingRow, ReportData } from "./types";

export function download(filename: string, content: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function findingsCsv(rows: FindingRow[], decisions: Record<string, Decision>): string {
  const header = ["id", "severity", "category", "verdict", "confidence", "priority", "title", "location", "cwe", "owasp", "asvs", "scanners", "package", "version", "fixed_version", "cve", "kev", "epss", "decision"];
  const lines = [header.join(",")];
  for (const r of rows) {
    lines.push([
      r.id, effectiveSeverity(r), r.category, r.verdict, r.confidence ?? "", r.priority, r.title, location(r), r.cwe, r.owasp, r.asvs,
      r.scanners, r.package ?? "", r.version ?? "", r.fixed_version ?? "", r.cve, r.kev, r.epss ?? "", decisions[r.id]?.decision ?? r.decision ?? "",
    ].map(csvEscape).join(","));
  }
  return lines.join("\n") + "\n";
}

export const reportFilename = (data: ReportData, ext: string): string =>
  `gapscan-report-${data.meta.project.replace(/[^\w.-]+/g, "_")}-${data.meta.generated_at.slice(0, 10)}.${ext}`;
