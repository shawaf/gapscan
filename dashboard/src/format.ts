import type { Severity, VerdictKey } from "./types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const SEV_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
// A distinct glyph per severity so meaning never depends on color alone.
export const SEV_GLYPH: Record<Severity, string> = { critical: "◆", high: "▲", medium: "■", low: "●", info: "○" };
export const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export const VERDICT_LABEL: Record<VerdictKey, string> = {
  true_positive: "Confirmed",
  likely_true_positive: "Likely real",
  false_positive: "False positive",
  needs_review: "Needs review",
  not_triaged: "Not reviewed",
  triage_failed: "Review failed",
};
export const VERDICTS: VerdictKey[] = [
  "true_positive", "likely_true_positive", "needs_review", "not_triaged", "triage_failed", "false_positive",
];
export const CATEGORY_LABEL: Record<string, string> = { code: "Code", dependency: "Dependency", secret: "Secret", config: "Config" };
export const DECISION_LABEL = { accepted_risk: "Accepted risk", false_positive: "False positive", fixed: "Fixed" } as const;

export const pct = (n: number, digits = 0): string => `${n.toFixed(digits)}%`;
export const num = (n: number): string => n.toLocaleString("en-US");
export const shortDate = (iso: string): string => (iso ? iso.slice(0, 10) : "-");
export const location = (f: { file: string | null; start_line: number | null; package: string | null; version: string | null }): string =>
  f.file ? (f.start_line ? `${f.file}:${f.start_line}` : f.file) : f.package ? `${f.package} ${f.version ?? ""}`.trim() : "-";
export const effectiveSeverity = (f: { severity: Severity; severity_adjusted: Severity | null }): Severity => f.severity_adjusted ?? f.severity;

export function csvEscape(v: unknown): string {
  const s = Array.isArray(v) ? v.join(";") : v == null ? "" : String(v);
  // Guard against spreadsheet formula injection from scanned content.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/** A scanner title without its rule plumbing: "Semgrep Finding: a.b.tainted-sql-string" is "Tainted sql string". */
export function plainTitle(t: string): string {
  const m = /^Semgrep Finding:\s*(\S+)$/i.exec(t);
  if (!m) return t;
  const words = (m[1]?.split(".").pop() ?? t).replace(/[-_]+/g, " ").trim();
  return words ? words[0]?.toUpperCase() + words.slice(1) : t;
}
