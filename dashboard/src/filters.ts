import { effectiveSeverity, SEV_RANK, location } from "./format";
import type { Decision, FindingRow, Severity, VerdictKey } from "./types";

export interface Criteria {
  text: string;
  severities: Set<Severity>;
  verdicts: Set<VerdictKey>;
  categories: Set<string>;
  owasp: string;
  cwe: string;
  scanner: string;
  path: string;
  minConfidence: number; // 0-1; findings without a confidence pass only when 0
  evidence: "all" | "scanner" | "llm_only";
  since: "all" | "new" | "unchanged"; // compared with the baseline run
  showDismissed: boolean;
}

export const emptyCriteria = (): Criteria => ({
  text: "", severities: new Set(), verdicts: new Set(), categories: new Set(), owasp: "", cwe: "", scanner: "",
  path: "", minConfidence: 0, evidence: "all", since: "all", showDismissed: false,
});

export type SortKey = "risk" | "severity" | "title" | "location" | "verdict" | "confidence";
export type GroupKey = "none" | "file" | "category" | "owasp" | "cwe" | "scanner" | "severity";

export interface IndexedRow { row: FindingRow; haystack: string }

/** Precompute the lowercase search text once per row so filtering 10k rows stays instant. */
export function indexRows(rows: FindingRow[]): IndexedRow[] {
  return rows.map((row) => ({
    row,
    haystack: [row.title, row.rule_id, location(row), row.cwe.join(" "), row.owasp.join(" "), row.cve.join(" "), row.package ?? "", row.scanners.join(" ")]
      .join(" ").toLowerCase(),
  }));
}

export function isOpen(row: FindingRow, decisions: Record<string, Decision>): boolean {
  return row.open && !decisions[row.id];
}

export function filterRows(index: IndexedRow[], c: Criteria, decisions: Record<string, Decision>): FindingRow[] {
  const text = c.text.trim().toLowerCase();
  const terms = text ? text.split(/\s+/) : [];
  const path = c.path.trim().toLowerCase();
  const cwe = c.cwe.trim().toLowerCase();
  const out: FindingRow[] = [];
  for (const { row, haystack } of index) {
    if (!c.showDismissed && !isOpen(row, decisions)) continue;
    if (c.severities.size && !c.severities.has(effectiveSeverity(row))) continue;
    if (c.verdicts.size && !c.verdicts.has(row.verdict)) continue;
    if (c.categories.size && !c.categories.has(row.category)) continue;
    if (c.owasp && !row.owasp.includes(c.owasp)) continue;
    if (cwe && !row.cwe.some((x) => x.toLowerCase().includes(cwe))) continue;
    if (c.scanner && !row.scanners.includes(c.scanner)) continue;
    if (path && !(row.file ?? row.package ?? "").toLowerCase().includes(path)) continue;
    if (c.minConfidence > 0 && (row.confidence ?? 0) < c.minConfidence) continue;
    if (c.evidence === "llm_only" && !row.llm_only) continue;
    if (c.evidence === "scanner" && row.llm_only) continue;
    if (c.since !== "all" && row.status !== c.since) continue;
    if (terms.length && !terms.every((t) => haystack.includes(t))) continue;
    out.push(row);
  }
  return out;
}

const VERDICT_ORDER: Record<VerdictKey, number> = {
  true_positive: 0, likely_true_positive: 1, needs_review: 2, triage_failed: 3, not_triaged: 4, false_positive: 5,
};

export function sortRows(rows: FindingRow[], key: SortKey, dir: 1 | -1): FindingRow[] {
  const cmp: Record<SortKey, (a: FindingRow, b: FindingRow) => number> = {
    risk: (a, b) => b.risk_points - a.risk_points,
    severity: (a, b) => SEV_RANK[effectiveSeverity(b)] - SEV_RANK[effectiveSeverity(a)],
    title: (a, b) => a.title.localeCompare(b.title),
    location: (a, b) => location(a).localeCompare(location(b)),
    verdict: (a, b) => VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict],
    confidence: (a, b) => (b.confidence ?? -1) - (a.confidence ?? -1),
  };
  // `rows` is already in server-ranked order, which acts as the stable tiebreaker.
  return [...rows].sort((a, b) => dir * cmp[key](a, b));
}

export function groupLabel(row: FindingRow, by: GroupKey): string[] {
  switch (by) {
    case "file": return [row.file ?? row.package ?? "(no file)"];
    case "category": return [row.category];
    case "owasp": return row.owasp.length ? [row.owasp[0] as string] : ["(unmapped)"];
    case "cwe": return row.cwe.length ? [row.cwe[0] as string] : ["(no CWE)"];
    case "scanner": return [row.scanners.join("+") || "(unknown)"];
    case "severity": return [effectiveSeverity(row)];
    default: return [""];
  }
}

export type ListItem = { kind: "group"; label: string; count: number; collapsed: boolean } | { kind: "row"; row: FindingRow };

export function flatten(rows: FindingRow[], by: GroupKey, collapsed: Set<string>): ListItem[] {
  if (by === "none") return rows.map((row) => ({ kind: "row", row }));
  const groups = new Map<string, FindingRow[]>();
  for (const r of rows) {
    const key = groupLabel(r, by)[0] as string;
    const list = groups.get(key);
    if (list) list.push(r); else groups.set(key, [r]);
  }
  const out: ListItem[] = [];
  for (const [label, members] of groups) {
    const isCollapsed = collapsed.has(label);
    out.push({ kind: "group", label, count: members.length, collapsed: isCollapsed });
    if (!isCollapsed) members.forEach((row) => out.push({ kind: "row", row }));
  }
  return out;
}
