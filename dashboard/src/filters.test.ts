import { describe, expect, it } from "vitest";
import { emptyCriteria, filterRows, flatten, indexRows, sortRows } from "./filters";
import { csvEscape } from "./format";
import type { FindingRow } from "./types";

let n = 0;
const row = (over: Partial<FindingRow> = {}): FindingRow => ({
  id: `f${n++}`, title: "SQL injection", rule_id: "rule", severity: "high", severity_adjusted: null, category: "code", priority: 50, risk_points: 5,
  verdict: "true_positive", confidence: 0.9, file: "app.py", start_line: 10, end_line: 10, cwe: ["CWE-89"], owasp: ["A05:2025"],
  asvs: [], scanners: ["semgrep"], package: null, version: null, fixed_version: null, cve: [], kev: false, epss: null,
  internet_facing: false, is_test_code: false, llm_only: false, decision: null, status: null, open: true, ...over,
});

describe("filters", () => {
  const rows = [
    row({ title: "SQL injection in login", severity: "critical", priority: 90, risk_points: 9 }),
    row({ title: "Weak hash", severity: "medium", cwe: ["CWE-327"], owasp: ["A04:2025"], file: "auth/pw.py", priority: 30, risk_points: 3, verdict: "needs_review", confidence: 0.5 }),
    row({ title: "Dismissed thing", open: false, verdict: "false_positive" }),
    row({ title: "Lodash", confidence: null, verdict: "not_triaged", category: "dependency", file: null, package: "lodash", version: "4.17.10", cve: ["CVE-2020-8203"], scanners: ["osv", "trivy"], severity: "high", severity_adjusted: "low" }),
  ];
  const index = indexRows(rows);

  it("hides dismissed findings unless asked, and honors reviewer decisions", () => {
    expect(filterRows(index, emptyCriteria(), {}).length).toBe(3);
    expect(filterRows(index, { ...emptyCriteria(), showDismissed: true }, {}).length).toBe(4);
    const decisions = { [rows[0]!.id]: { finding_id: rows[0]!.id, decision: "accepted_risk" as const, note: "", by: "", date: "" } };
    expect(filterRows(index, emptyCriteria(), decisions).map((r) => r.title)).not.toContain("SQL injection in login");
  });

  it("filters by severity (using the adjusted severity), verdict, category, OWASP, CWE, scanner, path and confidence", () => {
    const f = (c: Partial<ReturnType<typeof emptyCriteria>>) => filterRows(index, { ...emptyCriteria(), ...c }, {}).map((r) => r.title);
    expect(f({ severities: new Set(["low"]) })).toEqual(["Lodash"]); // severity_adjusted wins
    expect(f({ verdicts: new Set(["needs_review"]) })).toEqual(["Weak hash"]);
    expect(f({ categories: new Set(["dependency"]) })).toEqual(["Lodash"]);
    expect(f({ owasp: "A04:2025" })).toEqual(["Weak hash"]);
    expect(f({ cwe: "327" })).toEqual(["Weak hash"]);
    expect(f({ scanner: "trivy" })).toEqual(["Lodash"]);
    expect(f({ path: "auth/" })).toEqual(["Weak hash"]);
    expect(f({ minConfidence: 0.8 })).toEqual(["SQL injection in login"]);
  });

  it("searches all words across title, rule, location, CWE and CVE", () => {
    const f = (text: string) => filterRows(index, { ...emptyCriteria(), text }, {}).map((r) => r.title);
    expect(f("sql login")).toEqual(["SQL injection in login"]);
    expect(f("cve-2020-8203")).toEqual(["Lodash"]);
    expect(f("nothing matches")).toEqual([]);
  });

  it("sorts with a stable tiebreak and reverses", () => {
    const open = filterRows(index, emptyCriteria(), {});
    expect(sortRows(open, "risk", 1)[0]?.title).toBe("SQL injection in login");
    expect(sortRows(open, "risk", -1)[0]?.title).not.toBe("SQL injection in login");
    expect(sortRows(open, "severity", 1)[0]?.severity).toBe("critical");
  });

  it("groups with collapsible headers", () => {
    const open = filterRows(index, emptyCriteria(), {});
    const grouped = flatten(open, "category", new Set());
    expect(grouped.filter((i) => i.kind === "group").map((g) => (g as { label: string }).label)).toEqual(["code", "dependency"]);
    expect(flatten(open, "category", new Set(["code"])).filter((i) => i.kind === "row").length).toBe(1);
    expect(flatten(open, "none", new Set()).every((i) => i.kind === "row")).toBe(true);
  });

  it("filters 10,000 findings in well under a second", () => {
    const big = Array.from({ length: 10_000 }, (_, i) => row({ title: `Finding ${i}`, file: `src/m${i % 300}.py`, severity: (["critical", "high", "medium", "low", "info"] as const)[i % 5]!, cwe: [`CWE-${i % 90}`] }));
    const t0 = performance.now();
    const idx = indexRows(big);
    const hit = filterRows(idx, { ...emptyCriteria(), text: "finding 99", severities: new Set(["high", "critical"]), path: "src/m" }, {});
    sortRows(hit, "severity", 1);
    expect(performance.now() - t0).toBeLessThan(500);
    expect(hit.length).toBeGreaterThan(0);
  });
});

describe("csv", () => {
  it("quotes, joins lists and neutralizes spreadsheet formulas from scanned content", () => {
    expect(csvEscape('a,"b"')).toBe('"a,""b"""');
    expect(csvEscape(["CWE-1", "CWE-2"])).toBe("CWE-1;CWE-2");
    expect(csvEscape("=HYPERLINK(\"http://x\")")).toBe(`"'=HYPERLINK(""http://x"")"`);
    expect(csvEscape(null)).toBe("");
  });
});
