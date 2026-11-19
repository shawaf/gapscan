// Mirrors packages/gapscan-security/src/gapscan/report/schema.py (ReportData). The dashboard only renders this data:
// every number, score and status is computed in Python; model-written text is labeled.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type VerdictKey =
  | "true_positive" | "likely_true_positive" | "false_positive" | "needs_review" | "not_triaged" | "triage_failed";
export type Category = "code" | "dependency" | "secret" | "config";
export type DecisionKind = "accepted_risk" | "false_positive" | "fixed";
export type AsvsStatus = "evidence_of_failure" | "no_issue_found_by_tools" | "manual_review_required";

export interface ScannerInfo { name: string; version: string; status: string; findings: number; seconds: number; error: string; note?: string }
export interface Freshness {
  vuln_data: Record<string, string>; vuln_data_age_days: number | null; stale: boolean;
  owasp: Record<string, string>; model: string; prompt_versions: string[]; embedding_model: string; bundle: string;
}
export interface ScanStats { files_scanned: number; files_skipped: number; loc_total: number; loc_by_language: Record<string, number>; duration_s: number }
export interface ScoreComponent { name: string; points: number; findings: number; note: string }
export interface RiskScore { value: number; grade: string; raw_points: number; components: ScoreComponent[]; explanation: string[] }
export interface Counts {
  total: number; open: number; by_severity: Record<string, number>; by_verdict: Record<string, number>;
  by_category: Record<string, number>; by_scanner: Record<string, number>; dismissed: number; llm_triaged: number; not_triaged: number;
}
export interface TopRisk { finding_id: string; title: string; location: string; severity: Severity; priority: number; verdict: VerdictKey; why: string }
export interface OwaspCategory {
  id: string; name: string; description: string; by_severity: Record<string, number>;
  finding_ids: string[]; cheatsheets: { title: string; url: string }[];
}
export interface FindingRow {
  id: string; title: string; rule_id: string; severity: Severity; severity_adjusted: Severity | null; category: Category;
  priority: number; risk_points: number; verdict: VerdictKey; confidence: number | null; file: string | null; start_line: number | null;
  end_line: number | null; cwe: string[]; owasp: string[]; asvs: string[]; scanners: string[]; package: string | null;
  version: string | null; fixed_version: string | null; cve: string[]; kev: boolean; epss: number | null;
  internet_facing: boolean; is_test_code: boolean; is_tooling_code?: boolean; llm_only: boolean; decision: DecisionKind | null;
  status: "new" | "unchanged" | null; open: boolean; asset?: string;
}
export interface IacFile { file: string; findings: number; max_severity: Severity; finding_ids: string[] }
export interface IacGroup { kind: string; files: IacFile[]; by_severity: Record<string, number> }
export interface ImageSummary {
  image: string; findings: number; by_severity: Record<string, number>; vulnerabilities: number; vulnerable_packages: number; fixable: number;
  kev: number; misconfigurations: number; secrets: number; locations: string[]; finding_ids: string[];
}
export type EvidenceEffect = "protects" | "undermines" | "missing";
export interface DeepDive {
  failed: boolean; error: string; summary: string; protection: string;
  evidence: { claim: string; ref: string | null; effect: EvidenceEffect; search: string | null; search_scope?: string | null }[];
  scope: { where: string; affected: boolean; ref: string }[];
  related: { ref: string; note: string }[];
  remediation: string[]; verification: string[]; target_state: string;
  dropped: number; covers: number; tool_calls: number; model: string; prompt_version: string;
}
export interface FindingDetail {
  language: string | null; code: [number, string, boolean][]; function: string | null;
  callers: { file: string; line: number; function: string | null; snippet: string }[];
  untrusted_sources: { kind: string; line: number; text: string }[];
  scanner_messages: { scanner: string; rule: string; message: string }[];
  reasoning: string; exploit_scenario: string; fix_suggestion: string; references: string[];
  tool_calls: { tool: string; args: Record<string, string | number>; ok: boolean; evidence_ref: string | null; outcome: string | null }[];
  evidence_refs: string[]; policy_notes: string[]; memory_notes: string[]; model: string; prompt_version: string; cwe_names: Record<string, string>;
  deep_dive?: DeepDive | null;
}
export interface AsvsRequirement { id: string; chapter: string; section: string; text: string; level: number; status: AsvsStatus; finding_ids: string[] }
export interface AsvsCoverage {
  level: number; total: number; evidence_of_failure: number; no_issue_found_by_tools: number; manual_review_required: number;
  tool_verifiable_pct: number; manual_pct: number; requirements: AsvsRequirement[]; note: string;
}
export interface ControlCoverage { id: string; title: string; group: string; level: number | null; status: AsvsStatus; finding_ids: string[] }
export interface TargetCoverage {
  target: string; name: string; version: string; level: number | null; total: number; evidence_of_failure: number;
  no_issue_found_by_tools: number; manual_review_required: number; tool_verifiable_pct: number; controls: ControlCoverage[];
}
export interface PackageRow {
  package: string; version: string | null; ecosystem: string | null; cves: string[]; max_severity: Severity; kev: boolean;
  epss: number | null; fixed_version: string | null; finding_ids: string[]; priority: number; reachability: string; verdict: string;
}
export interface UpgradeStep { package: string; from_version: string | null; to_version: string; resolves: number; kev: boolean; risk_points: number }
export interface SbomRow { name: string; version: string; type: string; ecosystem: string; license: string; direct: boolean | null; vulnerable: boolean }
export interface Dependencies { packages: PackageRow[]; upgrade_plan: UpgradeStep[]; sbom: SbomRow[]; sbom_available: boolean }
export interface Hotspot { file: string; loc: number; language: string; findings: number; risk: number; max_severity: Severity }
export interface Baseline {
  previous_created_at: string; previous_score: number | null; new: number; fixed: number; unchanged: number;
  fixed_titles: { id: string; title: string; location: string }[];
}
export interface Narrative {
  headline: string; top_risks: { title: string; finding_ids: string[]; why: string }[]; themes: string[];
  recommended_priorities: string[]; failed: boolean;
}
export interface Meta {
  project: string; generated_at: string; gapscan_version: string; report_schema_version: number;
  scan_schema_version: number; scan_created_at: string; asvs_level: number;
}
export interface ReportData {
  meta: Meta; scanners: ScannerInfo[]; freshness: Freshness; stats: ScanStats; score: RiskScore; counts: Counts;
  top_risks: TopRisk[]; narrative: Narrative | null; owasp: OwaspCategory[]; findings: FindingRow[];
  details: Record<string, FindingDetail>; asvs: AsvsCoverage | null; dependencies: Dependencies; hotspots: Hotspot[];
  baseline: Baseline | null; limitations: string[];
  infrastructure?: IacGroup[]; images?: ImageSummary[]; coverage?: TargetCoverage[];
}
export interface Decision { finding_id: string; decision: DecisionKind; note: string; by: string; date: string }
