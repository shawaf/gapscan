"""The data contract between the Python engine and the dashboard/exports.

Everything the dashboard shows is in a `ReportData` (embedded as JSON in the single HTML file).
Every number, score and status here is computed in Python; model-written text appears only in
fields labeled as such (`narrative`, `reasoning`, `exploit_scenario`, `fix_suggestion`).
Secret values never appear anywhere in it.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from ..models import EvidenceItem, RelatedItem, ScopeItem

REPORT_SCHEMA_VERSION = 1

DecisionKind = Literal["accepted_risk", "false_positive", "fixed"]
AsvsStatus = Literal["evidence_of_failure", "no_issue_found_by_tools", "manual_review_required"]


class ScannerInfo(BaseModel):
    name: str
    version: str = ""
    status: str
    findings: int = 0
    seconds: float = 0.0
    error: str = ""
    note: str = ""


class Freshness(BaseModel):
    vuln_data: dict[str, str] = Field(default_factory=dict)  # dataset -> snapshot date
    vuln_data_age_days: int | None = None
    stale: bool = False  # older than general.vuln_data_max_age_days
    owasp: dict[str, str] = Field(default_factory=dict)  # Top 10 / ASVS / CWE versions
    model: str = ""
    prompt_versions: list[str] = Field(default_factory=list)
    embedding_model: str = ""
    bundle: str = ""  # when the installed data bundle was built (air-gapped installs)


class ScanStats(BaseModel):
    files_scanned: int = 0
    files_skipped: int = 0
    loc_total: int = 0
    loc_by_language: dict[str, int] = Field(default_factory=dict)
    duration_s: float = 0.0


class ScoreComponent(BaseModel):
    name: str
    points: float
    findings: int
    note: str = ""


class RiskScore(BaseModel):
    value: float  # 0 (no risk) .. 100
    grade: str  # A (best) .. F
    raw_points: float
    components: list[ScoreComponent]
    explanation: list[str]  # the formula in plain language, generated from the constants


class Counts(BaseModel):
    total: int
    open: int  # not dismissed by a verdict or a reviewer decision
    by_severity: dict[str, int]
    by_verdict: dict[str, int]
    by_category: dict[str, int]
    by_scanner: dict[str, int]
    dismissed: int = 0
    llm_triaged: int = 0
    not_triaged: int = 0


class TopRisk(BaseModel):
    finding_id: str
    title: str
    location: str
    severity: str
    priority: float
    verdict: str
    why: str = ""  # from the validated model narrative or the verdict reasoning (labeled in the UI)


class OwaspCategory(BaseModel):
    id: str
    name: str
    description: str = ""
    by_severity: dict[str, int] = Field(default_factory=dict)
    finding_ids: list[str] = Field(default_factory=list)
    cheatsheets: list[dict[str, str]] = Field(default_factory=list)  # {title, url}


class FindingRow(BaseModel):
    id: str
    title: str
    rule_id: str
    severity: str
    severity_adjusted: str | None = None
    category: str
    priority: float  # scanner-side priority (context heuristics)
    risk_points: float = 0.0  # what this finding adds to the risk score; the ranking key
    verdict: str  # true_positive | likely_true_positive | false_positive | needs_review | not_triaged | triage_failed
    confidence: float | None = None
    file: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    asvs: list[str] = Field(default_factory=list)
    scanners: list[str] = Field(default_factory=list)
    package: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    cve: list[str] = Field(default_factory=list)
    kev: bool = False
    epss: float | None = None
    internet_facing: bool = False
    is_test_code: bool = False
    is_tooling_code: bool = False
    llm_only: bool = False
    decision: DecisionKind | None = None
    status: Literal["new", "unchanged"] | None = None  # only with a baseline
    open: bool = True
    asset: str = ""  # code | dependency | secret | iac | image


class DeepDive(BaseModel):
    """Model-written investigation. Every ref kept here was shown to the
    model by a tool; `dropped` counts the claims removed because they were not."""

    failed: bool = False
    error: str = ""
    summary: str = ""
    protection: str = ""  # absent | partial | bypassed | present
    evidence: list[EvidenceItem] = Field(default_factory=list)
    scope: list[ScopeItem] = Field(default_factory=list)
    related: list[RelatedItem] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    target_state: str = ""
    dropped: int = 0
    covers: int = 1  # findings sharing this root cause and this investigation
    tool_calls: int = 0
    model: str = ""
    prompt_version: str = ""


class FindingDetail(BaseModel):
    language: str | None = None
    code: list[tuple[int, str, bool]] = Field(default_factory=list)  # (line, text, flagged)
    function: str | None = None
    callers: list[dict[str, Any]] = Field(default_factory=list)
    untrusted_sources: list[dict[str, Any]] = Field(default_factory=list)
    scanner_messages: list[dict[str, str]] = Field(default_factory=list)  # {scanner, rule, message}
    reasoning: str = ""
    exploit_scenario: str = ""
    fix_suggestion: str = ""
    references: list[str] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    policy_notes: list[str] = Field(default_factory=list)
    memory_notes: list[str] = Field(default_factory=list)  # team memories shown to the model
    model: str = ""
    prompt_version: str = ""
    cwe_names: dict[str, str] = Field(default_factory=dict)
    deep_dive: DeepDive | None = None


class AsvsRequirement(BaseModel):
    id: str
    chapter: str
    section: str
    text: str
    level: int
    status: AsvsStatus
    finding_ids: list[str] = Field(default_factory=list)


class AsvsCoverage(BaseModel):
    level: int
    total: int
    evidence_of_failure: int
    no_issue_found_by_tools: int
    manual_review_required: int
    tool_verifiable_pct: float  # share of requirements any scanner can speak to
    manual_pct: float
    requirements: list[AsvsRequirement]
    note: str


class ControlCoverage(BaseModel):
    id: str
    title: str
    group: str = ""
    level: int | None = None
    status: AsvsStatus  # the same three honest statuses as the ASVS page
    finding_ids: list[str] = Field(default_factory=list)


class TargetCoverage(BaseModel):
    """One standard (a registered target pack): every control in scope and its status."""

    target: str  # pack id, e.g. "owasp-masvs"
    name: str
    version: str
    level: int | None = None  # the level in scope, for standards with levels
    total: int
    evidence_of_failure: int
    no_issue_found_by_tools: int
    manual_review_required: int
    tool_verifiable_pct: float  # share of controls automated evidence can speak to
    controls: list[ControlCoverage]


class PackageRow(BaseModel):
    package: str
    version: str | None
    ecosystem: str | None = None
    cves: list[str] = Field(default_factory=list)
    max_severity: str
    kev: bool = False
    epss: float | None = None
    fixed_version: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    priority: float = 0.0
    reachability: str = "unknown"  # unknown | imported | not_imported_directly (from triage)
    verdict: str = "not_triaged"


class UpgradeStep(BaseModel):
    package: str
    from_version: str | None
    to_version: str
    resolves: int
    kev: bool = False
    risk_points: float


class SbomRow(BaseModel):
    name: str
    version: str = ""
    type: str = "library"
    ecosystem: str = ""
    license: str = ""
    direct: bool | None = None  # None when the SBOM has no dependency graph for it
    vulnerable: bool = False


class Dependencies(BaseModel):
    packages: list[PackageRow] = Field(default_factory=list)
    upgrade_plan: list[UpgradeStep] = Field(default_factory=list)
    sbom: list[SbomRow] = Field(default_factory=list)
    sbom_available: bool = False


class IacFile(BaseModel):
    file: str
    findings: int
    max_severity: str
    finding_ids: list[str] = Field(default_factory=list)


class IacGroup(BaseModel):
    kind: str  # Dockerfile, Kubernetes, Terraform, Helm, ...
    files: list[IacFile] = Field(default_factory=list)
    by_severity: dict[str, int] = Field(default_factory=dict)


class ImageSummary(BaseModel):
    image: str  # the scanned archive's name
    findings: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    vulnerabilities: int = 0
    vulnerable_packages: int = 0
    fixable: int = 0  # vulnerabilities with a fixed version
    kev: int = 0
    misconfigurations: int = 0
    secrets: int = 0
    locations: list[str] = Field(default_factory=list)  # OS / language package sets inside it
    finding_ids: list[str] = Field(default_factory=list)


class Hotspot(BaseModel):
    file: str
    loc: int
    language: str = ""
    findings: int = 0
    risk: float = 0.0
    max_severity: str = "info"


class Baseline(BaseModel):
    previous_created_at: str = ""
    previous_score: float | None = None
    new: int = 0
    fixed: int = 0
    unchanged: int = 0
    fixed_titles: list[dict[str, str]] = Field(default_factory=list)  # {id, title, location}


class Narrative(BaseModel):
    """Model-written text; the dashboard labels it as AI-generated."""

    headline: str = ""
    top_risks: list[dict[str, Any]] = Field(default_factory=list)
    themes: list[str] = Field(default_factory=list)
    recommended_priorities: list[str] = Field(default_factory=list)
    failed: bool = False


class Meta(BaseModel):
    project: str
    generated_at: str
    gapscan_version: str = ""
    report_schema_version: int = REPORT_SCHEMA_VERSION
    scan_schema_version: int = 1
    scan_created_at: str = ""
    asvs_level: int = 2


class ReportData(BaseModel):
    meta: Meta
    scanners: list[ScannerInfo] = Field(default_factory=list)
    freshness: Freshness = Field(default_factory=Freshness)
    stats: ScanStats = Field(default_factory=ScanStats)
    score: RiskScore
    counts: Counts
    top_risks: list[TopRisk] = Field(default_factory=list)
    narrative: Narrative | None = None
    owasp: list[OwaspCategory] = Field(default_factory=list)
    findings: list[FindingRow] = Field(default_factory=list)
    details: dict[str, FindingDetail] = Field(default_factory=dict)
    asvs: AsvsCoverage | None = None
    coverage: list[TargetCoverage] = Field(default_factory=list)  # one per registered standard
    dependencies: Dependencies = Field(default_factory=Dependencies)
    hotspots: list[Hotspot] = Field(default_factory=list)
    infrastructure: list[IacGroup] = Field(default_factory=list)
    images: list[ImageSummary] = Field(default_factory=list)
    baseline: Baseline | None = None
    limitations: list[str] = Field(default_factory=list)
