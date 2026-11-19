"""Phase 2: ignore rules, deduplication, dependency grouping, priority scoring and the
LLM cap. Pure and deterministic: no LLM, no network.

Priority formula (0-100), documented for the dashboard's "how is this calculated":
  base      = severity: critical 90, high 70, medium 45, low 20, info 5
  + secret  : +10;  config: -5
  + exposure: +10 if internet-facing (route/handler heuristic)
  + EPSS    : +20 * epss for dependency findings
  x test code 0.4, x vendor code 0.2
  x dev tooling 0.5 (code findings in build/developer scripts and docs that never ship)
  KEV-listed CVE -> 100 (always on top)
"""

from __future__ import annotations

import fnmatch
import re
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from .controls import map_controls
from .core.interfaces import Annotator, TargetPack
from .fingerprint import assign_stable_ids
from .models import Category, Finding, PackageGroup, ScanResult, Severity
from .registry import registry
from .versions import ver_key

IGNORE_FILENAME = ".gapscanignore"

_BASE = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 45,
    Severity.LOW: 20,
    Severity.INFO: 5,
}
_TEST_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|e2e|androidTest|testing|fixtures)/|"
    r"(_test\.(go|py)|\.(test|spec)\.[jt]sx?|Tests?\.(java|kt|swift)|_test\.dart)$",
)
_VENDOR_RE = re.compile(
    r"(^|/)(node_modules|vendor|third_party|Pods|Carthage|\.dart_tool|build|dist)/"
)
# Build and developer scripts, docs and samples: they run on a developer's machine or CI, not in
# the product. GitHub/GitLab workflow files are NOT here: injection in CI is a real attack path.
_TOOLING_RE = re.compile(
    r"(^|/)(tools|scripts|script|fastlane|buildSrc|build-logic|docs?|screenshots|samples?|examples?|"
    r"benchmarks?|\.husky)/|(^|/)(Fastfile|Dangerfile|Gemfile|Rakefile|Makefile|noxfile\.py|"
    r"setup\.py|conftest\.py|[^/]*\.gradle(\.kts)?)$"
)
_ROUTE_RE = re.compile(
    r"@(app|bp|router|blueprint)\.(route|get|post|put|delete|patch)|@(Get|Post|Put|Delete|Patch|Request)Mapping|"
    r"@(RestController|Controller)|\b(router|app)\.(get|post|put|delete|patch|use)\(|http\.HandleFunc|"
    r"\.(GET|POST|PUT|DELETE)\(|(^|/)(routes?|handlers?|controllers?|api|endpoints?)(/|\.)",
    re.IGNORECASE,
)


# --- ignore rules -----------------------------------------------------------------


def load_ignore_rules(target: Path) -> tuple[list[str], set[str]]:
    """Parse `.gapscanignore`: path globs and `rule:<id>` lines. `#` starts a comment."""
    path = target / IGNORE_FILENAME
    globs: list[str] = []
    rules: set[str] = set()
    if not path.is_file():
        return globs, rules
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("rule:"):
            rules.add(line[5:].strip())
        else:
            globs.append(line)
    return globs, rules


def _path_ignored(file: str | None, globs: list[str]) -> bool:
    if not file:
        return False
    for g in globs:
        g = g.lstrip("/")
        if g.endswith("/"):
            if file.startswith(g) or f"/{g}" in f"/{file}":
                return True
        elif fnmatch.fnmatch(file, g) or fnmatch.fnmatch(Path(file).name, g):
            return True
    return False


def apply_ignores(
    findings: list[Finding], globs: list[str], rules: set[str]
) -> tuple[list[Finding], int]:
    kept = [f for f in findings if f.rule_id not in rules and not _path_ignored(f.file, globs)]
    return kept, len(findings) - len(kept)


# Output of builds and package installs: copies of the project's own files or of third-party
# packages. Findings there repeat the real ones (a secret 3 times, once per build variant) or
# belong to dependencies, which the lockfile check covers.
_GENERATED_RE = re.compile(
    r"(^|/)(node_modules|bower_components|\.gradle|\.dart_tool|DerivedData|\.next|\.nuxt|"
    r"\.svelte-kit|__pycache__|\.tox|\.venv|venv|dist)/"
    r"|(^|/)build/(?:[^/]+/)*?(intermediates|generated|tmp|outputs|kotlin|reports|test-results|"
    r"classes|resources/main|kaptKotlin)/"
    r"|(^|/)target/(classes|test-classes|generated-sources|generated-test-sources)/"
    r"|(^|/)out/(production|test)/"
)
# Packaged into the APK/AAB: the merged assets of every variant, and BuildConfig constants
# (where secrets.properties values end up through buildConfigField), compiled into the app.
_APK_ASSETS_RE = re.compile(
    r"(^|/)build/intermediates/(?:merged_)?assets/[^/]+/(?:[^/]+/)?(.+)$"
    r"|(^|/)build/generated/source/buildConfig/.+/(BuildConfig\.(?:java|kt))$"
)


def drop_generated(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Remove findings in build and install output. One exception: a secret in Android's merged
    assets proves the file ships inside the app, so one finding per asset is kept and raised."""
    kept: list[Finding] = []
    shipped: dict[tuple[str, str], Finding] = {}
    for f in findings:
        path = f.file or ""
        asset = _APK_ASSETS_RE.search(path)
        if asset and f.category == Category.SECRET:
            key = (f.rule_id, asset.group(2) or asset.group(4))
            if key not in shipped:
                f.raw["shipped_in_app"] = True
                f.severity = Severity.CRITICAL
                f.title = f"{f.title} (packaged inside the app: anyone with the APK can extract it)"
                shipped[key] = f
                kept.append(f)
            continue
        if not _GENERATED_RE.search(path):
            kept.append(f)
    return kept, len(findings) - len(kept)


# --- deduplication ----------------------------------------------------------------


def _overlap(a: Finding, b: Finding) -> bool:
    if a.start_line is None or b.start_line is None:
        return a.start_line is None and b.start_line is None
    return a.start_line <= (b.end_line or b.start_line) and b.start_line <= (
        a.end_line or a.start_line
    )


def _same_issue(a: Finding, b: Finding) -> bool:
    if a.category != b.category:
        return False
    if a.category == Category.DEPENDENCY:
        return (
            a.package == b.package
            and a.version == b.version
            and bool(set(a.cve) & set(b.cve) or a.rule_id == b.rule_id)
        )
    if a.file != b.file or not _overlap(a, b):
        return False
    if a.scanner == b.scanner or set(a.sources) & set(b.sources):
        return a.rule_id == b.rule_id  # exact duplicate from one tool
    # Different tools: the same CWE at the same place is the same issue.
    return bool(set(a.cwe) & set(b.cwe)) or (a.category == Category.SECRET)


def _merge(into: Finding, other: Finding) -> None:
    if other.severity.rank > into.severity.rank:
        into.severity = other.severity
    for s in other.sources:
        if s not in into.sources:
            into.sources.append(s)
    into.cwe = sorted({*into.cwe, *other.cwe}, key=lambda c: int(c.split("-")[1]))
    into.cve = sorted({*into.cve, *other.cve})
    into.fixed_version = into.fixed_version or other.fixed_version
    into.snippet = into.snippet or other.snippet
    if other.start_line is not None and into.start_line is not None:
        into.start_line = min(into.start_line, other.start_line)
        into.end_line = max(into.end_line or into.start_line, other.end_line or other.start_line)
    for key in ("taint_path", "source", "cross_file", "symbols"):  # evidence the merge must keep
        if key in other.raw and key not in into.raw:
            into.raw[key] = other.raw[key]
    into.raw.setdefault("merged", []).append({"scanner": other.scanner, "rule_id": other.rule_id})


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge findings describing the same issue; keep every reporting scanner in `sources`."""
    out: list[Finding] = []
    buckets: dict[tuple[str, str | None, str | None], list[Finding]] = defaultdict(list)
    for f in findings:
        key = (f.category.value, f.package or f.file, f.version)
        match = next((m for m in buckets[key] if _same_issue(m, f)), None)
        if match is None:
            copy = f.model_copy(deep=True)
            buckets[key].append(copy)
            out.append(copy)
        else:
            _merge(match, f)
    return out


# --- dependency grouping ----------------------------------------------------------


def group_dependencies(findings: list[Finding]) -> list[PackageGroup]:
    by_pkg: dict[tuple[str, str | None], list[Finding]] = defaultdict(list)
    for f in findings:
        if f.category == Category.DEPENDENCY and f.package:
            by_pkg[(f.package, f.version)].append(f)
    groups = []
    for (pkg, ver), fs in by_pkg.items():
        fixes = [f.fixed_version for f in fs if f.fixed_version]
        epss = [f.epss for f in fs if f.epss is not None]
        groups.append(
            PackageGroup(
                package=pkg,
                version=ver,
                ecosystem=fs[0].raw.get("ecosystem"),
                finding_ids=[f.id for f in fs],
                cves=sorted({c for f in fs for c in f.cve}),
                max_severity=max((f.severity for f in fs), key=lambda s: s.rank),
                # Only a single version fixes everything if every finding has a known fix.
                fixed_version=max(fixes, key=ver_key) if len(fixes) == len(fs) else None,
                kev=any(f.kev for f in fs),
                max_epss=max(epss) if epss else None,
                priority=max(f.priority for f in fs),
            )
        )
    return sorted(groups, key=lambda g: -g.priority)


# --- context heuristics, enrichment, scoring --------------------------------------


def classify_asset(f: Finding) -> None:
    """Which first-class view a finding belongs to: code, dependency, secret, iac or image."""
    if f.raw.get("asset"):
        f.asset = str(f.raw["asset"])
    else:
        f.asset = {
            Category.CODE: "code",
            Category.DEPENDENCY: "dependency",
            Category.SECRET: "secret",
            Category.CONFIG: "iac",
        }[f.category]


def classify_context(f: Finding) -> None:
    classify_asset(f)
    path = f.file or ""
    f.is_vendor_code = bool(_VENDOR_RE.search(path))
    f.is_test_code = bool(_TEST_RE.search(path))
    f.is_tooling_code = not f.is_test_code and bool(_TOOLING_RE.search(path))
    f.internet_facing = bool(_ROUTE_RE.search(f"{path}\n{f.snippet or ''}"))


# Weaknesses the data-flow engine models: a pattern-rule finding of one of these classes in a
# language it analyzes is "confirmed" when the engine also reaches it, "not_confirmed" otherwise.
DATAFLOW_CWES = frozenset({
    "CWE-89", "CWE-78", "CWE-77", "CWE-22", "CWE-23", "CWE-79", "CWE-918", "CWE-601", "CWE-90",
    "CWE-643", "CWE-502", "CWE-94", "CWE-95", "CWE-501", "CWE-943",
})  # fmt: skip
DATAFLOW_LANGS = (".java", ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")


def mark_dataflow(findings: list[Finding], taint_ran: bool) -> None:
    """Record whether the inter-procedural engine agrees with each injection-class finding."""
    for f in findings:
        if f.category != Category.CODE or not set(f.cwe) & DATAFLOW_CWES:
            continue
        if "taint" in f.sources:
            f.raw["dataflow"] = "confirmed"
        elif taint_ran and (f.file or "").endswith(DATAFLOW_LANGS):
            f.raw["dataflow"] = "not_confirmed"


def score(f: Finding) -> float:
    if f.kev:
        return 100.0
    s = float(_BASE[f.severity])
    if f.raw.get("dataflow") == "confirmed":
        s += 5
    elif f.raw.get("dataflow") == "not_confirmed":
        s *= 0.6  # pattern only: no data path from untrusted input was found
    if f.category == Category.SECRET:
        s += 10
    elif f.category == Category.CONFIG:
        s -= 5
    if f.internet_facing:
        s += 10
    if f.category == Category.DEPENDENCY and f.epss is not None:
        s += 20 * f.epss
    if f.reachability == "reachable":
        s += 5
    elif f.reachability == "not_reachable":
        s *= 0.5
    elif f.reachability == "not_imported":
        s *= 0.6
    if f.raw.get("suppressed_in_code"):
        s *= 0.7  # the project marked it as accepted in its own code: kept visible, ranked lower
    if f.is_vendor_code:
        s *= 0.2
    elif f.is_test_code:
        s *= 0.4
    elif f.is_tooling_code and f.category == Category.CODE:
        s *= 0.5
    return round(max(0.0, min(100.0, s)), 1)


def apply_llm_cap(findings: list[Finding], max_llm_findings: int) -> None:
    """Flag everything beyond the top-N by priority as not sent to the LLM."""
    ranked = sorted(findings, key=lambda f: -f.priority)
    for i, f in enumerate(ranked):
        f.llm_triage = i < max_llm_findings


# --- pipeline ---------------------------------------------------------------------


def normalize(
    result: ScanResult,
    target: Path,
    annotators: Sequence[Annotator] | None = None,
    max_llm_findings: int = 200,
    target_packs: Sequence[TargetPack] | None = None,
) -> ScanResult:
    """Return a new ScanResult with ignore rules, dedupe, controls, the packs' annotations, scores
    and groups applied. Controls come from `target_packs` and annotations from `annotators`, by
    default the default packs' registered ones (annotators that need no config).

    `evidence` annotators run before findings are merged (they may merge or drop some themselves),
    `context` annotators after the stable IDs, before scoring."""
    reg = registry()
    annotators = reg.annotators_for(None) if annotators is None else annotators
    globs, rules = load_ignore_rules(target)
    findings, ignored = apply_ignores(result.findings, globs, rules)
    findings, generated = drop_generated(findings)
    ignored += generated
    for a in annotators:
        if a.stage == "evidence":
            findings = a.annotate(findings, target)
    findings = deduplicate(findings)
    map_controls(findings, reg.target_packs if target_packs is None else target_packs)
    assign_stable_ids(findings, target)
    mark_dataflow(findings, any(r.scanner == "taint" and r.status == "ok" for r in result.runs))
    for a in annotators:
        if a.stage == "context":
            findings = a.annotate(findings, target)
    for f in findings:
        classify_context(f)
        f.priority = score(f)
    apply_llm_cap(findings, max_llm_findings)
    findings.sort(key=lambda f: (-f.priority, f.file or "", f.start_line or 0, f.id))
    return result.model_copy(
        update={
            "findings": findings,
            "package_groups": group_dependencies(findings),
            "ignored_count": result.ignored_count + ignored,
            "vuln_data": {k: v for a in annotators for k, v in a.data_dates().items()},
        }
    )
