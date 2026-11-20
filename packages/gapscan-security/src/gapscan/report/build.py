"""Assemble `ReportData` from a scan, its verdicts and summary. Pure Python: every number,
score, status and ranking is computed here and only rendered by the dashboard."""

from __future__ import annotations

import contextlib
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from pathlib import Path

from ..compare import diff_open
from ..config import Config
from ..context.extract import build_context
from ..core.version import __version__
from ..kb import KnowledgeBase
from ..models import (
    Finding,
    Investigation,
    RepoSummary,
    ScanResult,
    Severity,
    Verdict,
    VerdictLabel,
)
from ..owasp.classify import load_tables
from ..owasp.packs import ASVS, TOP10
from ..redact import mask
from ..registry import registry_for
from .assets import images, infrastructure
from .asvs import build_coverage
from .coverage import coverage_by_target
from .decisions import Decisions
from .hotspots import build_hotspots, measure
from .owasp_info import category_names, cheatsheet_links
from .risk import compute_score, finding_points
from .sbom import sbom_rows
from .schema import (
    Baseline,
    Counts,
    DeepDive,
    Dependencies,
    FindingDetail,
    FindingRow,
    Freshness,
    Meta,
    Narrative,
    OwaspCategory,
    PackageRow,
    ReportData,
    ScannerInfo,
    ScanStats,
    TopRisk,
    UpgradeStep,
)

SEVERITIES = [
    s.value
    for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
]
LANG_FOR_HIGHLIGHT = {"tsx": "typescript"}
LIMITATIONS = [
    "Static analysis and a local language model cannot see business logic, authorization design, "
    "runtime behavior, deployment configuration or anything that happens outside the scanned files.",
    "A finding the model judged a false positive was dismissed from the score but is still listed; "
    "review dismissals before relying on them.",
    "Dependency findings show what is installed and vulnerable. Whether the vulnerable code is "
    "reachable is only an estimate (is the package imported at all?) and never clears a finding.",
    "ASVS 'no issue found by tools' is not a pass: it only means a scanner rule exists and found nothing.",
    "Model-written text (reasoning, summary, fix suggestions) can be wrong; it is labeled and always "
    "shown next to the scanner evidence it is based on.",
]


class PreviousRun:
    """What a baseline comparison needs from an earlier run: its findings and, when known, its score."""

    def __init__(
        self, items: dict[str, tuple[str, str]], created_at: str = "", score: float | None = None
    ) -> None:
        self.items = items  # finding id -> (title, location)
        self.created_at = created_at
        self.score = score


def load_previous(path: Path) -> PreviousRun:
    """A previous scan (`gapscan scan` JSON) or a previous report (`gapscan report --json` /
    the dashboard's Export JSON); the report form also carries the earlier risk score."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if "meta" in raw and "score" in raw:
        data = ReportData.model_validate(raw)
        items = {
            r.id: (r.title, f"{r.file}:{r.start_line}" if r.file else (r.package or "-"))
            for r in data.findings
            if r.open
        }
        return PreviousRun(items, data.meta.scan_created_at, data.score.value)
    scan = ScanResult.model_validate(raw)
    return PreviousRun(
        {f.id: (mask(f.title), _location(f)) for f in scan.findings}, scan.created_at
    )


def _verdict_label(v: Verdict | None) -> str:
    if v is None:
        return "not_triaged"
    return "triage_failed" if v.triage_failed else v.verdict.value


def _location(f: Finding) -> str:
    if f.file:
        return f"{f.file}:{f.start_line}" if f.start_line else f.file
    return f"{f.package} {f.version or ''}".strip() if f.package else "-"


def _first_sentence(text: str, limit: int = 220) -> str:
    text = " ".join(text.split())
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    return (m.group(1) if m else text)[:limit]


def _read_date(path: Path, key: str | None = None) -> str:
    try:
        raw = path.read_text(encoding="utf-8").strip()
        if key:
            raw = str(json.loads(raw).get(key, ""))
        return raw[:10]
    except (OSError, ValueError):
        return ""


def _freshness(
    config: Config, result: ScanResult, verdicts: list[Verdict], kb: KnowledgeBase | None
) -> Freshness:
    dates = dict(result.vuln_data)
    for name, path, key in [("osv_db", config.scanners.osv.db_dir / "SNAPSHOT_DATE", None),
                            ("trivy_db", config.scanners.trivy.cache_dir / "db" / "metadata.json", "UpdatedAt")]:  # fmt: skip
        if d := _read_date(path, key):
            dates[name] = d
    parsed = []
    for d in dates.values():
        try:
            parsed.append(date.fromisoformat(d))
        except ValueError:
            continue
    age = (datetime.now(UTC).date() - min(parsed)).days if parsed else None
    versions = {}
    try:
        meta = json.loads(
            (
                Path(__file__).resolve().parent.parent / "owasp" / "mappings" / "versions.json"
            ).read_text()
        )
        versions = {"OWASP Top 10": meta["top10"]["edition"], "OWASP ASVS": meta["asvs"]["version"]}
    except (OSError, KeyError, ValueError):
        pass
    emb = ""
    if kb is not None:
        sources = kb.index.meta.get("sources") or {}
        cwe_chunks = kb.index.get_doc("cwe", "CWE-89")  # any entry carries the catalog version
        if cwe_chunks:
            versions["MITRE CWE"] = cwe_chunks[0].version.removeprefix("CWE ")
        elif isinstance(sources, dict) and sources.get("mitre-cwe"):
            versions["MITRE CWE"] = str(sources["mitre-cwe"])
        emb = str(kb.index.meta.get("embedding_model") or "")
    bundle_built = ""
    with contextlib.suppress(OSError, ValueError):
        state = json.loads((config.data.dir / "bundle-state.json").read_text(encoding="utf-8"))
        bundle_built = str(state.get("bundle_created_at", ""))[:10]
        for key, value in (state.get("snapshots") or {}).items():
            dates.setdefault(
                key, str(value)
            )  # bundle snapshot dates fill in what the scan itself did not record
    return Freshness(
        bundle=bundle_built,
        vuln_data=dates, vuln_data_age_days=age,
        stale=age is not None and age > config.general.vuln_data_max_age_days,
        owasp=versions, model=next((v.model for v in verdicts if v.model), ""),  # only a model that ran
        prompt_versions=sorted({v.prompt_version for v in verdicts if v.prompt_version}),
        embedding_model=emb,
    )  # fmt: skip


def _detail(
    f: Finding, v: Verdict | None, target: Path | None, cwe_names: dict[str, str], budget: int
) -> FindingDetail:
    d = FindingDetail(cwe_names={c: cwe_names[c] for c in f.cwe if c in cwe_names})
    msgs = [
        {"scanner": ", ".join(f.sources), "rule": f.rule_id, "message": mask(f.message or f.title)}
    ]
    msgs += [
        {"scanner": m.get("scanner", ""), "rule": m.get("rule_id", ""), "message": ""}
        for m in f.raw.get("merged", [])
    ]
    d.scanner_messages = msgs
    if target is not None and f.file and f.start_line:
        ctx = build_context(f, target, budget_tokens=budget, max_callers=3)
        d.language = LANG_FOR_HIGHLIGHT.get(ctx.language or "", ctx.language)
        d.function = ctx.function_name
        d.callers = [c.model_dump() for c in ctx.callers]
        d.untrusted_sources = [u.model_dump() for u in ctx.untrusted_sources]
        for line in ctx.code.splitlines():
            m = re.match(r"^(>>|  )\s*(\d+) \| ?(.*)$", line)
            if m:
                d.code.append((int(m.group(2)), m.group(3), m.group(1) == ">>"))
            elif line.strip() == "...":
                d.code.append((0, "…", False))
    if v is not None and not v.triage_failed:
        d.reasoning, d.exploit_scenario = v.reasoning, v.exploit_scenario
        d.fix_suggestion, d.references = v.fix_suggestion, list(v.references)
        d.tool_calls = [t.model_dump() for t in v.tool_calls]
        d.evidence_refs, d.policy_notes = list(v.evidence_refs), list(v.policy_notes)
        d.memory_notes = list(v.memory_notes)
        d.model, d.prompt_version = v.model, v.prompt_version
    return d


def _deep_dive(inv: Investigation) -> DeepDive:
    """Report view of an investigation. Model text is masked again in case a secret slipped
    into prose (hard rule #4)."""
    d = DeepDive(failed=inv.failed or inv.answer is None, error=inv.error,
                 covers=len(inv.covers) or 1,
                 dropped=len(inv.dropped), tool_calls=len(inv.tool_calls), model=inv.model,
                 prompt_version=inv.prompt_version)  # fmt: skip
    a = inv.answer
    if a is None:
        return d
    d.summary, d.protection, d.target_state = (
        mask(a.summary),
        a.protection.value,
        mask(a.target_state),
    )
    d.evidence = [e.model_copy(update={"claim": mask(e.claim)}) for e in a.evidence]
    d.scope = [s.model_copy(update={"where": mask(s.where)}) for s in a.scope]
    d.related = [r.model_copy(update={"note": mask(r.note)}) for r in a.related]
    d.remediation = [mask(x) for x in a.remediation]
    d.verification = [mask(x) for x in a.verification]
    return d


def build_report(
    result: ScanResult,
    verdicts: list[Verdict] | None = None,
    summary: RepoSummary | None = None,
    *,
    config: Config,
    target: Path | None = None,
    baseline: PreviousRun | None = None,
    decisions: Decisions | None = None,
    project: str | None = None,
    kb: KnowledgeBase | None = None,
    max_details: int = 2000,
    investigations: list[Investigation] | None = None,
) -> ReportData:
    verdicts = verdicts or []
    imap = {fid_: i for i in investigations or [] for fid_ in (i.covers or [i.finding_id])}
    vmap = {v.finding_id: v for v in verdicts}
    dec = (decisions or Decisions()).by_id()
    findings = result.findings
    fid = {f.id for f in findings}

    def dismissed(f: Finding) -> bool:
        v = vmap.get(f.id)
        by_model = (
            v is not None and not v.triage_failed and v.verdict == VerdictLabel.FALSE_POSITIVE
        )
        return by_model or f.id in dec

    dismissed_ids = {f.id for f in findings if dismissed(f)}
    score = compute_score(findings, vmap, dismissed_ids)
    points = {f.id: finding_points(f, vmap.get(f.id), f.id in dismissed_ids) for f in findings}

    base_ids = set(baseline.items) if baseline else set()
    rows: list[FindingRow] = []
    for f in findings:
        v = vmap.get(f.id)
        ok = v is not None and not v.triage_failed
        rows.append(FindingRow(
            id=f.id, title=mask(f.title), rule_id=f.rule_id, severity=f.severity.value,
            severity_adjusted=(v.severity_adjusted.value if ok and v and v.severity_adjusted else None),
            category=f.category.value, priority=f.priority, risk_points=round(points[f.id], 2),
            verdict=_verdict_label(v),
            confidence=(v.confidence if ok and v else None), file=f.file, start_line=f.start_line,
            end_line=f.end_line, cwe=f.cwe, owasp=f.control_ids(TOP10), asvs=f.control_ids(ASVS), scanners=f.sources,
            package=f.package, version=f.version, fixed_version=f.fixed_version, cve=f.cve, kev=f.kev,
            epss=f.epss, internet_facing=f.internet_facing, is_test_code=f.is_test_code,
            is_tooling_code=f.is_tooling_code,
            llm_only=bool(v and v.llm_only),
            decision=(dec[f.id].decision if f.id in dec else None),
            status=(("unchanged" if f.id in base_ids else "new") if baseline else None),
            open=f.id not in dismissed_ids, asset=f.asset or _asset_of(f),
        ))  # fmt: skip
    rows.sort(key=lambda r: (-points[r.id], -r.priority, r.id))

    open_rows = [r for r in rows if r.open]
    counts = Counts(
        total=len(rows), open=len(open_rows), dismissed=len(rows) - len(open_rows),
        by_severity={s: sum(1 for r in open_rows if (r.severity_adjusted or r.severity) == s) for s in SEVERITIES},
        by_verdict=dict(Counter(r.verdict for r in rows)),
        by_category=dict(Counter(r.category for r in open_rows)),
        by_scanner=dict(Counter(s for r in open_rows for s in r.scanners)),
        llm_triaged=sum(1 for v in verdicts if not v.triage_failed and v.finding_id in fid),
        not_triaged=sum(1 for r in rows if r.verdict in ("not_triaged", "triage_failed")),
    )  # fmt: skip

    narrative = None
    why_by_id: dict[str, str] = {}
    if summary is not None and summary.narrative is not None:
        n = summary.narrative
        narrative = Narrative(headline=n.headline, themes=n.themes, recommended_priorities=n.recommended_priorities,
                              top_risks=[risk.model_dump() for risk in n.top_risks])  # fmt: skip
        for risk in n.top_risks:
            for i in risk.finding_ids:
                why_by_id.setdefault(i, risk.why)
    elif summary is not None and summary.failed:
        narrative = Narrative(failed=True)
    by_id = {f.id: f for f in findings}
    top = []
    for r in open_rows[:10]:
        f = by_id[r.id]
        v = vmap.get(r.id)
        why = why_by_id.get(r.id) or (_first_sentence(v.reasoning) if v and not v.triage_failed and v.reasoning
                                      else _first_sentence(mask(f.message or f.title)))  # fmt: skip
        top.append(TopRisk(finding_id=r.id, title=r.title, location=_location(f), severity=r.severity_adjusted or r.severity,
                           priority=r.priority, verdict=r.verdict, why=why))  # fmt: skip

    tables = load_tables()
    names = category_names()
    owasp: list[OwaspCategory] = []
    for cid, cname in names.items():
        members = [r for r in open_rows if cid in r.owasp]
        desc = ""
        if kb is not None and (chunks := kb.index.get_doc("top10-2025", cid)):
            desc = _first_sentence(chunks[0].text, 360)
        owasp.append(OwaspCategory(
            id=cid, name=cname, description=desc,
            by_severity={s: sum(1 for r in members if (r.severity_adjusted or r.severity) == s) for s in SEVERITIES},
            finding_ids=[r.id for r in members], cheatsheets=cheatsheet_links(cid)))  # fmt: skip

    stats = ScanStats()
    sizes: dict[str, tuple[int, str]] = {}
    if target is not None:
        stats, sizes = measure(target)
    stats.duration_s = round(sum(r.duration_s for r in result.runs), 1)

    details: dict[str, FindingDetail] = {}
    for r in rows[:max_details]:
        details[r.id] = _detail(
            by_id[r.id], vmap.get(r.id), target, tables.cwe_names, config.llm.code_context_tokens
        )
    for fid_, inv in imap.items():
        if fid_ in details:
            details[fid_].deep_dive = _deep_dive(inv)

    asvs_map: dict[str, list[str]] = defaultdict(list)
    for r in open_rows:
        for a in r.asvs:
            asvs_map[a].append(r.id)

    risk_by_file: dict[str, float] = defaultdict(float)
    count_by_file: dict[str, int] = defaultdict(int)
    sev_by_file: dict[str, str] = {}
    for r in open_rows:
        if r.file:
            risk_by_file[r.file] += points[r.id]
            count_by_file[r.file] += 1
            cur = r.severity_adjusted or r.severity
            if r.file not in sev_by_file or SEVERITIES.index(cur) < SEVERITIES.index(
                sev_by_file[r.file]
            ):
                sev_by_file[r.file] = cur

    deps = _dependencies(result, rows, vmap, points, by_id)

    base = None
    if baseline is not None:
        d = diff_open(baseline.items, (r.id for r in open_rows))
        base = Baseline(
            previous_created_at=baseline.created_at, previous_score=baseline.score,
            new=len(d.new), fixed=len(d.fixed), unchanged=len(d.unchanged),
            fixed_titles=[{"id": i, "title": baseline.items[i][0], "location": baseline.items[i][1]} for i in d.fixed[:50]],
        )  # fmt: skip

    return ReportData(
        meta=Meta(project=project or (target.name if target else Path(result.target).name),
                  generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), gapscan_version=__version__,
                  scan_schema_version=result.schema_version, scan_created_at=result.created_at,
                  asvs_level=config.general.asvs_level),
        scanners=[ScannerInfo(name=r.scanner, version=r.version, status=r.status, findings=r.finding_count,
                              seconds=r.duration_s, error=r.error, note=r.note) for r in result.runs],
        freshness=_freshness(config, result, verdicts, kb), stats=stats, score=score, counts=counts,
        top_risks=top, narrative=narrative, owasp=owasp, findings=rows, details=details,
        asvs=build_coverage(config.general.asvs_level, dict(asvs_map)), dependencies=deps,
        coverage=coverage_by_target(
            registry_for(config).target_packs,
            ((r.id, [(c.target, c.control_id) for c in by_id[r.id].controls]) for r in open_rows),
            config.general.asvs_level,
        ),
        hotspots=build_hotspots(sizes, dict(risk_by_file), dict(count_by_file), sev_by_file),
        baseline=base, limitations=list(LIMITATIONS),
        infrastructure=infrastructure(rows), images=images(rows),
    )  # fmt: skip


def _asset_of(f: Finding) -> str:
    """Scans saved before `asset` existed: derive it the way normalize does."""
    from ..normalize import classify_asset

    g = f.model_copy()
    classify_asset(g)
    return g.asset


def _dependencies(result: ScanResult, rows: list[FindingRow], vmap: dict[str, Verdict],
                  points: dict[str, float], by_id: dict[str, Finding]) -> Dependencies:  # fmt: skip
    open_ids = {r.id for r in rows if r.open}
    packages: list[PackageRow] = []
    plan: list[UpgradeStep] = []
    for g in result.package_groups:
        ids = [i for i in g.finding_ids if i in open_ids]
        if not ids:
            continue
        outcomes = {
            c.outcome
            for i in ids
            if (v := vmap.get(i))
            for c in v.tool_calls
            if c.tool == "find_imports"
        }
        reach = (
            "imported"
            if "imports_found" in outcomes
            else ("not_imported_directly" if "no_imports" in outcomes else "unknown")
        )
        verdicts = [vmap[i].verdict for i in ids if i in vmap and not vmap[i].triage_failed]
        best = max(verdicts, key=lambda x: list(VerdictLabel).index(x) * -1) if verdicts else None
        packages.append(PackageRow(
            package=g.package, version=g.version, ecosystem=g.ecosystem, cves=g.cves,
            max_severity=g.max_severity.value, kev=g.kev, epss=g.max_epss, fixed_version=g.fixed_version,
            finding_ids=ids, priority=g.priority, reachability=reach,
            verdict=best.value if best else "not_triaged"))  # fmt: skip
        if g.fixed_version:
            plan.append(UpgradeStep(package=g.package, from_version=g.version, to_version=g.fixed_version,
                                    resolves=len(ids), kev=g.kev, risk_points=round(sum(points[i] for i in ids), 2)))  # fmt: skip
    plan.sort(key=lambda s: (-s.kev, -s.risk_points, s.package))
    packages.sort(key=lambda p: (-p.kev, -p.priority, p.package))
    vulnerable = {(p.package, p.version or "") for p in packages}
    sbom = sbom_rows(result.sbom, vulnerable)
    return Dependencies(
        packages=packages, upgrade_plan=plan, sbom=sbom, sbom_available=bool(result.sbom)
    )
