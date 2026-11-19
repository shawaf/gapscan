"""Zero-day watch: re-check a saved scan's dependencies against newer vulnerability data.

When `gapscan data update` (or a new offline bundle) brings fresh OSV, KEV and EPSS data, a project
does not need a full rescan to learn that one of its dependencies was just disclosed as vulnerable.
The scan already saved the project's dependency list as a CycloneDX SBOM. This module hands that
SBOM to osv-scanner (offline, against the local database) and reports every advisory the saved scan
did not know about, ranked so the dangerous ones come first:

1. listed by CISA as exploited in the wild (KEV),
2. reachable: the project's code calls the vulnerable function (needs the project folder; the code
   is only read, never run),
3. the FIRST EPSS exploit-probability score,
4. severity.

Nothing here touches the network (hard rule 2) and nothing executes the project (hard rule 1).
GapScan cannot see a vulnerability nobody has disclosed yet in someone else's package: what this
closes is the time between disclosure and the moment you know which of your projects is affected.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .enrich import Enrichment
from .models import Category, Finding, ScanResult, Severity
from .reachability import annotate as annotate_reachability
from .scanners.osv import OSVScanner

log = logging.getLogger(__name__)

# osv-scanner reads a CycloneDX SBOM passed with -L when the file name ends in `.cdx.json`.
SBOM_NAME = "gapscan-watch.cdx.json"

# Package URL type -> OSV ecosystem (the folder name of its offline database).
PURL_ECOSYSTEMS = {
    "pypi": "PyPI", "npm": "npm", "golang": "Go", "maven": "Maven", "gem": "RubyGems",
    "cargo": "crates.io", "composer": "Packagist", "nuget": "NuGet", "pub": "Pub", "hex": "Hex",
    "swift": "SwiftURL",
}  # fmt: skip

REACHABILITY_WEIGHT = {
    "reachable": 300, "imported": 100, "transitive": 0, "not_imported": -100, "not_reachable": -200,
}  # fmt: skip


class WatchAlert(BaseModel):
    """One advisory the saved scan did not know about, for one dependency of one project."""

    project: str
    advisory: str
    cve: list[str] = Field(default_factory=list)
    package: str
    ecosystem: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    severity: Severity
    summary: str = ""
    kev: bool = False
    epss: float | None = None
    reachability: str | None = None
    reachability_evidence: list[str] = Field(default_factory=list)
    declared_in: str | None = None  # the manifest or lockfile that brings the package in, if known
    priority: int = 0  # computed by `priority()`, higher first


class WatchReport(BaseModel):
    """The result of re-checking one project."""

    project: str
    checked_at: str
    scan_created_at: str = ""
    components: int = 0  # dependencies in the saved SBOM that were checked
    known: int = 0  # advisories the saved scan already reported
    alerts: list[WatchAlert] = Field(default_factory=list)
    skipped_ecosystems: list[str] = Field(default_factory=list)
    vuln_data: dict[str, str] = Field(default_factory=dict)
    note: str = ""


def priority(a: WatchAlert) -> int:
    """KEV first, then reachability, then EPSS, then severity. Computed here, never by a model."""
    score = 1000 if a.kev else 0
    score += REACHABILITY_WEIGHT.get(a.reachability or "", 0)
    score += round((a.epss or 0.0) * 100)
    return score + a.severity.rank * 20


def purl_ecosystem(purl: str) -> str | None:
    if not purl.startswith("pkg:"):
        return None
    kind = purl[4:].split("/", 1)[0].lower()
    return PURL_ECOSYSTEMS.get(kind)


def sbom_components(scan: ScanResult) -> list[dict[str, Any]]:
    """The SBOM's components that carry a package URL (the only ones osv-scanner can look up)."""
    comps = (scan.sbom or {}).get("components") or []
    return [c for c in comps if isinstance(c, dict) and str(c.get("purl", "")).startswith("pkg:")]


def write_watch_sbom(components: list[dict[str, Any]], workdir: Path) -> Path:
    """A minimal CycloneDX document with just the components to check."""
    workdir.mkdir(parents=True, exist_ok=True)
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {k: c[k] for k in ("bom-ref", "type", "group", "name", "version", "purl") if k in c}
            for c in components
        ],
    }
    path = workdir / SBOM_NAME
    path.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    return path


def _known(scan: ScanResult) -> tuple[set[tuple[str, str]], int]:
    """(package, advisory or CVE id) pairs the saved scan already reported."""
    keys: set[tuple[str, str]] = set()
    advisories: set[tuple[str, str]] = set()
    for f in scan.findings:
        if f.category != Category.DEPENDENCY or not f.package:
            continue
        advisories.add((f.package, f.rule_id))
        keys.add((f.package, f.rule_id))
        keys.update((f.package, c) for c in f.cve)
    return keys, len(advisories)


def _declared_in(scan: ScanResult, components: list[dict[str, Any]]) -> dict[str, str]:
    """package -> the file the saved scan saw it in (its own dependency findings, or the SBOM's
    `gapscan:declared_in` property for libraries declared in Gradle build files)."""
    where: dict[str, str] = {}
    for c in components:
        for prop in c.get("properties") or []:
            if prop.get("name") == "gapscan:declared_in" and c.get("name"):
                where[str(c["name"])] = str(prop.get("value"))
    for f in scan.findings:
        if f.category == Category.DEPENDENCY and f.package and f.file:
            where.setdefault(f.package, f.file)
    return where


def to_alert(project: str, f: Finding, declared: dict[str, str]) -> WatchAlert:
    alert = WatchAlert(
        project=project,
        advisory=f.rule_id,
        cve=list(f.cve),
        package=f.package or "",
        ecosystem=str(f.raw.get("ecosystem") or "") or None,
        version=f.version,
        fixed_version=f.fixed_version,
        severity=f.severity,
        summary=f.title,
        kev=f.kev,
        epss=f.epss,
        reachability=f.reachability,
        reachability_evidence=list(f.reachability_evidence),
        declared_in=declared.get(f.package or ""),
    )
    alert.priority = priority(alert)
    return alert


def watch_scan(
    scan: ScanResult,
    project: str,
    scanner: OSVScanner,
    workdir: Path,
    *,
    enrichment: Enrichment | None = None,
    target: Path | None = None,
    now: datetime | None = None,
) -> WatchReport:
    """Re-check one saved scan's dependency list. `target` (the project folder) is optional and
    only read, to tell whether the project calls the vulnerable code."""
    report = WatchReport(
        project=project,
        checked_at=(now or datetime.now(UTC)).isoformat(timespec="seconds"),
        scan_created_at=scan.created_at,
        vuln_data=dict(enrichment.dates) if enrichment else {},
    )
    components = sbom_components(scan)
    if not components:
        report.note = (
            "The saved scan has no dependency list (SBOM). Scan the project once more with Trivy "
            "installed, then the watch can re-check it."
        )
        return report
    installed = scanner.installed_ecosystems()
    usable = [c for c in components if purl_ecosystem(str(c["purl"])) in installed]
    report.skipped_ecosystems = sorted(
        {e for c in components if (e := purl_ecosystem(str(c["purl"]))) and e not in installed}
    )
    report.components = len(usable)
    if not usable:
        report.note = "No offline vulnerability database is installed for this project's packages."
        return report
    sbom = write_watch_sbom(usable, workdir)
    findings = scanner.scan_files([sbom], workdir, workdir)
    known, report.known = _known(scan)
    fresh = [
        f
        for f in findings
        if f.package
        and (f.package, f.rule_id) not in known
        and not any((f.package, c) in known for c in f.cve)
    ]
    if enrichment:
        for f in fresh:
            if f.cve:
                f.kev, f.epss = enrichment.for_cves(f.cve)
    for f in fresh:  # the SBOM is not where the project declares the package
        f.file = None
    if target is not None and target.is_dir() and fresh:
        try:
            annotate_reachability(fresh, target)
        except Exception:  # noqa: BLE001 - reachability must never fail the watch
            log.warning("reachability check failed for %s", project)
    declared = _declared_in(scan, components)
    alerts = [to_alert(project, f, declared) for f in fresh]
    report.alerts = sorted(alerts, key=lambda a: (-a.priority, a.package, a.advisory))
    return report


def alert_line(a: WatchAlert) -> str:
    """One plain sentence for a notification or a terminal line."""
    ids = ", ".join(a.cve[:2]) or a.advisory
    parts = [f"{a.package} {a.version or ''}".strip() + f" in {a.project}: {ids}"]
    if a.kev:
        parts.append("exploited in the wild (CISA KEV)")
    if a.reachability == "reachable" and a.reachability_evidence:
        parts.append(a.reachability_evidence[0])
    elif a.reachability == "not_reachable":
        parts.append("the vulnerable function is not called")
    if a.fixed_version:
        parts.append(f"fixed in {a.fixed_version}")
    return "; ".join(parts)
