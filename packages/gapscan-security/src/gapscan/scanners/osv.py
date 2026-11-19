"""OSV-Scanner adapter, fully offline against a local database."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from ..manifests import SKIP_DIRS, Dep, declared_dependencies
from ..models import Category, Finding, Severity
from .base import CommandScanner, ScannerError, pick_fix, relpath

OSV_LAYOUT = "osv-scalibr"  # where osv-scanner 2.x keeps its offline databases
# Lockfiles and manifests osv-scanner reads, by OSV ecosystem (exact names, then patterns).
LOCKFILES: dict[str, str] = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm", "bun.lock": "npm",
    "poetry.lock": "PyPI", "pipfile.lock": "PyPI", "pdm.lock": "PyPI", "uv.lock": "PyPI",
    "go.mod": "Go", "pom.xml": "Maven", "gradle.lockfile": "Maven",
    "buildscript-gradle.lockfile": "Maven", "verification-metadata.xml": "Maven",
    "gemfile.lock": "RubyGems", "gems.locked": "RubyGems", "cargo.lock": "crates.io",
    "composer.lock": "Packagist", "packages.lock.json": "NuGet", "pubspec.lock": "Pub",
    "package.resolved": "SwiftURL", "mix.lock": "Hex",
}  # fmt: skip
_REQUIREMENTS = re.compile(r"requirements[\w.-]*\.txt")


def find_lockfiles(target: Path) -> list[tuple[Path, str]]:
    """(path, ecosystem) of every lockfile osv-scanner understands, outside build/vendor folders."""
    out: list[tuple[Path, str]] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            low = name.lower()
            eco = LOCKFILES.get(low) or ("PyPI" if _REQUIREMENTS.fullmatch(low) else None)
            if eco:
                out.append((Path(root) / name, eco))
    return out


def gradle_lockfile(deps: list[Dep]) -> str:
    """Gradle projects rarely commit a lockfile: write the declared coordinates in the
    gradle.lockfile format osv-scanner reads (direct dependencies with a literal version only)."""
    lines = ["# GapScan: dependencies declared in Gradle build files (direct, with a version)"]
    for d in sorted(
        {(d.name, d.version, d.dev) for d in deps if d.ecosystem == "Maven" and d.version}
    ):
        name, version, dev = d
        lines.append(
            f"{name}:{version}={'testRuntimeClasspath' if dev else 'releaseRuntimeClasspath'}"
        )
    return "\n".join(lines) + "\nempty=\n"


def _severity(vuln: dict[str, Any], group_max: str | None) -> Severity:
    db = (vuln.get("database_specific") or {}).get("severity", "")
    mapping = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
               "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}  # fmt: skip
    if db.upper() in mapping:
        return mapping[db.upper()]
    try:
        score = float(group_max) if group_max else None
    except ValueError:
        score = None
    if score is None:
        return Severity.MEDIUM
    return (
        Severity.CRITICAL
        if score >= 9
        else Severity.HIGH
        if score >= 7
        else (Severity.MEDIUM if score >= 4 else Severity.LOW)
    )


def _fixed(vuln: dict[str, Any], package: str, installed: str | None) -> str | None:
    """Lowest fix at or above the installed version (advisories list a fix per branch)."""
    fixes: list[str] = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name") != package:
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") == "GIT":  # commit hashes, not versions users can install
                continue
            fixes += [str(ev["fixed"]) for ev in rng.get("events", []) if "fixed" in ev]
    return pick_fix(installed, ", ".join(fixes))


def _symbols(vuln: dict[str, Any], package: str) -> list[str]:
    """Vulnerable functions named by the advisory (Go publishes them; others rarely do)."""
    out: set[str] = set()
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name") != package:
            continue
        eco = aff.get("ecosystem_specific") or {}
        for imp in eco.get("imports", []) or []:
            out.update(str(s) for s in imp.get("symbols", []) or [])
        out.update(str(s) for s in eco.get("affected_functions", []) or [])
    return sorted(out)


def parse_osv(data: dict[str, Any], target: Path) -> list[Finding]:
    out: list[Finding] = []
    for res in data.get("results", []):
        src = relpath((res.get("source") or {}).get("path"), target)
        for pkg in res.get("packages", []):
            info = pkg["package"]
            groups = {
                i: g.get("max_severity") for g in pkg.get("groups", []) for i in g.get("ids", [])
            }
            for vuln in pkg.get("vulnerabilities", []):
                aliases = [
                    a for a in [vuln["id"], *vuln.get("aliases", [])] if a.startswith("CVE-")
                ]
                cwes = (vuln.get("database_specific") or {}).get("cwe_ids", [])
                out.append(
                    Finding(
                        scanner="osv",
                        rule_id=vuln["id"],
                        title=vuln.get("summary") or vuln["id"],
                        message=(vuln.get("details") or "")[:500],
                        severity=_severity(vuln, groups.get(vuln["id"])),
                        category=Category.DEPENDENCY,
                        cwe=[str(c) for c in cwes],
                        file=src,
                        package=info["name"],
                        version=info.get("version"),
                        fixed_version=_fixed(vuln, info["name"], info.get("version")),
                        cve=aliases,
                        raw={
                            "ecosystem": info.get("ecosystem"),
                            "id": vuln["id"],
                            "symbols": _symbols(vuln, info["name"]),
                        },
                    )
                )
    return out


class OSVScanner(CommandScanner):
    name = "osv"
    binary = "osv-scanner"
    ok_returncodes = frozenset({0, 1})  # 1 = vulnerabilities found

    def __init__(self, db_dir: Path, timeout_s: int = 300) -> None:
        super().__init__(timeout_s)
        self.db_dir = db_dir.resolve()  # absolute: tools run from GapScan's work folder

    def is_available(self) -> bool:
        return super().is_available() and self.db_dir.exists()

    def env(self) -> dict[str, str]:
        return {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(self.db_dir.resolve())}

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        """Each lockfile is passed explicitly, and only when its ecosystem's database is installed:
        one missing database (say RubyGems for a fastlane Gemfile.lock) must not hide the rest."""
        self.note = ""
        installed = self.installed_ecosystems()
        lockfiles = find_lockfiles(target)
        gradle_files = (".gradle", ".gradle.kts", ".versions.toml")
        gradle = [
            d for d in declared_dependencies(target)
            if d.ecosystem == "Maven" and d.file.endswith(gradle_files)
        ]  # fmt: skip
        synthetic: Path | None = None
        if gradle and not any(p.name.lower() == "gradle.lockfile" for p, _ in lockfiles):
            synthetic = workdir / "declared" / "gradle.lockfile"
            synthetic.parent.mkdir(parents=True, exist_ok=True)
            synthetic.write_text(gradle_lockfile(gradle), encoding="utf-8")
            lockfiles.append((synthetic, "Maven"))
        usable = [p for p, eco in lockfiles if eco in installed]
        skipped = sorted({eco for _, eco in lockfiles if eco not in installed})
        if skipped:
            self.note = (
                f"no offline database for {', '.join(skipped)}: those lockfiles were not "
                "checked (run Setup again or import a newer bundle)"
            )
        if not usable:
            return []
        findings = self.scan_files(usable, target, workdir)
        if synthetic is not None:  # point findings at the line that declares the library
            where = {d.name: d for d in gradle}
            for f in findings:  # parse_osv keeps the absolute path of a file outside the target
                if f.file and Path(f.file) == synthetic:
                    dep = where.get(f.package or "")
                    if dep:
                        f.file, f.start_line = dep.file, dep.line
                        f.raw["declared_only"] = True  # direct dependency: transitive ones unseen
        return findings

    def installed_ecosystems(self) -> set[str]:
        """OSV ecosystems whose offline database is installed."""
        return {p.name for p in (self.db_dir / OSV_LAYOUT).glob("*") if (p / "all.zip").is_file()}

    def scan_files(self, files: list[Path], target: Path, workdir: Path) -> list[Finding]:
        """Run osv-scanner offline over explicit lockfiles or CycloneDX SBOMs (`*.cdx.json`)."""
        out = workdir / "osv.json"
        # GapScan's own (empty) config overrides any `osv-scanner.toml` in the scanned project,
        # whose [[IgnoredVulns]] would otherwise hide advisories (verified on osv-scanner 2.6.0).
        config = workdir / "osv-scanner.toml"
        config.write_text("", encoding="utf-8")
        args = [
            self.binary,
            "scan",
            "source",
            "--config",
            str(config),
            "--offline",
            "--format",
            "json",
            "--output",
            str(out),
        ]
        for p in files:
            args += ["-L", str(p)]
        proc = self._exec(args)
        if proc.returncode == 128 and "No package sources found" in (proc.stdout + proc.stderr):
            return []
        self.check(proc)
        if not out.is_file():
            raise ScannerError("osv-scanner produced no output")
        return parse_osv(json.loads(out.read_text()), target)
