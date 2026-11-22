"""Trivy adapter: offline filesystem scan (vulns + misconfig) and CycloneDX SBOM."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Category, Finding, Severity
from .base import CommandScanner, ScannerError, pick_fix

_SEV = {s.value.upper(): s for s in Severity} | {"UNKNOWN": Severity.INFO}


def parse_trivy(data: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for res in data.get("Results", []):
        path = res.get("Target")
        for v in res.get("Vulnerabilities") or []:
            vid = v["VulnerabilityID"]
            out.append(
                Finding(
                    scanner="trivy",
                    rule_id=vid,
                    title=v.get("Title") or vid,
                    message=(v.get("Description") or "")[:500],
                    severity=_SEV.get(v.get("Severity", ""), Severity.MEDIUM),
                    category=Category.DEPENDENCY,
                    cwe=list(v.get("CweIDs") or []),
                    file=path,
                    package=v.get("PkgName"),
                    version=v.get("InstalledVersion"),
                    fixed_version=pick_fix(v.get("InstalledVersion"), v.get("FixedVersion")),
                    cve=[vid] if vid.startswith("CVE-") else [],
                    raw={"primary_url": v.get("PrimaryURL")},
                )
            )
        for m in res.get("Misconfigurations") or []:
            cause = m.get("CauseMetadata") or {}
            code = "\n".join(
                ln.get("Content", "") for ln in (cause.get("Code") or {}).get("Lines") or []
            )
            out.append(
                Finding(
                    scanner="trivy",
                    rule_id=m.get("AVDID") or m.get("ID", "misconfig"),
                    title=m.get("Title", "Misconfiguration"),
                    message=m.get("Message") or m.get("Description", ""),
                    severity=_SEV.get(m.get("Severity", ""), Severity.MEDIUM),
                    category=Category.CONFIG,
                    file=path,
                    start_line=cause.get("StartLine"),
                    end_line=cause.get("EndLine"),
                    snippet=code or None,
                    raw={"resolution": m.get("Resolution")},
                )
            )
    return out


# Trivy (0.50+) calls check.trivy.dev on every run for a version check and anonymous telemetry,
# even with --offline-scan. A scan must make no network call, so both are switched off. Set as
# environment variables rather than flags so an older Trivy without the flags still runs.
NO_PHONE_HOME = {"TRIVY_SKIP_VERSION_CHECK": "true", "TRIVY_DISABLE_TELEMETRY": "true"}


class TrivyScanner(CommandScanner):
    name = "trivy"
    binary = "trivy"

    def __init__(self, cache_dir: Path, timeout_s: int = 300) -> None:
        super().__init__(timeout_s)
        self.cache_dir = cache_dir.resolve()  # absolute: tools run from GapScan's work folder

    def is_available(self) -> bool:
        return super().is_available() and self.cache_dir.exists()

    def env(self) -> dict[str, str]:
        return dict(NO_PHONE_HOME)

    def _base(self, target: Path, out: Path, fmt: str) -> list[str]:
        return [
            self.binary, "fs", "--cache-dir", str(self.cache_dir), "--skip-db-update",
            "--skip-java-db-update", "--offline-scan", "--quiet", "--format", fmt,
            "--output", str(out), str(target),
        ]  # fmt: skip

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        out = workdir / "trivy.json"
        self.check(self._exec([*self._base(target, out, "json"), "--scanners", "vuln,misconfig"]))
        if not out.is_file():
            raise ScannerError("trivy produced no output")
        return parse_trivy(json.loads(out.read_text()))

    def sbom(self, target: Path, workdir: Path) -> dict[str, Any]:
        """CycloneDX SBOM of the target's dependencies."""
        out = workdir / "sbom.cdx.json"
        self.check(self._exec([*self._base(target, out, "cyclonedx"), "--scanners", "vuln"]))
        if not out.is_file():
            raise ScannerError("trivy produced no SBOM")
        doc: dict[str, Any] = json.loads(out.read_text())
        return doc


class TrivyImageScanner(CommandScanner):
    """Scan a container image saved with `docker save` / `podman save` (an archive on disk), fully
    offline: no registry, no daemon. Findings are tagged `asset = "image"` and carry the image name
    in `file`, so the dashboard can show them as their own view."""

    name = "trivy-image"
    binary = "trivy"

    def __init__(self, cache_dir: Path, timeout_s: int = 600) -> None:
        super().__init__(timeout_s)
        self.cache_dir = cache_dir.resolve()  # absolute: tools run from GapScan's work folder

    def is_available(self) -> bool:
        return super().is_available() and self.cache_dir.exists()

    def env(self) -> dict[str, str]:
        return dict(NO_PHONE_HOME)

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        """`target` is the image archive."""
        out = workdir / "image.json"
        self.check(
            self._exec(
                [
                    self.binary,
                    "image",
                    "--input",
                    str(target),
                    "--cache-dir",
                    str(self.cache_dir),
                    "--skip-db-update",
                    "--skip-java-db-update",
                    "--offline-scan",
                    "--quiet",
                    "--scanners",
                    "vuln,misconfig,secret",
                    "--format",
                    "json",
                    "--output",
                    str(out),
                ]
            )  # fmt: skip
        )
        if not out.is_file():
            raise ScannerError("trivy produced no output for the image")
        findings = parse_trivy(json.loads(out.read_text()))
        for f in findings:
            f.scanner = "trivy-image"
            # Trivy names the OS layer after the archive path; keep only the name (no local paths)
            inner = (f.file or "").replace(str(target), target.name)
            f.file = f"image:{target.name} > {inner}" if inner else f"image:{target.name}"
            f.raw["asset"] = "image"
        return findings
