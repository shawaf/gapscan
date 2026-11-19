"""Scanner adapters and the scan step. The security pack registers the adapters in `pack.py`;
`gapscan.registry.build_scanners` builds the enabled set from config."""

from __future__ import annotations

import logging
import shutil
from collections.abc import Sequence
from pathlib import Path

from ..config import Config
from ..manifests import add_declared_to_sbom, declared_dependencies
from ..models import Finding, ScanResult
from ..redact import redact_findings
from ..registry import build_scanners, registry_for
from .base import Scanner, ScannerError, run_all
from .trivy import TrivyImageScanner, TrivyScanner

__all__ = ["Scanner", "ScannerError", "build_scanners", "scan_target"]

log = logging.getLogger(__name__)


def scan_target(
    config: Config,
    target: Path,
    workdir: Path,
    keep_workdir: bool = False,
    images: Sequence[Path] = (),
) -> ScanResult:
    """Run all enabled scanners in parallel plus the SBOM step. Never executes the target."""
    scanners = build_scanners(config)
    findings, runs = run_all(scanners, target, workdir, config.scanners.timeout_s)
    pack_of = {name: spec.pack for name, spec in registry_for(config).scanners.items()}
    for r in runs:
        r.pack = pack_of.get(r.scanner, "")
    for tar in images:  # container images saved to disk: scanned offline, one run each
        img = TrivyImageScanner(config.scanners.trivy.cache_dir, config.scanners.timeout_s)
        one, run = run_all([_ImageJob(img, tar)], target, workdir / "images")
        for r in run:
            r.pack = pack_of.get("trivy", "")  # image scans are Trivy's
        findings += one
        runs += run
    result = ScanResult(target=str(target), findings=redact_findings(findings), runs=runs)
    trivy = next((s for s in scanners if isinstance(s, TrivyScanner)), None)
    if trivy is not None and trivy.is_available():
        try:
            result.sbom = trivy.sbom(target, workdir / "trivy")
        except Exception as exc:  # noqa: BLE001 - SBOM failure must not fail the scan
            log.warning("SBOM generation failed: %s", exc)
    try:
        result.sbom = add_declared_to_sbom(result.sbom, declared_dependencies(target))
    except Exception as exc:  # noqa: BLE001 - SBOM failure must not fail the scan
        log.warning("adding declared dependencies to the SBOM failed: %s", exc)
    if not keep_workdir:
        # Raw tool output (e.g. Semgrep SARIF) quotes source lines, which may hold secrets.
        for s in scanners:
            shutil.rmtree(workdir / s.name, ignore_errors=True)
    return result


class _ImageJob:
    """Adapts the image scanner to the Scanner protocol: it scans `tar`, not the repository."""

    def __init__(self, scanner: TrivyImageScanner, tar: Path) -> None:
        self.inner, self.tar = scanner, tar
        self.name = "trivy-image"

    def is_available(self) -> bool:
        return self.inner.is_available() and self.tar.is_file()

    def version(self) -> str:
        return self.inner.version()

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        return self.inner.run(self.tar, workdir)
