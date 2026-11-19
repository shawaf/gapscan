"""The scan pipeline as plain functions, independent of the CLI, so other front ends (a CI
step, the Stage 2 server) call the same engine. Nothing here prints or reads sys.argv.

The engine runs the stages; the registered domain packs do the domain work inside them: their
collectors gather the evidence and their annotators add facts during normalize. The model review
is `gapscan.services.review_scan` with a pack's review steps."""

from __future__ import annotations

import logging
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from .config import Config
from .core.version import __version__
from .models import ScanResult
from .normalize import normalize
from .registry import registry_for

log = logging.getLogger(__name__)


def run_scan(
    config: Config, target: Path, *, keep_workdir: bool = False, images: Sequence[Path] = ()
) -> ScanResult:
    """Scanners, SBOM, redact, dedupe, classify, stable IDs, score. No LLM, no network.
    The `scan` and `normalize` stages (gapscan.stages) in one call."""
    raw = collect_evidence(config, target, keep_workdir=keep_workdir, images=images)
    return normalize_scan(config, raw, target)


def collect_evidence(
    config: Config, target: Path, *, keep_workdir: bool = False, images: Sequence[Path] = ()
) -> ScanResult:
    """The `scan` stage: every registered pack's collector (its enabled scanners plus, for
    security, the SBOM), secrets redacted. Raw findings."""
    collectors = registry_for(config).collectors
    target = target.resolve()
    if not collectors:
        log.warning("no pack collects evidence (scanners.packs: %s)", config.scanners.packs)
        return ScanResult(target=str(target))
    with tempfile.TemporaryDirectory(prefix="gapscan-") as work:
        # Each collector gets its own working folder (the first keeps the top one).
        dirs = [Path(work) / (f"collector-{i}" if i else "") for i in range(len(collectors))]
        results = [c(config, target, d, keep_workdir=keep_workdir, images=images)
                   for c, d in zip(collectors, dirs, strict=True)]  # fmt: skip
    merged = results[0]
    for other in results[1:]:
        merged.findings += other.findings
        merged.runs += other.runs
        merged.sbom = merged.sbom or other.sbom
    return merged


def normalize_scan(config: Config, raw: ScanResult, target: Path) -> ScanResult:
    """The `normalize` stage: ignores, dedupe, controls, stable IDs, the packs' annotations and
    scores. Reads the source tree (`.gapscanignore`, and whatever the annotators read)."""
    reg = registry_for(config)
    result = normalize(
        raw,
        target.resolve(),
        reg.annotators_for(config),
        config.general.max_llm_findings,
        reg.target_packs,
    )
    return result.model_copy(
        update={
            "gapscan_version": __version__,
            "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
