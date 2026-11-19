"""Typed pipeline stages and the run folder that holds their outputs.

Each stage's output is a pydantic model that can be saved, loaded in another process and checked
against the input it was computed from, so a run can stop after any stage and resume elsewhere:

    scan       scanners, SBOM, redaction        -> raw ScanResult   (raw.json)
    normalize  ignores, dedupe, IDs, scores     -> ScanResult       (scan.json)
    triage     verdicts, deep dives, summary    -> TriageOutput     (triage.json)

Every stage today reads the scanned source tree (`NEEDS_SOURCE`): normalize reads
`.gapscanignore`, secret context and reachability; triage extracts code context and runs read-only
tools on the repository. A process without the source can resume only from saved outputs (for
example to build the report), so a cloud split must keep these stages next to the code.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from .core.models import Investigation, RepoSummary, ScanResult, Verdict
from .core.version import __version__


class Stage(StrEnum):
    SCAN = "scan"
    NORMALIZE = "normalize"
    TRIAGE = "triage"


NEEDS_SOURCE = {Stage.SCAN: True, Stage.NORMALIZE: True, Stage.TRIAGE: True}
FILES = {Stage.SCAN: "raw.json", Stage.NORMALIZE: "scan.json", Stage.TRIAGE: "triage.json"}
MANIFEST = "run.json"


class StageMismatch(ValueError):
    """A stage output was computed from a different input than the one it is used with."""


def digest(model: BaseModel) -> str:
    """Content hash of a stage output, independent of how the file was formatted."""
    return hashlib.sha256(model.model_dump_json().encode("utf-8")).hexdigest()


class TriageOutput(BaseModel):
    """What the triage stage produces; `triage.json`. Older files have no `scan_digest`."""

    verdicts: list[Verdict] = Field(default_factory=list)
    summary: RepoSummary | None = None
    investigations: list[Investigation] = Field(default_factory=list)
    scan_digest: str = ""  # digest() of the normalized ScanResult it was computed from

    def check(self, scan: ScanResult) -> None:
        """Refuse verdicts made for another scan: their finding ids point at other code."""
        if self.scan_digest and self.scan_digest != digest(scan):
            raise StageMismatch("this triage output was computed from a different scan")


class StageRecord(BaseModel):
    stage: Stage
    file: str
    sha256: str
    inputs: dict[str, str] = Field(default_factory=dict)  # input stage -> its sha256
    needs_source: bool
    gapscan_version: str = __version__
    finished_at: str = ""


class RunManifest(BaseModel):
    manifest_version: int = 1
    stages: dict[Stage, StageRecord] = Field(default_factory=dict)


class RunFolder:
    """A run's stage outputs on disk, plus the manifest that links each output to its inputs."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def manifest(self) -> RunManifest:
        p = self.path / MANIFEST
        if not p.is_file():
            return RunManifest()
        return RunManifest.model_validate_json(p.read_text(encoding="utf-8"))

    def has(self, stage: Stage) -> bool:
        return (self.path / FILES[stage]).is_file()

    def _save(self, stage: Stage, output: BaseModel, inputs: dict[str, str]) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        (self.path / FILES[stage]).write_text(output.model_dump_json(indent=1), encoding="utf-8")
        m = self.manifest()
        m.stages[stage] = StageRecord(
            stage=stage, file=FILES[stage], sha256=digest(output), inputs=inputs,
            needs_source=NEEDS_SOURCE[stage],
            finished_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )  # fmt: skip
        (self.path / MANIFEST).write_text(m.model_dump_json(indent=1), encoding="utf-8")

    def _read(self, stage: Stage) -> str:
        return (self.path / FILES[stage]).read_text(encoding="utf-8")

    def save_raw(self, raw: ScanResult) -> None:
        self._save(Stage.SCAN, raw, {})

    def load_raw(self) -> ScanResult:
        return ScanResult.model_validate_json(self._read(Stage.SCAN))

    def save_scan(self, scan: ScanResult, raw: ScanResult | None = None) -> None:
        self._save(Stage.NORMALIZE, scan, {Stage.SCAN.value: digest(raw)} if raw else {})

    def load_scan(self) -> ScanResult:
        return ScanResult.model_validate_json(self._read(Stage.NORMALIZE))

    def save_triage(self, triage: TriageOutput) -> None:
        self._save(Stage.TRIAGE, triage, {Stage.NORMALIZE.value: triage.scan_digest})

    def load_triage(self, scan: ScanResult | None = None) -> TriageOutput:
        """The saved triage output, or an empty one; checked against `scan` when given."""
        if not self.has(Stage.TRIAGE):
            return TriageOutput()
        out = TriageOutput.model_validate_json(self._read(Stage.TRIAGE))
        if scan is not None:
            out.check(scan)
        return out
