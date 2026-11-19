"""Typed pipeline stages: each stage's output is saved, loaded in another process,
and checked against the input it was computed from."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gapscan.cli import app
from gapscan.config import Config
from gapscan.models import ScanResult, Verdict, VerdictLabel
from gapscan.pipeline import normalize_scan
from gapscan.scanners.bandit import parse_bandit
from gapscan.scanners.sarif import parse_sarif
from gapscan.stages import (
    FILES,
    NEEDS_SOURCE,
    RunFolder,
    Stage,
    StageMismatch,
    TriageOutput,
    digest,
)
from tests.synthetic import synthetic_scan

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
TARGET = ROOT / "eval" / "fixtures" / "vuln-app"


def raw_scan() -> ScanResult:
    """Raw scanner output for the vuln-app fixture, from recorded tool runs."""
    load = lambda n: json.loads((DATA / n).read_text().replace("TARGET", str(TARGET)))  # noqa: E731
    findings = parse_sarif(load("semgrep.sarif"), TARGET, "semgrep") + parse_bandit(
        load("bandit.json"), TARGET
    )
    return ScanResult(target=str(TARGET), findings=findings)


def without_time(scan: ScanResult) -> ScanResult:
    return scan.model_copy(update={"created_at": ""})


def test_every_stage_has_a_file_and_states_whether_it_needs_the_source() -> None:
    assert set(FILES) == set(NEEDS_SOURCE) == set(Stage)
    # Today every stage reads the scanned code; a process without it resumes from saved outputs.
    assert all(NEEDS_SOURCE.values())


def test_the_digest_ignores_file_formatting() -> None:
    scan = synthetic_scan(30)
    again = ScanResult.model_validate_json(scan.model_dump_json(indent=1))
    assert digest(again) == digest(scan)
    assert digest(synthetic_scan(30, seed=8)) != digest(scan)


def test_normalize_resumes_in_another_process_from_the_saved_raw_scan(tmp_path) -> None:
    raw = raw_scan()
    folder = RunFolder(tmp_path / "run")
    folder.save_raw(raw)
    code = (
        "import sys; from pathlib import Path\n"
        "from gapscan.config import Config\n"
        "from gapscan.pipeline import normalize_scan\n"
        "from gapscan.stages import RunFolder\n"
        "f = RunFolder(Path(sys.argv[1]))\n"
        "raw = f.load_raw()\n"
        "f.save_scan(normalize_scan(Config(), raw, Path(sys.argv[2])), raw)\n"
    )
    subprocess.run([sys.executable, "-c", code, str(folder.path), str(TARGET)], check=True,
                   cwd=ROOT, timeout=120)  # fmt: skip
    resumed = folder.load_scan()
    here = normalize_scan(Config(), raw, TARGET)
    assert len(resumed.findings) > 10
    assert digest(without_time(resumed)) == digest(without_time(here))
    record = folder.manifest().stages[Stage.NORMALIZE]
    assert record.inputs == {"scan": digest(raw)} and record.sha256 == digest(resumed)
    assert record.needs_source


def test_triage_output_is_tied_to_its_scan(tmp_path) -> None:
    scan, other = synthetic_scan(20), synthetic_scan(20, seed=9)
    verdict = Verdict(finding_id=scan.findings[0].id, verdict=VerdictLabel.TRUE_POSITIVE)
    folder = RunFolder(tmp_path)
    folder.save_scan(scan)
    folder.save_triage(TriageOutput(verdicts=[verdict], scan_digest=digest(scan)))
    assert folder.load_triage(scan).verdicts == [verdict]
    with pytest.raises(StageMismatch):
        folder.load_triage(other)
    stages = folder.manifest().stages
    assert stages[Stage.TRIAGE].inputs == {"normalize": stages[Stage.NORMALIZE].sha256}


def test_triage_files_from_before_the_digest_still_load(tmp_path) -> None:
    scan = synthetic_scan(5)
    v = Verdict(finding_id=scan.findings[0].id)
    old = {"verdicts": [v.model_dump(mode="json")], "summary": None, "investigations": []}
    (tmp_path / "triage.json").write_text(json.dumps(old))
    assert RunFolder(tmp_path).load_triage(scan).verdicts == [v]
    assert RunFolder(tmp_path / "none").load_triage(scan) == TriageOutput()


def test_report_refuses_verdicts_from_another_scan(tmp_path) -> None:
    scan, other = synthetic_scan(10), synthetic_scan(10, seed=3)
    (tmp_path / "scan.json").write_text(scan.model_dump_json())
    (tmp_path / "triage.json").write_text(TriageOutput(scan_digest=digest(other)).model_dump_json())
    r = CliRunner().invoke(app, ["report", str(tmp_path / "scan.json"), "--triage",
                                 str(tmp_path / "triage.json"), "-o", str(tmp_path / "r.html")])  # fmt: skip
    assert r.exit_code == 2 and "different scan" in r.output
    assert not (tmp_path / "r.html").exists()
