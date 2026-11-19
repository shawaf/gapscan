"""Engine services: the review the CLI and the local server share."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from gapscan.cli import app
from gapscan.config import Config
from gapscan.models import Investigation, Verdict
from gapscan.services import ReviewHooks, ReviewStopped, review_scan
from gapscan.stages import TriageOutput, digest
from tests.test_server import FakePipeline

CFG = Config(agent={"deep_dive_min_priority": 0})


class Recorder(ReviewHooks):
    def __init__(self) -> None:
        self.events: list[str] = []

    def message(self, text: str) -> None:
        self.events.append(f"msg:{text}")

    def triage_started(self, total: int) -> None:
        self.events.append(f"triage:{total}")

    def verdict(self, verdict: Verdict) -> None:
        self.events.append("verdict")

    def deep_dive_started(self, groups: int) -> None:
        self.events.append(f"deep:{groups}")

    def investigation(self, investigation: Investigation) -> None:
        self.events.append("investigation")

    def summary_started(self) -> None:
        self.events.append("summary")


def test_a_review_triages_investigates_and_summarizes(tmp_path: Path) -> None:
    steps, hooks = FakePipeline(), Recorder()
    out = review_scan(CFG, steps.scan_result, tmp_path, steps=steps, limit=40, deep_dive_limit=2,
                      hooks=hooks)  # fmt: skip
    assert out.verdicts and out.investigations and out.summary is not None
    assert out.scan_digest == digest(steps.scan_result)  # tied to the scan it reviewed
    phases = [e for e in hooks.events if not e.startswith(("msg:", "verdict", "investigation"))]
    assert phases[0].startswith("triage:") and phases[1] == "deep:2" and phases[-1] == "summary"
    assert hooks.events.count("investigation") == len(out.investigations)


def test_a_failing_deep_dive_keeps_the_review(tmp_path: Path) -> None:
    steps, hooks = FakePipeline(), Recorder()
    steps.deep_fail = "model went away"
    out = review_scan(CFG, steps.scan_result, tmp_path, steps=steps, limit=40, deep_dive_limit=2,
                      hooks=hooks)  # fmt: skip
    assert out.verdicts and out.investigations == [] and out.summary is not None
    assert "msg:deep dive stopped: model went away" in hooks.events


def test_a_stop_from_a_hook_is_never_swallowed(tmp_path: Path) -> None:
    class StopOnInvestigation(Recorder):
        def investigation(self, investigation: Investigation) -> None:
            raise ReviewStopped("cancelled")

    steps = FakePipeline()
    with pytest.raises(ReviewStopped):
        review_scan(CFG, steps.scan_result, tmp_path, steps=steps, limit=40, deep_dive_limit=2,
                    hooks=StopOnInvestigation())  # fmt: skip


def test_no_summary_without_verdicts_and_no_deep_dive_unless_asked(tmp_path: Path) -> None:
    steps, hooks = FakePipeline(), Recorder()
    out = review_scan(CFG, steps.scan_result, tmp_path, steps=steps, limit=0, hooks=hooks)
    assert out == TriageOutput(scan_digest=digest(steps.scan_result))
    assert steps.deep_calls == 0 and "summary" not in hooks.events


def test_the_cli_runs_the_same_review(tmp_path: Path, monkeypatch) -> None:
    steps = FakePipeline()
    monkeypatch.setattr("gapscan.cli.AgentSteps", lambda client: steps)
    scan_file, out = tmp_path / "scan.json", tmp_path / "verdicts.json"
    scan_file.write_text(steps.scan_result.model_dump_json())
    r = CliRunner().invoke(app, ["triage", str(scan_file), "-t", str(tmp_path), "-o", str(out),
                                 "--limit", "40", "--deep-dive", "--deep-dive-limit", "2"])  # fmt: skip
    assert r.exit_code == 0, r.output
    saved = TriageOutput.model_validate_json(out.read_text())
    assert saved.verdicts and saved.investigations and saved.summary is not None
    saved.check(steps.scan_result)  # the report command will accept it for this scan
    assert "Deep dive" in r.output and f"{len(saved.verdicts)} verdicts" in r.output
