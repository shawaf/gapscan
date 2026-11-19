"""Verified autofix (fake model, real re-scan), hardware tiers and the opt-in data flywheel."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from gapscan.autofix import NoFix, PatchProposal, apply_offer, apply_proposal, suggest_verified_fix
from gapscan.config import Config, LLMConfig
from gapscan.flywheel import FlywheelDisabled, export_dataset
from gapscan.llm.client import LLMClient
from gapscan.models import Category, Finding, ScanResult, Severity, TriageAnswer
from gapscan.report.decisions import Decision, Decisions
from gapscan.taint.scanner import TaintScanner

VULN = (
    "import os\nimport shlex\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
    '@app.route("/ping")\ndef ping():\n    host = request.args.get("host")\n    os.system("ping -c1 " + host)\n'
)


def project(tmp_path: Path) -> tuple[Path, Finding]:
    (tmp_path / "app.py").write_text(VULN)
    (f,) = TaintScanner().run(tmp_path, tmp_path)
    f.sources = ["taint"]
    return tmp_path, f


def _mk(p: Path) -> Path:
    p.mkdir()
    return p


def model(*proposals: dict[str, str]) -> LLMClient:
    it = iter(proposals)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {"content": json.dumps(next(it))},
                "prompt_eval_count": 9,
                "eval_count": 9,
            },
        )

    return LLMClient(LLMConfig(model="m:1"), httpx.Client(transport=httpx.MockTransport(handler)))


GOOD = {
    "old": 'os.system("ping -c1 " + host)',
    "new": 'os.system("ping -c1 " + shlex.quote(host))',
    "explanation": "quote the argument",
}
NOOP = {
    "old": 'os.system("ping -c1 " + host)',
    "new": 'os.system("ping -c1 " + host)',
    "explanation": "x",
}
WORSE = {
    "old": 'os.system("ping -c1 " + host)',
    "new": 'eval("ping -c1 " + host)',
    "explanation": "x",
}
MISSING = {"old": "not in the file", "new": "x", "explanation": "x"}


def test_verified_patch_is_offered_and_the_project_is_untouched(tmp_path: Path) -> None:
    target, f = project(tmp_path)
    offer = suggest_verified_fix(Config(), target, f, client=model(GOOD))
    assert offer.verified and offer.attempts == 1 and "shlex.quote(host)" in offer.diff
    assert {c.name: c.ok for c in offer.checks}["finding removed"] and not offer.new_findings
    assert (target / "app.py").read_text() == VULN  # nothing applied during verification
    apply_offer(target, offer)
    assert "shlex.quote(host)" in (target / "app.py").read_text()


def test_rejected_patch_gets_feedback_then_a_second_try(tmp_path: Path) -> None:
    target, f = project(tmp_path)
    offer = suggest_verified_fix(Config(), target, f, client=model(NOOP, GOOD))
    assert offer.attempts == 2 and offer.verified


def test_patch_that_adds_a_new_finding_is_never_offered(tmp_path: Path) -> None:
    target, f = project(tmp_path)
    with pytest.raises(NoFix, match="did not verify"):
        suggest_verified_fix(Config(), target, f, client=model(WORSE, WORSE))


def test_patch_text_must_match_exactly_once(tmp_path: Path) -> None:
    with pytest.raises(NoFix, match="exactly once"):
        apply_proposal(VULN, PatchProposal(**MISSING))
    with pytest.raises(NoFix, match="changes nothing"):
        apply_proposal(VULN, PatchProposal(**NOOP))
    big = PatchProposal(
        old="import os", new="\n".join(f"x{i} = {i}" for i in range(60)), explanation="x"
    )
    with pytest.raises(NoFix, match="lines"):
        apply_proposal(VULN, big)


def test_dependency_findings_are_not_autofixed(tmp_path: Path) -> None:
    dep = Finding(
        scanner="osv",
        rule_id="CVE-1",
        title="t",
        severity=Severity.HIGH,
        category=Category.DEPENDENCY,
        file="r.txt",
        package="p",
    )
    with pytest.raises(NoFix, match="upgrade"):
        suggest_verified_fix(Config(), tmp_path, dep, client=model(GOOD))


def test_unapplied_offers_cannot_be_applied(tmp_path: Path) -> None:
    target, f = project(tmp_path)
    offer = suggest_verified_fix(Config(), target, f, client=model(GOOD))
    offer.verified = False
    with pytest.raises(NoFix):
        apply_offer(target, offer)


def test_hardware_tiers() -> None:
    assert LLMConfig(tier="ci").profile == "small" and LLMConfig(tier="ci").model == "granite4.2:8b"
    assert LLMConfig(tier="server").profile == "best"
    assert LLMConfig(tier="laptop", profile="tiny").profile == "tiny"  # explicit settings win
    gpu = LLMConfig(
        tier="gpu", tiers={"gpu": {"profile": "best", "endpoint": "http://gpu.local:11434"}}
    )  # type: ignore[arg-type]
    assert gpu.endpoint == "http://gpu.local:11434"
    with pytest.raises(ValidationError):
        LLMConfig(
            tier="gpu", tiers={"gpu": {"profile": "best", "endpoint": "https://api.example.com"}}
        )  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        LLMConfig(tier="nope")


def test_flywheel_is_opt_in_and_exports_validated_masked_examples(tmp_path: Path) -> None:
    target, f = project(_mk(tmp_path / "proj"))
    result = ScanResult(target=str(target), findings=[f])
    decisions = Decisions(
        decisions=[
            Decision(
                finding_id=f.id,
                decision="false_positive",
                note="password = 'hunter2hunter2' is a fixture value",
                by="ana",
            )
        ]
    )
    with pytest.raises(FlywheelDisabled):
        export_dataset(Config(), result, decisions, target, tmp_path / "out")
    cfg = Config(flywheel={"enabled": True, "holdout_percent": 5})  # type: ignore[arg-type]
    stats = export_dataset(cfg, result, decisions, target, tmp_path / "out")
    assert stats.train + stats.heldout == 1 and stats.skipped == 0
    lines = [
        ln
        for name in ("train.jsonl", "heldout.jsonl")
        for ln in (tmp_path / "out" / name).read_text().splitlines()
    ]
    ex = json.loads(lines[0])
    answer = TriageAnswer.model_validate_json(ex["messages"][1]["content"])
    assert answer.verdict.value == "false_positive"
    assert "hunter2hunter2" not in lines[0] and "<untrusted_data>" in ex["messages"][0]["content"]
    assert json.loads((tmp_path / "out" / "manifest.json").read_text())["skipped"] == 0
