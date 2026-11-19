from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gapscan.agent.review import triage_top_findings
from gapscan.cli import app
from gapscan.config import Config
from gapscan.llm.client import ChatResult
from gapscan.memory import (
    Memory,
    add_memory,
    from_decision,
    load_memories,
    relevance,
    remove_memory,
    render_memory,
    retrieve,
    save_memories,
)
from gapscan.models import Category, Finding, ScanResult, Severity, VerdictLabel


def finding(
    rule="javascript.audit.detect-non-literal-fs-filename",
    file="src/logs/svc.ts",
    cwe=("CWE-22",),
    **kw,
):
    return Finding(scanner="semgrep", rule_id=rule, title="t", severity=Severity.MEDIUM,
                   category=Category.CODE, cwe=list(cwe), file=file, start_line=3, **kw)  # fmt: skip


def test_memory_ids_are_stable_and_text_is_bounded():
    a = Memory(text="x is deployed", rule="r", path="src")
    assert a.id == Memory(text="x is deployed", rule="r", path="src").id
    assert a.id != Memory(text="x is deployed", rule="r", path="lib").id
    with pytest.raises(ValueError):
        Memory(text="y" * 401)
    with pytest.raises(ValueError):
        Memory(text="ok", kind="bogus")  # type: ignore[arg-type]


def test_relevance_by_rule_path_and_cwe():
    f = finding()
    by_tail = Memory(text="t", rule="detect-non-literal-fs-filename")
    by_full = Memory(text="t", rule=f.rule_id)
    assert relevance(by_full, f) > relevance(by_tail, f) > 0
    assert relevance(Memory(text="t", rule="other-rule"), f) == 0
    assert relevance(Memory(text="t", rule="non-literal-fs"), f) > 0  # a distinctive fragment
    assert relevance(Memory(text="t", rule="fs"), f) == 0  # too short to be distinctive
    assert (
        relevance(Memory(text="t", path="src/logs"), f) > 0
        and relevance(Memory(text="t", path="src/log"), f) == 0
    )
    assert relevance(Memory(text="t", path="src/*/svc.ts"), f) > 0
    assert (
        relevance(Memory(text="t", cwe="CWE-22"), f) > 0
        and relevance(Memory(text="t", cwe="CWE-89"), f) == 0
    )
    assert relevance(Memory(text="t"), f) == 0.5  # an unscoped note applies weakly everywhere
    assert relevance(Memory(text="t", rule=f.rule_id, enabled=False), f) == 0
    assert relevance(Memory(text="t", path="src"), finding(file=None)) == 0


def test_retrieval_ranks_specific_first_and_respects_the_limit():
    f = finding()
    general = Memory(text="general", rule="detect-non-literal-fs-filename")
    specific = Memory(
        text="specific", rule="detect-non-literal-fs-filename", path="src/logs", cwe="CWE-22"
    )
    other = Memory(text="other folder", path="lib")
    context = Memory(text="whole project")
    got = retrieve([context, other, general, specific], f, limit=2)
    assert [m.text for m in got] == ["specific", "general"]
    assert retrieve([other], f) == []


def test_render_names_the_kind_and_the_scope():
    m = Memory(
        text="the cleanup only touches files it created",
        kind="false_positive",
        rule="rm-rule",
        path="src/logs",
    )
    line = render_memory(m)
    assert (
        m.id in line
        and "NOT a real weakness" in line
        and "rule rm-rule" in line
        and "src/logs" in line
    )
    assert line.endswith("the cleanup only touches files it created")


def test_decisions_become_memories_only_with_a_real_note():
    f = finding()
    assert from_decision(f, "false_positive", "") is None
    assert from_decision(f, "false_positive", "too short") is None
    m = from_decision(
        f, "false_positive", "  userId is checked against ^[a-z0-9]+$ in   guard()  ", "ana"
    )
    assert (
        m
        and m.kind == "false_positive"
        and m.path == "src/logs"
        and m.rule == "detect-non-literal-fs-filename"
    )
    assert (
        m.text == "userId is checked against ^[a-z0-9]+$ in guard()"
        and "decision:" in m.source
        and "ana" in m.source
    )
    assert from_decision(f, "fixed", "patched in the controller last sprint").kind == "confirmed"  # type: ignore[union-attr]
    assert (
        from_decision(f, "accepted_risk", "internal tool, accepted until Q3").kind
        == "accepted_risk"
    )  # type: ignore[union-attr]


def test_files_round_trip_and_adds_are_idempotent(tmp_path):
    path = tmp_path / "m" / "memories.json"
    assert load_memories(path) == [] and load_memories(None) == []
    a = Memory(text="alpha note here", rule="r")
    memories = add_memory(add_memory([], a), a)
    assert len(memories) == 1
    save_memories(path, memories)
    assert load_memories(path) == memories
    assert remove_memory(memories, a.id) == [] and remove_memory(memories, "nope") == memories
    path.write_text(json.dumps({"version": 99, "memories": []}))
    with pytest.raises(ValueError):
        load_memories(path)


def test_cli_add_list_rm_and_from_decisions(tmp_path):
    runner = CliRunner()
    file = tmp_path / "memories.json"
    r = runner.invoke(
        app,
        [
            "memory",
            "add",
            "the logs folder is never deployed",
            "--path",
            "src/logs",
            "--kind",
            "context",
            "--file",
            str(file),
        ],
    )
    assert r.exit_code == 0, r.output
    mem_id = load_memories(file)[0].id
    assert "src/logs" in runner.invoke(app, ["memory", "list", "--file", str(file)]).output
    assert (
        runner.invoke(
            app, ["memory", "add", "x", "--kind", "nonsense", "--file", str(file)]
        ).exit_code
        != 0
    )
    scan = ScanResult(target=str(tmp_path), findings=[finding()])
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(scan.model_dump_json())
    decisions = tmp_path / "d.json"
    decisions.write_text(json.dumps({"version": 1, "decisions": [
        {"finding_id": scan.findings[0].id, "decision": "false_positive", "note": "cleanup only deletes files this service created"},
        {"finding_id": scan.findings[0].id, "decision": "fixed", "note": ""},
        {"finding_id": "unknown", "decision": "false_positive", "note": "long enough note but unknown finding"},
    ]}))  # fmt: skip
    r = runner.invoke(
        app, ["memory", "from-decisions", str(scan_file), str(decisions), "--file", str(file)]
    )
    assert r.exit_code == 0 and "1 memories from 3 decisions" in r.output
    assert len(load_memories(file)) == 2
    assert runner.invoke(app, ["memory", "rm", mem_id, "--file", str(file)]).exit_code == 0
    assert len(load_memories(file)) == 1
    assert runner.invoke(app, ["memory", "rm", "missing", "--file", str(file)]).exit_code != 0


def test_pipeline_shows_memories_to_the_model_and_records_them(tmp_path):
    (tmp_path / "svc.ts").write_text("export function f(id: string) {\n  return db.query(id)\n}\n")
    prompts: list[str] = []

    class FakeClient:
        model = "fake:1"

        def answer_settings(self):
            return {}

        def chat(self, messages, **kw):
            prompts.append(messages[-1]["content"])
            answer = {"verdict": "needs_review", "confidence": 0.5, "reasoning": "unsure"}
            return ChatResult(
                text=json.dumps(answer), prompt_tokens=1, completion_tokens=1, duration_s=0.0
            )

    f = finding(file="svc.ts", rule="x.sql-injection", cwe=("CWE-89",)).model_copy(
        update={"start_line": 2}
    )
    mem = Memory(
        text="db.query here always receives a validated numeric id",
        kind="false_positive",
        rule="sql-injection",
    )
    other = Memory(text="unrelated note about another rule", rule="xss-rule")
    cfg = Config(data={"dir": str(tmp_path)}, agent={"use_tools": False})
    out = triage_top_findings(cfg, ScanResult(target=str(tmp_path), findings=[f]), tmp_path,
                              limit=1, client=FakeClient(), kb=None, memories=[mem, other])  # fmt: skip
    assert len(out) == 1 and out[0].memories_used == [mem.id]
    assert (
        "TEAM MEMORIES" in prompts[0]
        and mem.id in prompts[0]
        and "validated numeric id" in prompts[0]
    )
    assert other.id not in prompts[0]
    # no memories, no section
    prompts.clear()
    triage_top_findings(cfg, ScanResult(target=str(tmp_path), findings=[f]), tmp_path, limit=1,
                        client=FakeClient(), kb=None, memories=[other])  # fmt: skip
    assert (
        "TEAM MEMORIES (notes" not in prompts[0]
    )  # the rule text names it; the section does not appear


def test_memories_never_override_the_hard_guardrails(tmp_path):
    from gapscan.agent.triage import apply_policy
    from gapscan.models import Verdict

    dep = Finding(scanner="osv", rule_id="GHSA-x", title="t", severity=Severity.HIGH,
                  category=Category.DEPENDENCY, package="django", version="3.0.0", cve=["CVE-1"])  # fmt: skip
    dismissed = Verdict(finding_id=dep.id, verdict=VerdictLabel.FALSE_POSITIVE, confidence=1.0,
                        memories_used=["abc"])  # fmt: skip
    assert apply_policy(dep, dismissed).verdict == VerdictLabel.NEEDS_REVIEW
    _ = Path


def test_a_dismissal_that_leaned_on_a_memory_is_not_final_for_serious_findings():
    from gapscan.agent.triage import guard_memory_use
    from gapscan.models import Verdict

    def v(label, used=("abc",)):
        return Verdict(finding_id="x", verdict=label, confidence=0.9, memories_used=list(used))

    high = finding().model_copy(update={"severity": Severity.HIGH})
    medium = finding()
    dismissed = v(VerdictLabel.FALSE_POSITIVE)
    out = guard_memory_use(high, dismissed, ["false_positive"])
    assert (
        out.verdict == VerdictLabel.NEEDS_REVIEW
        and out.confidence <= 0.5
        and "abc" in out.policy_notes[-1]
    )
    assert (
        guard_memory_use(medium, dismissed, ["false_positive"]).verdict
        == VerdictLabel.FALSE_POSITIVE
    )
    assert (
        guard_memory_use(high, dismissed, ["confirmed", "context"]).verdict
        == VerdictLabel.FALSE_POSITIVE
    )
    assert guard_memory_use(high, dismissed, []).verdict == VerdictLabel.FALSE_POSITIVE
    confirmed = v(VerdictLabel.TRUE_POSITIVE)
    assert (
        guard_memory_use(high, confirmed, ["false_positive"]).verdict == VerdictLabel.TRUE_POSITIVE
    )


def test_the_report_carries_the_memories_shown_for_a_finding(tmp_path):
    from gapscan.models import RepoSummary, Verdict
    from gapscan.report.build import build_report

    f = finding(file="a.ts")
    verdict = Verdict(finding_id=f.id, verdict=VerdictLabel.NEEDS_REVIEW, confidence=0.5, reasoning="r",
                      memories_used=["m1"], memory_notes=["[m1] note about this project: x"])  # fmt: skip
    report = build_report(ScanResult(target=str(tmp_path), findings=[f]), [verdict], RepoSummary(),
                          config=Config(), target=tmp_path)  # fmt: skip
    assert report.details[f.id].memory_notes == ["[m1] note about this project: x"]
