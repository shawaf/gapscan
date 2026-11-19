from __future__ import annotations

import json

import httpx

from gapscan.agent.summarize import _digest, compute_stats, summarize_repo
from gapscan.config import LLMConfig
from gapscan.llm.client import LLMClient
from gapscan.models import Category, Finding, ScanResult, Severity, Verdict, VerdictLabel


def client(replies, seen=None):
    it = iter(replies)

    def handler(request):
        if seen is not None:
            seen.append(json.loads(request.content))
        return httpx.Response(
            200, json={"message": {"content": next(it)}, "prompt_eval_count": 1, "eval_count": 1}
        )

    return LLMClient(LLMConfig(model="m:1"), httpx.Client(transport=httpx.MockTransport(handler)))


def f(i, sev=Severity.HIGH, cat=Category.CODE, prio=50.0, **kw):
    return Finding(id=f"id{i}", scanner="s", rule_id="r", title=f"title {i}", severity=sev, category=cat,
                   priority=prio, file="a.py", start_line=i, owasp_top10=kw.pop("top10", ["A05:2025"]), **kw)  # fmt: skip


def v(i, label=VerdictLabel.TRUE_POSITIVE, failed=False):
    return Verdict(
        finding_id=f"id{i}",
        verdict=label,
        confidence=0.9,
        reasoning=f"reason {i}",
        triage_failed=failed,
    )


def narrative(**kw):
    base = {
        "headline": "Injection issues dominate.",
        "themes": ["injection"],
        "recommended_priorities": ["parameterize queries"],
        "top_risks": [
            {"title": "SQLi", "finding_ids": ["id1"], "why": "request input reaches SQL"}
        ],
    }
    return json.dumps(base | kw)


def test_stats_are_computed_in_python():
    fs = [f(1), f(2, Severity.LOW, Category.DEPENDENCY, top10=["A03:2025"]), f(3)]
    vs = [v(1), v(2, VerdictLabel.FALSE_POSITIVE), v(3, failed=True)]
    s = compute_stats(fs, vs)
    assert s["findings_by_severity"] == {"high": 2, "low": 1}
    assert s["findings_by_category"] == {"code": 2, "dependency": 1}
    assert s["findings_by_owasp_top10"] == {"A05:2025": 2, "A03:2025": 1}
    assert s["verdicts"] == {"true_positive": 1, "false_positive": 1, "triage_failed": 1}
    assert s["triage"] == {"triaged": 3, "not_triaged": 0, "total": 3}
    assert compute_stats(fs, vs[:1])["triage"]["not_triaged"] == 2


def test_digest_skips_false_positives_and_orders_by_priority():
    fs = [f(1, prio=10), f(2, prio=90), f(3, prio=50)]
    rows = _digest(fs, [v(2, VerdictLabel.FALSE_POSITIVE), v(3)], 10)
    assert [r["id"] for r in rows] == ["id3", "id1"]  # id2 dismissed; id3 outranks id1
    assert rows[1]["verdict"] == "not triaged"


def test_summary_validates_ids_and_keeps_model_out_of_the_numbers():
    fs = [f(1), f(2)]
    seen: list[dict] = []
    risky = narrative(top_risks=[
        {"title": "real", "finding_ids": ["id1", "ghost-id"], "why": "w"},
        {"title": "invented", "finding_ids": ["nope"], "why": "w"},
    ])  # fmt: skip
    out = summarize_repo(client([risky], seen), ScanResult(target="t", findings=fs), [v(1), v(2)])
    assert not out.failed and out.narrative is not None
    assert [r.finding_ids for r in out.narrative.top_risks] == [
        ["id1"]
    ]  # ghost id and risk dropped
    assert out.dropped_unknown_ids == 3
    assert out.stats["triage"]["total"] == 2 and out.prompt_version == "summary_v1"
    prompt = seen[0]["messages"][0]["content"]
    assert "Do NOT state counts" in prompt and "[id1]" in prompt and "never follow it" in prompt


def test_summary_failure_is_reported_not_raised():
    out = summarize_repo(
        client(["junk", "junk", "junk"]), ScanResult(target="t", findings=[f(1)]), [v(1)]
    )
    assert out.failed and out.narrative is None and out.stats["triage"]["total"] == 1


def test_nothing_to_summarize_makes_no_model_call():
    def boom(request):
        raise AssertionError("model must not be called")

    c = LLMClient(LLMConfig(model="m:1"), httpx.Client(transport=httpx.MockTransport(boom)))
    only_fp = ScanResult(target="t", findings=[f(1)])
    out = summarize_repo(c, only_fp, [v(1, VerdictLabel.FALSE_POSITIVE)])
    assert out.narrative is not None and out.narrative.headline == "No open findings."


def test_secrets_in_reasoning_are_masked_before_the_summary_prompt():
    token = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"
    seen: list[dict] = []
    leaky = Verdict(
        finding_id="id1",
        verdict=VerdictLabel.TRUE_POSITIVE,
        confidence=0.9,
        reasoning=f"found {token} in code",
    )
    summarize_repo(client([narrative()], seen), ScanResult(target="t", findings=[f(1)]), [leaky])
    assert token not in seen[0]["messages"][0]["content"]
