from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from gapscan.config import Config
from gapscan.evaluation import benchmark as bench
from gapscan.evaluation.labels import Label, compatible, finding_truth, load_labels
from gapscan.evaluation.metrics import TriageItem, check_targets, scanner_metrics, triage_metrics
from gapscan.evaluation.runner import headline, result_path, run_fixtures
from gapscan.evaluation.targets import Target, fetch_target, is_fetched, load_targets
from gapscan.models import Category, Finding, Severity, Verdict, VerdictLabel

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "eval" / "fixtures" / "labeled"


def finding(file="a.py", line=10, cwe=("CWE-89",), owasp=("A05:2025",), **kw):
    return Finding(id=kw.pop("id", f"{file}:{line}:{cwe}"), scanner="s", rule_id="r", title="t", severity=Severity.HIGH,
                   category=Category.CODE, cwe=list(cwe), owasp_top10=list(owasp), file=file, start_line=line, end_line=line, **kw)  # fmt: skip


def verdict(label, fid="x", conf=0.9, **kw):
    return Verdict(finding_id=fid, verdict=label, confidence=conf, **kw)


V, FP, NR = VerdictLabel.TRUE_POSITIVE, VerdictLabel.FALSE_POSITIVE, VerdictLabel.NEEDS_REVIEW

# --- fixtures and labels -------------------------------------------------------------------


def test_labeled_fixtures_are_consistent_and_hint_free():
    labels = load_labels(FIXTURES)
    assert len(labels) >= 60 and len({lb.id for lb in labels}) == len(labels)
    vulnerable = [lb for lb in labels if lb.vulnerable]
    assert 30 <= len(vulnerable) < len(labels) and any(lb.kind == "injection" for lb in labels)
    for lb in labels:
        text = (FIXTURES / lb.file).read_text().splitlines()
        assert 1 <= lb.line <= len(text), lb.id
    # every labeled weakness class has both vulnerable and safe examples (except one-offs)
    for cwe in ("CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-502", "CWE-327", "CWE-798", "CWE-918"):
        assert {lb.vulnerable for lb in labels if lb.cwe == cwe} == {True, False}, cwe
    # No comment may tell the reviewer the answer, except the deliberate injection attempts.
    for lb in labels:
        if lb.kind == "injection":
            continue
        # a real API name (Go's InsecureSkipVerify) is not a hint about the answer
        body = (FIXTURES / lb.file).read_text().lower().replace("insecureskipverify", "")
        assert "vulnerable" not in body and "insecure" not in body and "not safe" not in body, (
            lb.file
        )


def test_finding_truth_matches_by_location_and_compatible_weakness():
    labels = [Label("v", "a.py", 10, "CWE-89", "A05:2025", True, "standard"),
              Label("b", "b.py", 5, "CWE-89", "A05:2025", False, "bait")]  # fmt: skip
    assert finding_truth(finding("a.py", 12), labels).vulnerable  # within tolerance
    assert (
        not finding_truth(finding("a.py", 40), labels).vulnerable
        and finding_truth(finding("a.py", 40), labels).kind == "stray"
    )
    assert not finding_truth(
        finding("a.py", 10, cwe=("CWE-20",), owasp=("A06:2025",)), labels
    ).vulnerable  # unrelated weakness
    assert not finding_truth(
        finding("a.py", 10, cwe=("CWE-564",), owasp=("A05:2025",)), labels
    ).vulnerable  # sharing only an OWASP category is not the same weakness
    safe = finding_truth(finding("b.py", 5), labels)
    assert not safe.vulnerable and safe.site == "b" and safe.kind == "bait"
    assert compatible(labels[0], finding(cwe=("CWE-89",), owasp=()))


def test_scanner_metrics_recall_precision_and_buckets():
    labels = [Label("v1", "a.py", 10, "CWE-89", "A05:2025", True, "standard"),
              Label("v2", "a.py", 50, "CWE-78", "A05:2025", True, "standard"),
              Label("s1", "b.py", 5, "CWE-89", "A05:2025", False, "bait"),
              Label("s2", "c.py", 5, "CWE-79", "A05:2025", False, "bait")]  # fmt: skip
    findings = [
        finding("a.py", 10, id="f1"),
        finding("b.py", 5, id="f2"),
        finding("zzz.py", 1, id="f3"),
    ]
    m = scanner_metrics(findings, labels)
    assert m["recall"] == 0.5 and m["detected_sites"] == 1 and m["missed"] == ["v2"]
    assert (
        m["findings"] == 3
        and m["findings_vulnerable"] == 1
        and m["finding_precision"] == pytest.approx(0.333, abs=0.001)
    )
    assert m["safe_sites_flagged"] == 1 and m["recall_by_cwe"]["CWE-78"]["rate"] == 0.0  # type: ignore[index]
    assert m["detection_by_owasp"]["A05:2025"]["detected"] == 1  # type: ignore[index]


# --- triage metrics ------------------------------------------------------------------------


def test_triage_metrics_definitions():
    items = [
        TriageItem("1", True, verdict(V)),  # real, kept
        TriageItem("2", True, verdict(VerdictLabel.LIKELY_TRUE_POSITIVE)),  # real, kept
        TriageItem("3", True, verdict(FP)),  # real, wrongly dismissed
        TriageItem("4", False, verdict(FP)),  # false alarm removed
        TriageItem("5", False, verdict(FP)),  # removed
        TriageItem("6", False, verdict(V)),  # false alarm kept as real
        TriageItem("7", False, verdict(NR)),  # undecided
        TriageItem("8", True, verdict(V, triage_failed=True)),  # model failed: excluded, counted
        TriageItem("9", True, None),  # not triaged: excluded
    ]
    m = triage_metrics(items)
    assert m["triaged"] == 7 and m["failed"] == 1
    assert m["accuracy"] == pytest.approx(4 / 7, abs=0.001)  # 1,2 kept + 4,5 removed
    assert m["baseline_confirm_all_accuracy"] == pytest.approx(
        3 / 7, abs=0.001
    )  # "confirm everything" gets only the 3 real ones
    assert m["decisive_accuracy"] == pytest.approx(4 / 6, abs=0.001)  # undecided excluded
    assert (
        m["true_positives_kept"] == pytest.approx(2 / 3, abs=0.001)
        and m["true_positives_dismissed_count"] == 1
    )
    assert (
        m["false_positive_reduction"] == pytest.approx(2 / 4, abs=0.001)
        and m["false_positives_kept_as_real"] == 1
    )
    assert m["undecided"] == 1


def test_unlabeled_findings_are_reported_not_judged():
    items = [TriageItem("1", True, verdict(V)), TriageItem("2", False, verdict(FP)),
             TriageItem("3", False, verdict(V), "stray"), TriageItem("4", False, verdict(FP), "stray")]  # fmt: skip
    m = triage_metrics(items)
    assert m["triaged"] == 2 and m["accuracy"] == 1.0  # strays do not count either way
    assert m["unlabeled_reviewed"] == 2 and m["unlabeled_confirmed"] == 1


def test_label_matching_accepts_a_rule_that_names_the_weakness():
    label = Label("y", "a.py", 9, "CWE-502", "A08:2025", True, "standard")
    bandit_yaml = Finding(id="1", scanner="bandit", rule_id="B506", title="yaml load", severity=Severity.MEDIUM,
                          category=Category.CODE, cwe=["CWE-20"], owasp_top10=["A05:2025"], file="a.py", start_line=9)  # fmt: skip
    assert compatible(
        label, bandit_yaml
    )  # tagged CWE-20 by Bandit, but it is the yaml.load finding
    best_practice = bandit_yaml.model_copy(
        update={
            "rule_id": "requests.use-raise-for-status",
            "title": "missing raise_for_status",
            "cwe": [],
        }
    )
    assert not compatible(
        label, best_practice
    )  # a neighbouring best-practice rule is not the weakness


def test_injection_resistance_and_tokens():
    items = [
        TriageItem(
            "a", True, verdict(V, tokens=1000, seconds=4.0), "injection"
        ),  # resisted (still confirmed)
        TriageItem(
            "b", True, verdict(FP, tokens=3000, seconds=8.0), "injection"
        ),  # fooled into dismissing
        TriageItem("c", False, verdict(FP, tokens=2000, seconds=6.0), "injection"),
    ]  # resisted
    m = triage_metrics(items)
    assert (
        m["injection_cases"] == 3
        and m["injection_resisted"] == 2
        and m["injection_resistance"] == pytest.approx(0.667, abs=0.001)
    )
    assert m["mean_tokens"] == 2000 and m["mean_seconds"] == 6.0 and m["total_seconds"] == 18.0


def test_empty_triage_has_no_division_by_zero():
    m = triage_metrics([])
    assert (
        m["accuracy"] is None and m["false_positive_reduction"] is None and m["mean_tokens"] is None
    )
    assert check_targets(m)["all_pass"] is None


def test_target_checks_pass_and_fail():
    ok = check_targets(
        {
            "decisive_accuracy": 0.85,
            "false_positive_reduction": 0.5,
            "true_positives_dismissed": 0.02,
        }
    )
    assert ok["all_pass"] is True
    bad = check_targets(
        {
            "decisive_accuracy": 0.79,
            "false_positive_reduction": 0.5,
            "true_positives_dismissed": 0.06,
        }
    )
    assert (
        bad["triage_accuracy_ge_80"] is False
        and bad["tp_dismissed_lt_5"] is False
        and bad["all_pass"] is False
    )


# --- OWASP Benchmark scorecard -------------------------------------------------------------


CSV = """# test name, category, real vulnerability, cwe, Benchmark version: 1.2, 2016-06-1
BenchmarkTest00001,sqli,true,89
BenchmarkTest00002,sqli,true,89
BenchmarkTest00003,sqli,false,89
BenchmarkTest00004,sqli,false,89
BenchmarkTest00005,hash,true,328
BenchmarkTest00006,hash,false,328
"""


def test_scorecard_tpr_fpr_and_youden_score(tmp_path):
    p = tmp_path / "expected.csv"
    p.write_text(CSV)
    cases = bench.load_expected(p)
    assert (
        len(cases) == 6
        and cases["BenchmarkTest00001"].real
        and not cases["BenchmarkTest00003"].real
    )
    fs = [
        finding("org/BenchmarkTest00001.java", cwe=("CWE-89",)),
        finding("org/BenchmarkTest00003.java", cwe=("CWE-564",)),
        finding("org/BenchmarkTest00005.java", cwe=("CWE-327",)),
        finding("org/BenchmarkTest00006.java", cwe=("CWE-79",)),  # wrong class
        finding("org/Helper.java", cwe=("CWE-89",)),
    ]  # not a test file
    flagged = bench.flagged_cases(fs, cases)
    assert set(flagged) == {"BenchmarkTest00001", "BenchmarkTest00003", "BenchmarkTest00005"}
    sc = bench.scorecard(set(flagged), cases)
    sqli = sc["categories"]["sqli"]  # type: ignore[index]
    assert (sqli["tpr"], sqli["fpr"], sqli["score"]) == (0.5, 0.5, 0.0)
    assert sc["categories"]["hash"]["score"] == 1.0  # type: ignore[index]  # flagged the real one, not the fake one
    assert (
        sc["overall"]["real"] == 3
        and sc["overall"]["fake"] == 3
        and sc["overall"]["tpr"] == pytest.approx(0.667, abs=0.001)
    )  # type: ignore[index]


def test_benchmark_sample_is_reproducible_balanced_and_bounded(tmp_path):
    p = tmp_path / "e.csv"
    rows = [f"BenchmarkTest{i:05d},sqli,{'true' if i % 2 else 'false'},89" for i in range(1, 41)]
    p.write_text("\n".join(rows))
    cases = bench.load_expected(p)
    flagged = {
        c.name: [finding(f"x/{c.name}.java", priority=float(i))]
        for i, c in enumerate(cases.values())
    }  # type: ignore[arg-type]
    a = bench.triage_sample(flagged, cases, 3)
    b = bench.triage_sample(flagged, cases, 3)
    assert [x[1].name for x in a] == [x[1].name for x in b] and len(a) == 6
    assert sum(c.real for _, c in a) == 3  # 3 real + 3 fake per category


# --- pinned targets ------------------------------------------------------------------------


def test_targets_are_pinned_to_full_commits_with_licenses():
    targets = load_targets(ROOT / "eval" / "targets.toml")
    assert set(targets) >= {"benchmark-java", "juice-shop", "nodegoat"}
    for t in targets.values():
        assert len(t.sha) == 40 and all(c in "0123456789abcdef" for c in t.sha) and t.license
    assert (
        targets["benchmark-java"].license == "GPL-2.0"
        and targets["benchmark-java"].truth == "benchmark-csv"
    )
    assert (
        "never" in (ROOT / "eval" / "targets.toml").read_text().lower()
    )  # the GPL warning is present


def test_fetch_rejects_a_commit_that_does_not_match_the_pin(tmp_path, monkeypatch):
    import gapscan.evaluation.targets as t

    calls = []

    def fake_git(args, cwd, timeout=900):
        calls.append(args[0])
        return "deadbeef" * 5 if args[0] == "rev-parse" else ""

    monkeypatch.setattr(t, "_git", fake_git)
    target = Target(
        name="x",
        repo="https://example.com/x.git",
        ref="v1",
        sha="a" * 40,
        license="MIT",
        language="py",
        truth="none",
    )
    with pytest.raises(RuntimeError, match="pin"):
        fetch_target(tmp_path, target)
    assert not is_fetched(tmp_path, target)


# --- runner (scripted model, real scanners) ------------------------------------------------


needs_scanners = pytest.mark.skipif(
    not all(__import__("shutil").which(b) for b in ("semgrep", "bandit"))
    or not (ROOT / "data" / "semgrep-rules").is_dir(),
    reason="scanners or rules not installed",
)


@needs_scanners
def test_fixture_run_end_to_end_with_a_scripted_model(tmp_path, monkeypatch):
    from gapscan.llm.client import LLMClient

    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        body = json.loads(request.content)
        prompt = body["messages"][0]["content"]
        # a scripted reviewer: parameterized/escaped/constant code is "false_positive", the rest real
        safe_markers = (
            "?",
            "escape",
            "safe_load",
            "textContent",
            "prepareStatement",
            "SecureRandom",
            "environ[",
        )
        verdict = "false_positive" if any(m in prompt for m in safe_markers) else "true_positive"
        answer = {
            "action": "final",
            "answer": {"verdict": verdict, "confidence": 0.9, "reasoning": "scripted"},
        }
        return httpx.Response(
            200,
            json={
                "message": {"content": json.dumps(answer)},
                "prompt_eval_count": 100,
                "eval_count": 20,
            },
        )

    cfg = Config(
        data={"dir": str(tmp_path)}, llm={"model": "scripted:1b"}, agent={"use_tools": True}
    )
    client = LLMClient(cfg.llm, httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.chdir(ROOT)
    out = run_fixtures(cfg, FIXTURES, triage=True, client=client)
    assert out["scanner"]["recall"] > 0.6 and out["scanner"]["findings"] > 50  # Dart: no rules
    t = out["triage"]
    assert (
        t["triaged"] + t["unlabeled_reviewed"] == out["scanner"]["findings"]
    )  # strays reported separately
    # code rules decide some findings without the model (weak algorithms, provable noise)
    assert 0 < calls["n"] < out["scanner"]["findings"] and calls["n"] > 100
    assert 0 < t["mean_tokens"] <= 120 and t["cached"] == 0
    assert set(out["checks"]) >= {
        "triage_accuracy_ge_80",
        "fp_reduction_ge_30",
        "tp_dismissed_lt_5",
        "all_pass",
    }
    assert out["models"] == ["gapscan-rules", "scripted:1b"] and out["triage_by_cwe"]
    assert headline({"results": {"fixtures": out}})["fixtures.recall"] == out["scanner"]["recall"]


def test_result_files_are_named_by_date_and_model(tmp_path):
    r = {"meta": {"date": "2026-10-02T10:00:00Z", "models": ["qwen3-coder:30b"]}}
    assert result_path(tmp_path, r) == tmp_path / "2026-10-02-qwen3-coder_30b.json"


def test_language_breakdown_shows_a_weak_language_that_the_average_hides():
    from gapscan.evaluation.labels import Label
    from gapscan.evaluation.metrics import language_breakdown, language_of, scanner_metrics
    from gapscan.models import Category, Finding, Severity

    assert language_of("kotlin/A.kt") == "kotlin" and language_of("loose.py") == "(none)"
    labels = [
        Label("py-1", "python/a.py", 5, "CWE-89", "A05:2025", True, "standard"),
        Label("py-2", "python/b.py", 5, "CWE-89", "A05:2025", False, "bait"),
        Label("dart-1", "dart/a.dart", 5, "CWE-89", "A05:2025", True, "standard"),
    ]
    found = Finding(scanner="s", rule_id="sql-injection", title="SQL injection", severity=Severity.HIGH,
                    category=Category.CODE, file="python/a.py", start_line=5, cwe=["CWE-89"])  # fmt: skip
    m = scanner_metrics([found], labels)
    by = m["recall_by_language"]
    assert by["python"]["recall"] == 1.0 and by["python"]["precision"] == 1.0
    assert by["dart"]["recall"] == 0.0 and by["dart"]["findings"] == 0
    assert by["python"]["false_alarm_rate"] == 0.0
    assert m["recall"] == 0.5  # the average hides that Dart has no coverage at all
    assert language_breakdown  # public helper


def test_triage_in_an_evaluation_needs_a_provider_from_the_caller(tmp_path, monkeypatch):
    """The engine never builds an LLM client itself (ARCHITECTURE.md section 4)."""
    from gapscan.evaluation import runner
    from gapscan.models import ScanResult

    monkeypatch.setattr(runner, "_scan", lambda cfg, d, p: (ScanResult(target=str(d)), 0.0))
    with pytest.raises(ValueError, match="LLM provider"):
        run_fixtures(Config(data={"dir": str(tmp_path)}), FIXTURES, triage=True, client=None)
