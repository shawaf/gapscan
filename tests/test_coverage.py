"""Coverage per target (report/coverage.py): every registered standard's controls in scope, with
the three honest statuses. A control is never reported as met."""

from __future__ import annotations

from gapscan.config import Config
from gapscan.models import Category, Finding, ScanResult, Severity, Verdict, VerdictLabel
from gapscan.owasp.packs import ASVS, MASVS, TOP10, AsvsPack, MasvsPack, Top10Pack, classify_finding
from gapscan.report.build import build_report
from gapscan.report.coverage import coverage_by_target, target_coverage


def finding(fid: str, **kw: object) -> Finding:
    base = {"id": fid, "scanner": "semgrep", "rule_id": "r", "title": "t",
            "severity": Severity.HIGH, "category": Category.CODE, "file": "a.py", "start_line": 1}  # fmt: skip
    f = Finding(**{**base, **kw})
    classify_finding(f)
    return f


def test_a_control_is_failing_checked_or_manual_and_never_passed() -> None:
    cov = target_coverage(MasvsPack(), {"MASVS-CRYPTO-1": ["f1"]})
    by_id = {c.id: c for c in cov.controls}
    assert by_id["MASVS-CRYPTO-1"].status == "evidence_of_failure"
    assert by_id["MASVS-CRYPTO-1"].finding_ids == ["f1"]
    assert by_id["MASVS-NETWORK-1"].status == "no_issue_found_by_tools"  # our rules check it
    assert by_id["MASVS-PRIVACY-3"].status == "manual_review_required"  # nothing automated can
    assert cov.total == 24 == (cov.evidence_of_failure + cov.no_issue_found_by_tools
                               + cov.manual_review_required)  # fmt: skip
    assert {c.status for c in cov.controls} <= {
        "evidence_of_failure", "no_issue_found_by_tools", "manual_review_required"}  # fmt: skip


def test_levels_limit_scope_only_for_standards_that_have_them() -> None:
    l1, l3 = target_coverage(AsvsPack(), {}, level=1), target_coverage(AsvsPack(), {}, level=3)
    assert 0 < l1.total < l3.total and l1.level == 1
    assert all(c.level == 1 for c in l1.controls)
    top = target_coverage(Top10Pack(), {}, level=1)
    assert top.total == 10 and top.level is None  # Top 10 has no levels
    assert top.no_issue_found_by_tools == 10  # every category has CWE links


def test_findings_count_once_per_control_and_land_in_their_own_standard() -> None:
    refs = [("owasp-top10", "A05:2025"), ("owasp-top10", "A05:2025"), ("owasp-asvs", "x")]
    covs = coverage_by_target([Top10Pack(), MasvsPack()], [("f1", refs)])
    top = next(c for c in covs if c.target == TOP10)
    assert next(c for c in top.controls if c.id == "A05:2025").finding_ids == ["f1"]
    assert next(c for c in covs if c.target == MASVS).evidence_of_failure == 0


def test_the_report_carries_coverage_for_every_registered_standard_and_agrees_with_asvs() -> None:
    sqli = finding("s1", cwe=["CWE-89"])
    weak = finding("k1", rule_id="gapscan.kotlin.weak-key-length", cwe=["CWE-326"], file="a.kt")
    dismissed = finding("d1", cwe=["CWE-79"], file="b.py")
    scan = ScanResult(target="/x", findings=[sqli, weak, dismissed])
    fp = Verdict(finding_id="d1", verdict=VerdictLabel.FALSE_POSITIVE, confidence=0.9)
    data = build_report(scan, [fp], None, config=Config())
    covs = {c.target: c for c in data.coverage}
    assert set(covs) == {TOP10, ASVS, MASVS}
    top = {c.id: c for c in covs[TOP10].controls}
    assert top["A05:2025"].finding_ids == ["s1"]  # the dismissed XSS is not open, so not a gap
    assert {c.id: c for c in covs[MASVS].controls}["MASVS-CRYPTO-1"].finding_ids == ["k1"]
    # The generic ASVS coverage gives exactly the statuses of the ASVS page.
    assert data.asvs is not None
    asvs_page = {r.id: r.status for r in data.asvs.requirements}
    assert {c.id: c.status for c in covs[ASVS].controls} == asvs_page
    assert covs[ASVS].total == data.asvs.total and covs[ASVS].level == data.asvs.level
