from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from gapscan.config import Config
from gapscan.models import (
    Category,
    Finding,
    RepoSummary,
    ScanResult,
    Severity,
    Verdict,
    VerdictLabel,
)
from gapscan.report.build import build_report
from gapscan.report.dashboard import PLACEHOLDER, TemplateMissing, embed_json, render_dashboard
from gapscan.report.decisions import Decision, Decisions, load_decisions
from gapscan.report.risk import K, compute_score, finding_points, grade_for
from gapscan.report.schema import ReportData

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "tests" / "data" / "report"
TARGET = ROOT / "eval" / "fixtures" / "vuln-app"


def inputs():
    scan = ScanResult.model_validate_json((FIXTURE_DIR / "scan.json").read_text())
    tri = json.loads((FIXTURE_DIR / "triage.json").read_text())
    verdicts = [Verdict.model_validate(v) for v in tri["verdicts"]]
    summary = RepoSummary.model_validate(tri["summary"]) if tri.get("summary") else None
    return scan, verdicts, summary


def report(**kw) -> ReportData:
    scan, verdicts, summary = inputs()
    return build_report(scan, verdicts, summary, config=Config(), target=TARGET, **kw)


def f(i=1, sev=Severity.HIGH, cat=Category.CODE, **kw):
    return Finding(
        id=f"id{i}", scanner="s", rule_id="r", title=f"t{i}", severity=sev, category=cat, **kw
    )


def v(i=1, label=VerdictLabel.TRUE_POSITIVE, conf=1.0, **kw):
    return Verdict(finding_id=f"id{i}", verdict=label, confidence=conf, **kw)


# --- risk score ------------------------------------------------------------------------


def test_score_formula_is_exactly_what_the_docs_say():
    one = compute_score([f(1, Severity.CRITICAL)], {"id1": v(1, conf=1.0)})
    assert one.raw_points == 10.0 and one.value == round(100 * (1 - math.exp(-10 / K)), 1) == 22.1
    assert one.grade == "C" and len(one.explanation) == 5
    # not reviewed: x0.6; likely_true_positive at confidence 0.5: x0.7 x 0.75
    assert finding_points(f(1, Severity.HIGH), None) == pytest.approx(3.0)
    assert finding_points(
        f(1, Severity.HIGH), v(1, VerdictLabel.LIKELY_TRUE_POSITIVE, 0.5)
    ) == pytest.approx(5 * 0.7 * 0.75)


def test_dismissed_findings_and_false_positives_score_zero_and_score_is_monotonic_and_bounded():
    fp = v(1, VerdictLabel.FALSE_POSITIVE, 0.9)
    assert finding_points(f(1), fp) == 0.0 and finding_points(f(1), v(1), dismissed=True) == 0.0
    scores = [
        compute_score([f(i, Severity.CRITICAL) for i in range(n)], {}).value
        for n in (0, 1, 5, 20, 200)
    ]
    assert scores[0] == 0.0 and scores == sorted(scores) and scores[-1] <= 100.0
    assert [grade_for(x) for x in (0, 7.9, 8, 17.9, 18, 39.9, 40, 64.9, 65, 100)] == list(
        "AABBCCDDFF"
    )


def test_modifiers_exposure_test_code_secrets_epss_and_kev():
    base = finding_points(f(1, Severity.MEDIUM), None)
    assert finding_points(f(1, Severity.MEDIUM, internet_facing=True), None) == pytest.approx(
        base * 1.25
    )
    assert finding_points(f(1, Severity.MEDIUM, is_test_code=True), None) == pytest.approx(
        base * 0.4
    )
    assert finding_points(f(1, Severity.MEDIUM, is_vendor_code=True), None) == pytest.approx(
        base * 0.2
    )
    assert finding_points(f(1, Severity.MEDIUM, cat=Category.SECRET), None) == pytest.approx(
        base * 1.5
    )
    dep = f(1, Severity.LOW, cat=Category.DEPENDENCY)
    assert finding_points(dep.model_copy(update={"epss": 0.5}), None) == pytest.approx(
        finding_points(dep, None) * 1.5
    )
    assert finding_points(dep.model_copy(update={"kev": True}), None) == pytest.approx(
        10 * 0.6
    )  # KEV = critical


def test_model_can_lower_severity_but_a_kev_vulnerability_stays_critical():
    lowered = v(1, severity_adjusted=Severity.LOW)
    assert finding_points(f(1, Severity.CRITICAL), lowered) == pytest.approx(0.5)
    assert finding_points(f(1, Severity.CRITICAL, kev=True), lowered) == pytest.approx(10.0)


# --- report assembly -------------------------------------------------------------------


def test_counts_are_consistent_and_computed_in_python():
    r = report()
    c = r.counts
    assert c.total == len(r.findings) == 67
    assert c.open + c.dismissed == c.total and c.open == sum(1 for x in r.findings if x.open)
    assert sum(c.by_severity.values()) == c.open and sum(c.by_category.values()) == c.open
    assert c.llm_triaged == 40 and c.not_triaged == 27
    assert r.score.raw_points == pytest.approx(sum(x.points for x in r.score.components))
    assert 0 < r.score.value <= 100 and r.score.grade in "ABCDF"


def test_findings_are_ranked_by_risk_and_top_risks_are_open_findings():
    r = report()
    assert len(r.top_risks) == 10
    open_ids = {x.id for x in r.findings if x.open}
    assert all(t.finding_id in open_ids for t in r.top_risks)
    assert [t.finding_id for t in r.top_risks] == [x.id for x in r.findings if x.open][:10]
    assert all(t.why for t in r.top_risks)


def test_every_owasp_category_is_listed_with_cheatsheet_links():
    r = report()
    assert [c.id for c in r.owasp] == [f"A{i:02d}:2025" for i in range(1, 11)]
    a05 = next(c for c in r.owasp if c.id == "A05:2025")
    assert a05.name == "Injection" and a05.finding_ids and a05.cheatsheets
    assert all(
        x["url"].startswith("https://cheatsheetseries.owasp.org/")
        for c in r.owasp
        for x in c.cheatsheets
    )
    ids = {x.id for x in r.findings}
    assert all(i in ids for c in r.owasp for i in c.finding_ids)


def test_details_have_flagged_code_and_labeled_model_text():
    r = report()
    sqli = next(
        x for x in r.findings if x.file == "app.py" and x.start_line == 16 and x.category == "code"
    )
    d = r.details[sqli.id]
    assert d.language == "python" and d.function == "user"
    flagged = [line for line in d.code if line[2]]
    assert flagged and flagged[0][0] == 16 and "execute" in flagged[0][1]
    assert d.reasoning and d.scanner_messages and d.model
    assert d.untrusted_sources and d.untrusted_sources[0]["kind"] == "http_param"


def test_dependencies_upgrade_plan_and_sbom():
    r = report()
    deps = r.dependencies
    assert deps.packages and deps.sbom_available
    assert deps.upgrade_plan == sorted(
        deps.upgrade_plan, key=lambda s: (-s.kev, -s.risk_points, s.package)
    )
    assert all(s.to_version and s.resolves > 0 for s in deps.upgrade_plan)
    names = {(row.name, row.vulnerable) for row in deps.sbom}
    assert ("lodash", True) in names
    lodash = next(row for row in deps.sbom if row.name == "lodash")
    assert lodash.direct is True and lodash.ecosystem == "npm"
    assert {p.reachability for p in deps.packages} <= {
        "unknown",
        "imported",
        "not_imported_directly",
    }


def test_asvs_coverage_is_honest_about_manual_review():
    r = report()
    a = r.asvs
    assert a and a.level == 2 and a.total == len(a.requirements)
    assert a.evidence_of_failure + a.no_issue_found_by_tools + a.manual_review_required == a.total
    assert a.manual_review_required > 0 and a.evidence_of_failure > 0
    assert a.tool_verifiable_pct + a.manual_pct == pytest.approx(100.0, abs=0.2)
    assert all(q.finding_ids for q in a.requirements if q.status == "evidence_of_failure")
    assert all(not q.finding_ids for q in a.requirements if q.status != "evidence_of_failure")
    assert "not evidence" in a.note and all(q.level <= 2 for q in a.requirements)


def test_hotspots_and_stats_come_from_the_files():
    r = report()
    assert (
        r.stats.files_scanned >= 2
        and r.stats.loc_total > 20
        and "python" in r.stats.loc_by_language
    )
    top = r.hotspots[0]
    assert top.file == "app.py" and top.risk > 0 and top.findings > 0 and top.loc > 10


def test_decisions_remove_findings_from_the_score_and_carry_over():
    base = report()
    victim = base.top_risks[0].finding_id
    d = Decisions(
        decisions=[
            Decision(finding_id=victim, decision="accepted_risk", note="behind VPN", by="me")
        ]
    )
    after = report(decisions=d)
    row = next(x for x in after.findings if x.id == victim)
    assert row.decision == "accepted_risk" and not row.open
    assert (
        after.counts.dismissed == base.counts.dismissed + 1 and after.score.value < base.score.value
    )
    assert victim not in {t.finding_id for t in after.top_risks}


def test_decisions_file_roundtrip_and_version_check(tmp_path):
    p = tmp_path / "gapscan-decisions.json"
    p.write_text(
        Decisions(decisions=[Decision(finding_id="x", decision="fixed")]).model_dump_json()
    )
    assert load_decisions(p).by_id()["x"].decision == "fixed"
    assert (
        load_decisions(tmp_path / "missing.json").decisions == []
        and load_decisions(None).decisions == []
    )
    p.write_text('{"version": 99, "decisions": []}')
    with pytest.raises(ValueError, match="version"):
        load_decisions(p)


def test_baseline_comparison_new_fixed_unchanged():
    from gapscan.report.build import PreviousRun

    scan, verdicts, summary = inputs()
    open_ids = [x.id for x in report().findings if x.open]
    prev = PreviousRun(
        {i: (f"t{i}", "a.py:1") for i in open_ids[5:]} | {"gone": ("Old bug", "old.py:1")},
        "2026-09-01T00:00:00Z",
        40.0,
    )
    r = build_report(scan, verdicts, summary, config=Config(), target=TARGET, baseline=prev)
    b = r.baseline
    assert (
        b and b.fixed == 1 and b.fixed_titles[0]["title"] == "Old bug" and b.previous_score == 40.0
    )
    assert b.new == 5 and b.unchanged == len(open_ids) - 5 and b.new + b.unchanged == r.counts.open
    assert {x.status for x in r.findings} == {"new", "unchanged"}
    assert report().baseline is None and {x.status for x in report().findings} == {None}


def test_load_previous_from_a_scan_file_and_from_a_report_file(tmp_path):
    from gapscan.report.build import load_previous

    from_scan = load_previous(FIXTURE_DIR / "scan.json")
    assert len(from_scan.items) == 67 and from_scan.score is None
    rep = report()
    p = tmp_path / "report.json"
    p.write_text(rep.model_dump_json())
    from_report = load_previous(p)
    assert from_report.score == rep.score.value and set(from_report.items) == {
        x.id for x in rep.findings if x.open
    }
    assert from_report.created_at == rep.meta.scan_created_at


def test_freshness_flags_stale_vulnerability_data():
    scan, verdicts, summary = inputs()
    stale = scan.model_copy(update={"vuln_data": {"epss": "2020-01-01"}})
    r = build_report(stale, verdicts, summary, config=Config(), target=None)
    assert r.freshness.stale and r.freshness.vuln_data_age_days > 365
    assert (
        r.freshness.owasp["OWASP Top 10"] == "2025" and r.freshness.owasp["OWASP ASVS"] == "5.0.0"
    )
    assert r.freshness.model and r.freshness.prompt_versions


def test_no_secret_values_anywhere_in_the_report():
    blob = report().model_dump_json()
    for secret in ("ghp_aB3dE5", "AKIAJ3XK7QW2", "wJ8nQ2xLm4Rt"):
        assert secret not in blob
    assert "/Users/" not in blob  # no absolute paths from the scanning machine


def test_limitations_are_stated_and_json_roundtrips():
    r = report()
    assert len(r.limitations) >= 4 and any("business logic" in x for x in r.limitations)
    assert ReportData.model_validate_json(r.model_dump_json()).score.value == r.score.value


def test_report_without_triage_still_builds():
    scan, _, _ = inputs()
    r = build_report(scan, [], None, config=Config(), target=TARGET)
    assert r.counts.llm_triaged == 0 and r.counts.not_triaged == 67 and r.narrative is None
    assert all(x.verdict == "not_triaged" for x in r.findings)
    # No model ran, so the report names none (it used to name the configured model, and the UI then
    # labeled scanner text as "AI-generated" by that model).
    assert r.freshness.model == ""


# --- embedding -------------------------------------------------------------------------


def test_embed_json_cannot_break_out_of_the_script_element():
    nasty = json.dumps({"x": "</script><script>alert(1)</script><!-- \u2028"})
    safe = embed_json(nasty)
    assert "</script>" not in safe and "<!--" not in safe and "\u2028" not in safe
    assert json.loads(safe)["x"].startswith("</script>")  # round-trips for the page's JSON.parse


def test_render_dashboard_injects_one_data_block():
    r = report()
    html = render_dashboard(r, f"<html><body>{PLACEHOLDER}<div id=app></div></body></html>")
    assert html.count('id="gapscan-data"') == 1 and PLACEHOLDER not in html
    blob = html.split('type="application/json">', 1)[1].split("</script>", 1)[0]
    assert json.loads(blob)["meta"]["project"] == "vuln-app"
    with pytest.raises(TemplateMissing):
        render_dashboard(r, "<html>no placeholder</html>")


def test_freshness_shows_the_installed_bundle_and_uses_its_snapshot_dates(tmp_path):
    scan, verdicts, summary = inputs()
    (tmp_path / "bundle-state.json").write_text(
        json.dumps(
            {
                "bundle_created_at": "2026-10-03T08:00:00Z",
                "snapshots": {"osv_db": "2026-10-03", "epss": "2026-10-02"},
            }
        )
    )
    cfg = Config(
        data={"dir": str(tmp_path)},
        scanners={
            "osv": {"db_dir": str(tmp_path / "o")},
            "trivy": {"cache_dir": str(tmp_path / "t")},
        },
    )
    r = build_report(
        scan.model_copy(update={"vuln_data": {"epss": "2026-10-01"}}),
        verdicts,
        summary,
        config=cfg,
        target=None,
    )
    assert r.freshness.bundle == "2026-10-03"
    assert r.freshness.vuln_data["osv_db"] == "2026-10-03"  # filled in from the bundle
    assert r.freshness.vuln_data["epss"] == "2026-10-01"  # what the scan recorded wins
    assert (
        build_report(
            scan,
            verdicts,
            summary,
            config=Config(data={"dir": str(tmp_path / "none")}),
            target=None,
        ).freshness.bundle
        == ""
    )
