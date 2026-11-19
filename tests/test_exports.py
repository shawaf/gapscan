from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gapscan.cli import app
from gapscan.config import Config
from gapscan.models import Category, Finding, RepoSummary, ScanResult, Severity, Verdict
from gapscan.report.build import build_report
from gapscan.report.dashboard import TEMPLATE_PATH, render_dashboard
from gapscan.report.decisions import Decision, Decisions
from gapscan.report.exports import asvs_csv, findings_csv, markdown_summary, to_sarif, write_exports

ROOT = Path(__file__).resolve().parent.parent
D = ROOT / "tests" / "data" / "report"


def load():
    scan = ScanResult.model_validate_json((D / "scan.json").read_text())
    tri = json.loads((D / "triage.json").read_text())
    verdicts = [Verdict.model_validate(v) for v in tri["verdicts"]]
    summary = RepoSummary.model_validate(tri["summary"])
    return scan, verdicts, summary


@pytest.fixture(scope="module")
def data_and_scan():
    scan, verdicts, summary = load()
    data = build_report(
        scan, verdicts, summary, config=Config(), target=ROOT / "eval" / "fixtures" / "vuln-app"
    )
    return data, scan


def test_sarif_structure_levels_fingerprints_and_suppressions():
    scan, verdicts, summary = load()
    victim = next(v for v in verdicts if v.verdict.value == "false_positive").finding_id
    data = build_report(scan, verdicts, summary, config=Config(), target=None,
                        decisions=Decisions(decisions=[Decision(finding_id=scan.findings[0].id, decision="accepted_risk")]))  # fmt: skip
    sarif = to_sarif(data)
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    (run,) = sarif["runs"]
    assert run["tool"]["driver"]["name"] == "GapScan" and len(run["results"]) == len(data.findings)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(res["ruleId"] in rule_ids for res in run["results"])
    assert len(rule_ids) == len(run["tool"]["driver"]["rules"])  # rules are unique
    for res in run["results"]:
        assert res["level"] in {"error", "warning", "note"}
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] and loc["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["gapscanFingerprint/v1"]
    by_fp = {r["partialFingerprints"]["gapscanFingerprint/v1"]: r for r in run["results"]}
    assert (
        "suppressions" in by_fp[victim]
        and "false positive" in by_fp[victim]["suppressions"][0]["justification"]
    )
    assert (
        by_fp[scan.findings[0].id]["suppressions"][0]["justification"]
        == "reviewer decision: accepted_risk"
    )
    assert any("suppressions" not in r for r in run["results"])
    critical = next(r for r in run["results"] if r["level"] == "error")
    assert (
        float(
            next(x for x in run["tool"]["driver"]["rules"] if x["id"] == critical["ruleId"])[
                "properties"
            ]["security-severity"]
        )
        >= 7
    )


def test_sarif_has_no_secret_values(data_and_scan):
    blob = json.dumps(to_sarif(data_and_scan[0]))
    for secret in ("ghp_aB3dE5", "AKIAJ3XK7QW2", "wJ8nQ2xLm4Rt"):
        assert secret not in blob


def test_findings_csv_roundtrips_and_neutralizes_formulas(data_and_scan):
    data, _ = data_and_scan
    rows = list(csv.DictReader(io.StringIO(findings_csv(data))))
    assert len(rows) == len(data.findings) and rows[0]["id"] == data.findings[0].id
    assert {"severity", "verdict", "risk_points", "cwe", "owasp", "decision"} <= set(rows[0])
    nasty = Finding(
        scanner="s",
        rule_id="r",
        title='=HYPERLINK("http://evil")',
        severity=Severity.LOW,
        category=Category.CODE,
        file="+cmd.py",
    )
    d = build_report(
        ScanResult(target="t", findings=[nasty]), [], None, config=Config(), target=None
    )
    out = list(csv.DictReader(io.StringIO(findings_csv(d))))[0]
    assert out["title"].startswith("'=") and out["file"].startswith("'+")


def test_asvs_csv_lists_every_requirement_at_the_level(data_and_scan):
    data, _ = data_and_scan
    rows = list(csv.DictReader(io.StringIO(asvs_csv(data))))
    assert len(rows) == data.asvs.total == 253
    assert {r["status"] for r in rows} <= {
        "evidence_of_failure",
        "no_issue_found_by_tools",
        "manual_review_required",
    }
    assert all(r["finding_ids"] for r in rows if r["status"] == "evidence_of_failure")


def test_markdown_summary_is_labeled_and_complete(data_and_scan):
    md = markdown_summary(data_and_scan[0])
    assert md.startswith("# GapScan report: vuln-app")
    for heading in (
        "## Open findings by severity",
        "## Top risks",
        "## OWASP Top 10:2025",
        "## Upgrade plan",
        "## Limitations",
    ):
        assert heading in md
    assert "AI-generated" in md and "CC BY-SA 4.0" in md and "Risk score 98/100" in md
    assert md.count("| A0") + md.count("| A10") == 10


def test_write_exports_writes_every_file_and_the_sbom_verbatim(tmp_path, data_and_scan):
    data, scan = data_and_scan
    paths = write_exports(data, scan, tmp_path / "out", "gapscan-report")
    names = sorted(p.name for p in paths)
    assert names == ["gapscan-report-asvs.csv", "gapscan-report-findings.csv", "gapscan-report-summary.md",
                     "gapscan-report.cdx.json", "gapscan-report.json", "gapscan-report.sarif"]  # fmt: skip
    sbom = json.loads((tmp_path / "out" / "gapscan-report.cdx.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX" and sbom["components"] == scan.sbom["components"]
    assert (
        json.loads((tmp_path / "out" / "gapscan-report.json").read_text())["meta"]["project"]
        == "vuln-app"
    )


@pytest.mark.skipif(not TEMPLATE_PATH.is_file(), reason="dashboard template not built")
def test_cli_report_end_to_end(tmp_path):
    out = tmp_path / "r.html"
    res = CliRunner().invoke(app, ["report", str(D / "scan.json"), "--triage", str(D / "triage.json"), "-t", str(ROOT / "eval" / "fixtures" / "vuln-app"),
                                   "-o", str(out), "--json", str(tmp_path / "r.json"), "--exports", str(tmp_path / "x")])  # fmt: skip
    assert res.exit_code == 0, res.stdout
    html = out.read_text()
    assert 'id="gapscan-data"' in html and "Risk 98/100" in " ".join(res.stdout.split())
    assert (tmp_path / "x" / "r.sarif").is_file() and (tmp_path / "r.json").is_file()
    # a second report using the first as a baseline shows nothing new and nothing fixed
    res2 = CliRunner().invoke(app, ["report", str(D / "scan.json"), "--triage", str(D / "triage.json"), "-t", str(ROOT / "eval" / "fixtures" / "vuln-app"),
                                    "--baseline", str(tmp_path / "r.json"), "-o", str(tmp_path / "r2.html"), "--json", str(tmp_path / "r2.json")])  # fmt: skip
    assert res2.exit_code == 0, res2.stdout
    b = json.loads((tmp_path / "r2.json").read_text())["baseline"]
    assert (
        b["new"] == 0
        and b["fixed"] == 0
        and b["unchanged"] == 63
        and b["previous_score"] is not None
    )


@pytest.mark.skipif(not TEMPLATE_PATH.is_file(), reason="dashboard template not built")
def test_cli_report_fails_cleanly_without_a_template(tmp_path, monkeypatch):
    monkeypatch.setattr("gapscan.report.dashboard.TEMPLATE_PATH", tmp_path / "missing.html")
    res = CliRunner().invoke(app, ["report", str(D / "scan.json"), "-o", str(tmp_path / "r.html")])
    assert res.exit_code == 1 and "make dashboard" in " ".join(res.stdout.split())


@pytest.mark.skipif(not TEMPLATE_PATH.is_file(), reason="dashboard template not built")
def test_pdf_executive_report_is_rendered_by_chromium(tmp_path, data_and_scan, monkeypatch):
    pytest.importorskip("playwright.sync_api")
    from gapscan.report.exports.pdf import PdfUnavailable, render_pdf

    from .browser import FALLBACKS

    for path in FALLBACKS:  # exercises the GAPSCAN_CHROMIUM route when Playwright's build is absent
        if Path(path).exists() and not os.environ.get("GAPSCAN_CHROMIUM"):
            monkeypatch.setenv("GAPSCAN_CHROMIUM", path)

    html = tmp_path / "r.html"
    html.write_text(render_dashboard(data_and_scan[0]), encoding="utf-8")
    try:
        pdf = render_pdf(html, tmp_path / "r.pdf")
    except PdfUnavailable as exc:
        pytest.skip(str(exc))
    raw = pdf.read_bytes()
    assert raw.startswith(b"%PDF") and len(raw) > 20_000
