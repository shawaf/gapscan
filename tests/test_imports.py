"""`gapscan scan --import`: SARIF, ZAP and nuclei results as evidence, and runtime proof links."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from gapscan.models import Category, Finding, ScanResult, Severity
from gapscan.normalize import normalize
from gapscan.scanners.imports import (
    RUNTIME,
    ImportError_,
    link_runtime_proof,
    load_import,
    parse_nuclei,
    parse_zap,
)

DATA = Path(__file__).parent / "data" / "imports"
APP = Path(__file__).resolve().parents[1] / "eval" / "fixtures" / "vuln-app"


def test_zap_report_becomes_runtime_findings_with_the_request_as_evidence():
    found = parse_zap(json.loads((DATA / "zap-report.json").read_text()))
    assert len(found) == 3
    sqli = next(f for f in found if f.cwe == ["CWE-89"])
    assert sqli.scanner == "zap" and sqli.severity == Severity.HIGH and sqli.file is None
    assert sqli.raw["evidence_kind"] == RUNTIME and sqli.raw["route"] == "/user"
    assert sqli.raw["method"] == "GET" and sqli.raw["param"] == "name"
    assert "GET http://localhost:5000/user" in (sqli.snippet or "")
    assert "unrecognized token" in (sqli.snippet or "")  # the scanner's evidence, quoted
    assert "<p>" not in sqli.message


def test_nuclei_jsonl_keeps_cwe_cve_and_extracted_proof():
    found = parse_nuclei((DATA / "nuclei.jsonl").read_text().splitlines())
    cmd, cve = found
    assert cmd.scanner == "nuclei" and cmd.severity == Severity.CRITICAL and cmd.cwe == ["CWE-78"]
    assert cmd.raw["route"] == "/ping" and cmd.raw["method"] == "GET"
    assert "uid=1000" in (cmd.snippet or "")
    assert cve.cve == ["CVE-2099-0001"] and cve.cwe == ["CWE-94"]


def test_formats_are_recognized_from_content(tmp_path):
    assert load_import(DATA / "zap-report.json", tmp_path).scanner == "zap"
    assert load_import(DATA / "nuclei.jsonl", tmp_path).scanner == "nuclei"
    sarif = tmp_path / "x.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}},
                     "results": [{"ruleId": "r1", "message": {"text": "Bad thing here."},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                     "region": {"startLine": 3}}}]}]}]}))  # fmt: skip
    got = load_import(sarif, tmp_path)
    assert got.scanner == "sarif" and got.findings[0].file == "a.py"
    array = tmp_path / "nuclei.json"
    lines = (DATA / "nuclei.jsonl").read_text().splitlines()
    array.write_text("[" + ",".join(lines) + "]")
    assert load_import(array, tmp_path).scanner == "nuclei"


@pytest.mark.parametrize("content", ['{"hello": 1}', "plain text", "[1, 2]"])
def test_unknown_files_are_refused_with_a_reason(tmp_path, content):
    path = tmp_path / "x.json"
    path.write_text(content)
    with pytest.raises(ImportError_, match="not"):
        load_import(path, tmp_path)


def test_secrets_in_imported_evidence_are_masked():
    data = json.loads((DATA / "zap-report.json").read_text())
    inst = data["site"][0]["alerts"][0]["instances"][0]
    inst["evidence"] = 'api_key = "sk_live_abcdefghijklmnop1234"'
    found = parse_zap(data)
    assert "sk_live_abcdefghijklmnop1234" not in json.dumps([f.model_dump() for f in found])


def _static(file: str, line: int, cwe: str) -> Finding:
    return Finding(scanner="semgrep", rule_id="r", title="t", severity=Severity.HIGH,
                   category=Category.CODE, cwe=[cwe], file=file, start_line=line,
                   sources=["semgrep"])  # fmt: skip


def test_runtime_results_confirm_the_code_that_serves_their_route(tmp_path):
    target = tmp_path / "app"
    shutil.copytree(APP, target)
    sqli, cmd, md5 = (
        _static("app.py", 16, "CWE-89"),
        _static("app.py", 23, "CWE-78"),
        _static("app.py", 32, "CWE-327"),
    )
    runtime = parse_zap(json.loads((DATA / "zap-report.json").read_text())) + parse_nuclei(
        (DATA / "nuclei.jsonl").read_text().splitlines()
    )
    findings = [sqli, cmd, md5, *runtime]
    assert link_runtime_proof(findings, target) == 2
    assert "zap" in sqli.sources and sqli.reachability == "reachable"
    assert sqli.reachability_evidence[0].startswith("Confirmed at runtime by zap: SQL Injection")
    assert "nuclei" in cmd.sources and cmd.raw["runtime_proof"][0]["scanner"] == "nuclei"
    assert md5.sources == ["semgrep"] and not md5.raw.get("runtime_proof")  # no runtime match
    imports = _static(
        "app.py", 5, "CWE-78"
    )  # `import subprocess`: above every route, not a handler
    assert link_runtime_proof([imports, *runtime], target) == 0


def test_no_link_without_the_route_in_the_file_or_for_the_site_root(tmp_path):
    (tmp_path / "other.py").write_text('x = "/somewhere-else"\n')
    s = _static("other.py", 1, "CWE-693")
    runtime = parse_zap(json.loads((DATA / "zap-report.json").read_text()))  # CSP alert is on "/"
    assert link_runtime_proof([s, *runtime], tmp_path) == 0


def test_runtime_proof_runs_inside_normalize_and_raises_priority(tmp_path):
    target = tmp_path / "app"
    shutil.copytree(APP, target)
    base = [_static("app.py", 16, "CWE-89")]
    plain = normalize(ScanResult(target=str(target), findings=[f.model_copy(deep=True) for f in base]),
                      target)  # fmt: skip
    runtime = parse_zap(json.loads((DATA / "zap-report.json").read_text()))
    proven = normalize(ScanResult(target=str(target), findings=base + runtime), target)
    code = next(f for f in proven.findings if f.file == "app.py")
    assert code.raw["runtime_proof"][0]["id"]  # links name the runtime finding's stable ID
    assert code.priority > next(f for f in plain.findings if f.file == "app.py").priority
    assert all(f.controls for f in proven.findings if f.cwe == ["CWE-89"])  # mapped to OWASP
