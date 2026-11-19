"""A scanned project must not be able to configure or silence GapScan's scanners (hard rule #3).

Each tool below honored a file inside the scanned project that hid every finding (verified with
the real binaries on 2026-10-09): `.semgrepignore`, `.bandit`, `.checkov.yaml`, `osv-scanner.toml`,
and `.trivyignore` / `trivy.yaml` when the working directory was the project. Inline suppressions
(`nosemgrep`, `# nosec`, `checkov:skip`) are reported anyway, marked as suppressed in the code.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from gapscan.config import load_config
from gapscan.models import Category, Finding, Severity
from gapscan.normalize import score
from gapscan.scanners import build_scanners
from gapscan.scanners.bandit import BanditScanner
from gapscan.scanners.base import CommandScanner, run_all
from gapscan.scanners.checkov import CheckovScanner, iac_files, parse_checkov
from gapscan.scanners.sarif import parse_sarif
from gapscan.scanners.semgrep import IGNORE_SEMGREPIGNORE, SemgrepScanner

SHELL_PY = "import subprocess\n\ndef f(x):\n    subprocess.call(x, shell=True)\n"
NOSEC_PY = "import subprocess\n\ndef g(x):\n    subprocess.call(x, shell=True)  # nosec\n"
NOSEM_PY = "import subprocess\n\ndef h(x):\n    subprocess.call(x, shell=True)  # nosemgrep\n"
DOCKERFILE = 'FROM python:3.12\nRUN pip install flask\nCMD ["python", "app.py"]\n'


def done(argv, stdout=""):
    return subprocess.CompletedProcess(argv, 0, stdout, "")


# --- the working directory --------------------------------------------------------------------


class _Pwd(CommandScanner):
    name = "pwd"
    binary = "pwd"

    def run(self, target, workdir):
        self.seen = self._exec(["pwd", "-P"]).stdout.strip()
        return []


def test_every_scanner_runs_outside_the_scanned_project(tmp_path):
    target, work = tmp_path / "repo", tmp_path / "work"
    target.mkdir()
    s = _Pwd()
    run_all([s], target, work)
    assert Path(s.seen) == (work / "pwd").resolve()


# --- semgrep --------------------------------------------------------------------------------


def test_semgrep_ignores_semgrepignore_and_reports_nosem(tmp_path, monkeypatch):
    calls: list[list[str]] = []

    def fake(argv, timeout_s=None):
        calls.append(argv)
        out = Path(argv[argv.index("--output") + 1])
        out.write_text(json.dumps({"runs": [{"tool": {"driver": {}}, "results": []}]}))
        return done(argv)

    s = SemgrepScanner(tmp_path / "no-community-rules")
    monkeypatch.setattr(s, "_exec", fake)
    s.run(tmp_path, tmp_path)
    assert IGNORE_SEMGREPIGNORE in calls[0] and "--disable-nosem" in calls[0]
    assert s.note == ""


def test_semgrep_without_the_experimental_flag_still_scans_and_says_so(tmp_path, monkeypatch):
    calls: list[list[str]] = []

    def fake(argv, timeout_s=None):
        calls.append(argv)
        if IGNORE_SEMGREPIGNORE in argv:
            return subprocess.CompletedProcess(
                argv, 2, "", f"unknown option '{IGNORE_SEMGREPIGNORE}'"
            )
        out = Path(argv[argv.index("--output") + 1])
        out.write_text(json.dumps({"runs": [{"tool": {"driver": {}}, "results": []}]}))
        return done(argv)

    s = SemgrepScanner(tmp_path / "no-community-rules")
    monkeypatch.setattr(s, "_exec", fake)
    s.run(tmp_path, tmp_path)
    assert len(calls) == 2 and IGNORE_SEMGREPIGNORE not in calls[1]
    assert "--disable-nosem" in calls[1] and ".semgrepignore" in s.note


def test_sarif_suppressions_are_kept_and_marked(tmp_path):
    result = {"ruleId": "r", "message": {"text": "shell"}, "suppressions": [{"kind": "inSource"}],
              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                                  "region": {"startLine": 3}}}]}  # fmt: skip
    (f,) = parse_sarif({"runs": [{"tool": {"driver": {}}, "results": [result]}]}, tmp_path, "x")
    assert f.raw["suppressed_in_code"] == "a suppression comment in the source"
    assert "reports it anyway" in f.message


# --- bandit ---------------------------------------------------------------------------------


def test_bandit_uses_its_own_settings_and_reports_nosec(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(NOSEC_PY)
    calls: list[list[str]] = []
    result = {"results": [{"test_id": "B602", "test_name": "shell", "issue_text": "shell=True",
                           "issue_severity": "HIGH", "filename": str(tmp_path / "app.py"),
                           "line_number": 4, "line_range": [4]}]}  # fmt: skip

    def fake(argv, timeout_s=None):
        calls.append(argv)
        Path(argv[argv.index("-o") + 1]).write_text(json.dumps(result))
        return done(argv)

    s = BanditScanner()
    monkeypatch.setattr(s, "_exec", fake)
    (f,) = s.run(tmp_path, tmp_path)
    ini = Path(calls[0][calls[0].index("--ini") + 1])
    assert ini.parent == tmp_path and ini.read_text() == "[bandit]\n"
    assert "--ignore-nosec" in calls[0]
    assert f.raw["suppressed_in_code"] == "`# nosec`"


# --- checkov --------------------------------------------------------------------------------


def test_checkov_lists_iac_files_itself_and_never_passes_the_folder(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    (tmp_path / "main.tf").write_text("")
    (tmp_path / "deploy.yaml").write_text("")
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / ".checkov.yaml").write_text("skip-check: [CKV_DOCKER_2]\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.yaml").write_text("")
    names = sorted(p.name for p in iac_files(tmp_path))
    assert names == ["Dockerfile", "deploy.yaml", "main.tf"]
    calls: list[list[str]] = []
    monkeypatch.setattr(CheckovScanner, "_exec", lambda self, argv, timeout_s=None:
                        calls.append(argv) or done(argv))  # fmt: skip
    CheckovScanner().run(tmp_path, tmp_path)
    assert "-d" not in calls[0] and "--quiet" not in calls[0] and calls[0].count("-f") == 3


def test_checkov_inline_skips_are_reported_with_their_reason(tmp_path):
    abs_path = str(tmp_path / "svc" / "Dockerfile")
    check = {"check_id": "CKV_DOCKER_2", "check_name": "healthcheck", "file_abs_path": abs_path,
             "file_path": abs_path, "file_line_range": [1, 3], "resource": "Dockerfile"}  # fmt: skip
    data = {"results": {"failed_checks": [dict(check, check_id="CKV_DOCKER_3")],
                        "skipped_checks": [dict(check, check_result={
                            "result": "SKIPPED", "suppress_comment": "handled by k8s"})]}}  # fmt: skip
    failed, skipped = parse_checkov(data, tmp_path)
    assert failed.file == "svc/Dockerfile" and "suppressed_in_code" not in failed.raw
    assert skipped.raw["suppressed_in_code"] == "`checkov:skip`: handled by k8s"


# --- ranking --------------------------------------------------------------------------------


def test_suppressed_findings_stay_but_rank_lower():
    f = Finding(scanner="s", rule_id="r", title="t", severity=Severity.HIGH, category=Category.CODE)
    g = f.model_copy(update={"raw": {"suppressed_in_code": "`# nosec`"}})
    assert 0 < score(g) < score(f)


# --- the real binaries: each attack that worked before ----------------------------------------

needs = pytest.mark.skipif


def _scan(scanner, target: Path, work: Path) -> list[Finding]:
    findings, runs = run_all([scanner], target, work)
    assert runs[0].status == "ok", runs[0].error
    return findings


@needs(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_real_semgrep_finds_what_semgrepignore_tries_to_hide(tmp_path):
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    (repo / "app.py").write_text(SHELL_PY)
    (repo / "sub" / "b.py").write_text(SHELL_PY)
    (repo / "c.py").write_text(NOSEM_PY)
    (repo / ".semgrepignore").write_text("*\n")
    (repo / "sub" / ".semgrepignore").write_text("*\n")
    found = _scan(SemgrepScanner(tmp_path / "no-community-rules"), repo, tmp_path / "w")
    files = {f.file for f in found}
    assert {"app.py", "sub/b.py", "c.py"} <= files
    assert all(f.raw.get("suppressed_in_code") for f in found if f.file == "c.py")


@needs(shutil.which("bandit") is None, reason="bandit not installed")
def test_real_bandit_ignores_the_projects_dot_bandit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(SHELL_PY)
    (repo / "b.py").write_text(NOSEC_PY)
    (repo / ".bandit").write_text("[bandit]\nskips: B602,B404,B607,B603\n")
    found = _scan(BanditScanner(), repo, tmp_path / "w")
    b602 = {f.file: f for f in found if f.rule_id == "B602"}
    assert set(b602) == {"app.py", "b.py"} and b602["b.py"].raw.get("suppressed_in_code")


@needs(shutil.which("checkov") is None, reason="checkov not installed")
def test_real_checkov_ignores_the_projects_config_and_keeps_inline_skips(tmp_path):
    repo = tmp_path / "repo"
    (repo / "svc").mkdir(parents=True)
    (repo / "Dockerfile").write_text(DOCKERFILE)
    (repo / "svc" / "Dockerfile").write_text(
        'FROM python:3.12\n# checkov:skip=CKV_DOCKER_2:handled by k8s\nCMD ["python", "x.py"]\n'
    )
    (repo / ".checkov.yaml").write_text("skip-check:\n  - CKV_DOCKER_2\n  - CKV_DOCKER_3\n")
    found = _scan(CheckovScanner(), repo, tmp_path / "w")
    root = {f.rule_id for f in found if f.file == "Dockerfile"}
    assert {"CKV_DOCKER_2", "CKV_DOCKER_3"} <= root
    skipped = [f for f in found if f.file == "svc/Dockerfile" and f.rule_id == "CKV_DOCKER_2"]
    assert skipped and "handled by k8s" in skipped[0].raw["suppressed_in_code"]


def _configured(name: str):
    return next((s for s in build_scanners(load_config(None)) if s.name == name), None)


def test_real_trivy_ignores_trivyignore_even_when_started_inside_the_project(tmp_path, monkeypatch):
    trivy = _configured("trivy")
    if trivy is None or not trivy.is_available():
        pytest.skip("trivy or its cache is not installed")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text(DOCKERFILE)
    (repo / ".trivyignore").write_text("DS-0002\nDS-0026\nDS002\nDS026\n")
    (repo / "trivy.yaml").write_text("misconfiguration:\n  scanners: []\n")
    monkeypatch.chdir(repo)  # e.g. `gapscan scan .`
    found = _scan(trivy, repo, tmp_path / "w")
    assert any(f.file == "Dockerfile" for f in found)


def test_real_osv_ignores_the_projects_osv_scanner_toml(tmp_path):
    osv = _configured("osv")
    if osv is None or not osv.is_available():
        pytest.skip("osv-scanner or its offline database is not installed")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("flask==1.0\n")
    before = {f.rule_id for f in _scan(osv, repo, tmp_path / "w1")}
    if not before:
        pytest.skip("no PyPI advisories in the installed offline database")
    (repo / "osv-scanner.toml").write_text(
        "".join(f'[[IgnoredVulns]]\nid = "{i}"\n' for i in sorted(before))
    )
    assert {f.rule_id for f in _scan(osv, repo, tmp_path / "w2")} == before
