"""Tests for the doctor checks. No real scanners or LLM required."""

from __future__ import annotations

import httpx

from gapscan.config import Config
from gapscan.doctor import Status, check_databases, check_llm, check_scanners


def test_check_scanners_reports_missing(monkeypatch) -> None:
    monkeypatch.setattr("shutil.which", lambda *_: None)  # no scanner program installed
    cfg = Config()
    checks = check_scanners(cfg)
    assert [c.name for c in checks] == list(cfg.scanners.enabled)
    assert all(c.status is Status.MISSING for c in checks if c.name not in ("taint", "malware"))
    taint = next(c for c in checks if c.name == "taint")
    assert taint.status is Status.OK and "data-flow" in taint.detail  # built in


def test_check_scanners_reports_version(monkeypatch) -> None:
    from gapscan.scanners.semgrep import SemgrepScanner

    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(SemgrepScanner, "version", lambda self: "semgrep 1.2.3")
    checks = check_scanners(Config(scanners={"enabled": ["semgrep"]}))
    assert checks[0].status is Status.OK
    assert checks[0].detail.startswith("semgrep 1.2.3 (Static analysis")


def test_check_scanners_warns_about_a_scanner_no_allowed_pack_registers() -> None:
    checks = check_scanners(Config(scanners={"enabled": ["nope"]}))
    assert checks[0].status is Status.WARN and "security" in checks[0].detail


def test_check_databases_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)  # default data paths are cwd-relative; the repo's data/ is real now
    cfg = Config()
    by_name = {c.name: c for c in check_databases(cfg)}
    # Required datasets are MISSING when absent...
    assert all(
        by_name[n].status is Status.MISSING for n in ("osv db", "trivy cache", "kb index")
    )
    # ...but the optional Semgrep community rules only warn (GapScan's own rules are packaged).
    assert by_name["semgrep rules"].status is Status.WARN


def test_check_databases_present_and_empty(tmp_path) -> None:
    kb = tmp_path / "kb"
    kb.mkdir()
    (kb / "index.bin").write_text("x", encoding="utf-8")
    empty = tmp_path / "osv"
    empty.mkdir()
    cfg = Config(
        data={"kb_dir": kb},
        scanners={"osv": {"db_dir": empty}},
    )
    by_name = {c.name: c for c in check_databases(cfg)}
    assert by_name["kb index"].status is Status.OK
    assert by_name["osv db"].status is Status.WARN


def test_check_llm_unreachable(monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr("gapscan.doctor.httpx.get", boom)
    checks = check_llm(Config())
    assert checks[0].status is Status.MISSING


def test_check_llm_model_present(monkeypatch) -> None:
    class FakeResp:
        def raise_for_status(self) -> None: ...

        def json(self) -> dict:
            return {"models": [{"name": "my-model:7b"}]}

    monkeypatch.setattr("gapscan.doctor.httpx.get", lambda *a, **k: FakeResp())
    by_name = {c.name: c for c in check_llm(Config(llm={"model": "my-model:7b"}))}
    assert by_name["llm endpoint"].status is Status.OK
    assert by_name["llm model"].status is Status.OK


def test_check_llm_model_missing(monkeypatch) -> None:
    class FakeResp:
        def raise_for_status(self) -> None: ...

        def json(self) -> dict:
            return {"models": [{"name": "some-other-model"}]}

    monkeypatch.setattr("gapscan.doctor.httpx.get", lambda *a, **k: FakeResp())
    by_name = {c.name: c for c in check_llm(Config())}
    assert by_name["llm model"].status is Status.MISSING
