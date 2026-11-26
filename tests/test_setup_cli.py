"""`gapscan setup`: the one command a new user runs after `pipx install gapscan`."""

from __future__ import annotations

from typing import Any

import httpx
from typer.testing import CliRunner

from gapscan import cli

runner = CliRunner()


class FakeTools:
    def __init__(self, missing_after: list[str]) -> None:
        self.installed = False
        self.activated = False
        self._missing = missing_after

    def install(self, progress: Any, cancel: Any = None, say: Any = lambda _m: None) -> None:
        self.installed = True
        say("downloading trivy 0.74.0 (49 MB)")
        progress(49, 49)

    def activate(self) -> None:
        self.activated = True

    def missing(self) -> list[str]:
        return self._missing


def _patch(monkeypatch, tools: FakeTools, fetched: list[bool]) -> None:
    class FakeRuntime:
        def __init__(self, data_dir: Any) -> None:
            self.tools = tools

    monkeypatch.setattr(cli, "RuntimeManager", FakeRuntime)
    monkeypatch.setattr(cli, "data_fetch_vulns", lambda **_kw: fetched.append(True))


def test_setup_installs_scanners_then_data(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    tools, fetched = FakeTools([]), []
    _patch(monkeypatch, tools, fetched)
    result = runner.invoke(cli.app, ["setup"])
    assert result.exit_code == 0, result.stdout
    assert tools.installed and tools.activated and fetched == [True]
    assert "Every scanner is ready" in result.stdout


def test_setup_names_what_is_still_missing(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    tools, fetched = FakeTools(["checkov"]), []
    _patch(monkeypatch, tools, fetched)
    result = runner.invoke(cli.app, ["setup", "--no-data"])
    assert result.exit_code == 0
    assert "checkov" in result.stdout and fetched == []


def test_setup_without_network_for_data_fails_cleanly(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    tools = FakeTools([])
    _patch(monkeypatch, tools, [])

    def offline(**_kw: Any) -> None:
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(cli, "data_fetch_vulns", offline)
    result = runner.invoke(cli.app, ["setup"])
    assert result.exit_code == 1
    assert "download failed" in result.stdout and "Traceback" not in result.stdout


def test_setup_can_skip_scanners(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    tools, fetched = FakeTools([]), []
    _patch(monkeypatch, tools, fetched)
    result = runner.invoke(cli.app, ["setup", "--no-scanners"])
    assert result.exit_code == 0 and not tools.installed and fetched == [True]
