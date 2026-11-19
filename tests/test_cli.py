"""Smoke tests for the CLI skeleton."""

from __future__ import annotations

from typer.testing import CliRunner

from gapscan.cli import app
from gapscan.core.version import __version__

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("scan", "doctor", "kb", "bundle"):
        assert cmd in result.stdout


def test_doctor_runs(monkeypatch) -> None:
    # No scanners / LLM in the test env, so doctor should exit non-zero but not crash.
    monkeypatch.setattr("shutil.which", lambda *_: None)  # no scanner programs installed

    def unreachable(*args, **kwargs):
        import httpx

        raise httpx.ConnectError("refused")

    monkeypatch.setattr("gapscan.doctor.httpx.get", unreachable)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "doctor" in result.stdout.lower()


def test_scan_missing_target() -> None:
    result = runner.invoke(app, ["scan", "/no/such/path"])
    assert result.exit_code == 2


def test_serve_explains_a_busy_port(tmp_path, monkeypatch):
    import socket

    from typer.testing import CliRunner

    from gapscan.cli import app

    monkeypatch.setenv("GAPSCAN_HOME", str(tmp_path))
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        res = CliRunner().invoke(app, ["serve", "--no-open", "--port", str(port)])
    out = " ".join(res.output.split())
    assert res.exit_code == 1 and "already in use" in out and f"--port {port + 1}" in out
