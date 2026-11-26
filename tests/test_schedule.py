"""The daily zero-day check: what `gapscan schedule enable` writes and runs, per platform."""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any

import pytest

from gapscan import schedule

ARGV = ["/opt/gapscan/bin/gapscan"]


def test_macos_writes_a_launch_agent_that_fetches_then_watches(tmp_path: Path) -> None:
    log = tmp_path / "s.log"
    plan = schedule.plan_enable("07:30", log=log, home=tmp_path, platform="darwin", argv=ARGV)
    assert plan.kind == "launchd"
    ((path, text),) = plan.files.items()
    assert path == tmp_path / "Library/LaunchAgents/dev.gapscan.watch.plist"
    data = plistlib.loads(text.encode())
    assert data["ProgramArguments"] == ARGV + ["data", "fetch-vulns", "--watch", "--notify"]
    assert data["StartCalendarInterval"] == {"Hour": 7, "Minute": 30}
    assert data["StandardOutPath"] == str(log)
    assert plan.commands[-1][:2] == ["launchctl", "bootstrap"]


def test_no_fetch_only_rechecks(tmp_path: Path) -> None:
    plan = schedule.plan_enable("09:00", fetch=False, log=tmp_path / "l", home=tmp_path,
                                platform="darwin", argv=ARGV)  # fmt: skip
    args = plistlib.loads(next(iter(plan.files.values())).encode())["ProgramArguments"]
    assert args == ARGV + ["watch", "--all", "--new-only", "--notify"]


def test_linux_uses_a_systemd_user_timer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schedule.shutil, "which", lambda name: "/usr/bin/systemctl")
    plan = schedule.plan_enable("6:05", log=tmp_path / "l", home=tmp_path, platform="linux",
                                argv=['/path with "quotes"/gapscan'])  # fmt: skip
    assert plan.kind == "systemd"
    files = {p.name: t for p, t in plan.files.items()}
    assert "OnCalendar=*-*-* 06:05:00" in files["gapscan-watch.timer"]
    assert 'ExecStart="/path with \\"quotes\\"/gapscan" "data"' in files["gapscan-watch.service"]
    assert ["systemctl", "--user", "enable", "--now", "gapscan-watch.timer"] in plan.commands


def test_without_systemd_it_prints_a_crontab_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(schedule.shutil, "which", lambda name: None)
    plan = schedule.plan_enable("21:00", log=tmp_path / "l", home=tmp_path, platform="linux",
                                argv=ARGV)  # fmt: skip
    assert (
        plan.kind == "cron" and "0 21 * * * /opt/gapscan/bin/gapscan data fetch-vulns" in plan.note
    )


def test_a_bad_time_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        schedule.plan_enable("25:00", log=tmp_path / "l", home=tmp_path, platform="darwin")


def test_apply_writes_runs_and_disable_removes(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    class Done:
        returncode = 0
        stderr = ""

    def runner(cmd: list[str], **kw: Any) -> Done:
        assert kw["timeout"] and "shell" not in kw
        calls.append(cmd)
        return Done()

    plan = schedule.plan_enable("09:00", log=tmp_path / "l", home=tmp_path, platform="darwin",
                                argv=ARGV)  # fmt: skip
    assert schedule.apply(plan, runner=runner) == []
    assert schedule.is_enabled(tmp_path, "darwin") is not None
    off = schedule.plan_disable(tmp_path, "darwin")
    schedule.apply(off, remove=True, runner=runner)
    assert schedule.is_enabled(tmp_path, "darwin") is None
    assert calls[-1][:2] == ["launchctl", "bootout"]


def test_fetch_vulns_with_watch_rechecks_new_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    import gapscan.cli as cli

    monkeypatch.setattr(cli, "fetch_enrichment", lambda store: {"cisa_kev": "k", "epss": "e"})
    monkeypatch.setattr(cli, "fetch_osv_db", lambda d: "o")
    monkeypatch.setattr(cli, "fetch_trivy_db", lambda d, java_db=False: "t")
    seen: list[tuple[Any, ...]] = []
    monkeypatch.setattr(cli, "_run_watch", lambda *a: seen.append(a))
    cfg = tmp_path / "gapscan.toml"
    cfg.write_text(f'[data]\ndir = "{tmp_path / "data"}"\n')
    r = CliRunner().invoke(cli.app, ["data", "fetch-vulns", "--watch", "--notify", "-c", str(cfg)])
    assert r.exit_code == 0, r.output
    (args,) = seen
    assert args[1:] == (None, True, None, None, True, False, True)  # all projects, notify, new only
