"""The daily zero-day check, scheduled by the user (`gapscan schedule enable`).

Turning it on is the user's choice; nothing is scheduled otherwise. Once a day the system runs:

    gapscan data fetch-vulns --watch --notify

which downloads fresh vulnerability data (the user-run data command, the same hosts as by hand),
re-checks every saved project's dependencies offline, and shows a desktop notification only for
advisories no earlier check reported. With `--no-fetch` it only re-checks against data the user
refreshes some other way (an offline bundle on an air-gapped machine).

The job is registered with the system's own scheduler, so nothing of GapScan stays running:
a LaunchAgent on macOS, a systemd user timer on Linux (or a crontab line where systemd is missing).
Every command is an argument list with a timeout; nothing goes through a shell.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

LABEL = "dev.gapscan.watch"
UNIT = "gapscan-watch"
Runner = Callable[..., Any]


@dataclass(frozen=True)
class Plan:
    """What `enable` writes and runs, so it can be shown and tested without touching the system."""

    kind: str  # launchd | systemd | cron | manual
    files: dict[Path, str]
    commands: list[list[str]]
    note: str = ""


def program() -> list[str]:
    """How to start this GapScan again: the frozen app, the installed command, or this Python."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    found = shutil.which("gapscan")
    if found:
        return [str(Path(found).resolve())]
    return [sys.executable, "-m", "gapscan.cli"]


def job_args(fetch: bool) -> list[str]:
    if fetch:
        return ["data", "fetch-vulns", "--watch", "--notify"]
    return ["watch", "--all", "--new-only", "--notify"]


def _hm(at: str) -> tuple[int, int]:
    hour, _, minute = at.partition(":")
    h, m = int(hour), int(minute or 0)
    if not (0 <= h < 24 and 0 <= m < 60):
        raise ValueError(f"not a time of day: {at!r} (use HH:MM)")
    return h, m


def _launchd(argv: list[str], h: int, m: int, log: Path, home: Path) -> Plan:
    args = "\n".join(f"    <string>{escape(a)}</string>" for a in argv)
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args}
  </array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>{h}</integer><key>Minute</key><integer>{m}</integer></dict>
  <key>StandardOutPath</key><string>{escape(str(log))}</string>
  <key>StandardErrorPath</key><string>{escape(str(log))}</string>
</dict>
</plist>
"""
    path = home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
    domain = f"gui/{os.getuid()}"
    return Plan("launchd", {path: plist},
                [["launchctl", "bootout", domain, str(path)],
                 ["launchctl", "bootstrap", domain, str(path)]])  # fmt: skip


def _quote(arg: str) -> str:
    """systemd's own quoting for ExecStart (it does not use a shell)."""
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _systemd(argv: list[str], h: int, m: int, log: Path, home: Path) -> Plan:
    base = home / ".config" / "systemd" / "user"
    service = (
        "[Unit]\nDescription=GapScan daily zero-day check\n\n[Service]\nType=oneshot\n"
        f"ExecStart={' '.join(_quote(a) for a in argv)}\n"
        f"StandardOutput=append:{log}\nStandardError=append:{log}\n"
    )
    timer = (
        "[Unit]\nDescription=GapScan daily zero-day check\n\n[Timer]\n"
        f"OnCalendar=*-*-* {h:02d}:{m:02d}:00\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    return Plan("systemd", {base / f"{UNIT}.service": service, base / f"{UNIT}.timer": timer},
                [["systemctl", "--user", "daemon-reload"],
                 ["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"]])  # fmt: skip


def plan_enable(at: str = "09:00", *, fetch: bool = True, log: Path, home: Path | None = None,
                platform: str | None = None, argv: list[str] | None = None) -> Plan:  # fmt: skip
    h, m = _hm(at)
    home = home or Path.home()
    platform = platform or sys.platform
    argv = (argv or program()) + job_args(fetch)
    if platform == "darwin":
        return _launchd(argv, h, m, log, home)
    if platform.startswith("linux") and shutil.which("systemctl"):
        return _systemd(argv, h, m, log, home)
    line = " ".join(argv)
    if platform.startswith("linux"):
        return Plan("cron", {}, [], f"Add this line with `crontab -e`:\n{m} {h} * * * {line}")
    return Plan("manual", {}, [], f"Schedule this command daily at {h:02d}:{m:02d} "
                f"(Task Scheduler on Windows):\n{line}")  # fmt: skip


def plan_disable(home: Path | None = None, platform: str | None = None) -> Plan:
    home = home or Path.home()
    platform = platform or sys.platform
    if platform == "darwin":
        path = home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
        return Plan(
            "launchd", {path: ""}, [["launchctl", "bootout", f"gui/{os.getuid()}", str(path)]]
        )
    base = home / ".config" / "systemd" / "user"
    return Plan("systemd", {base / f"{UNIT}.service": "", base / f"{UNIT}.timer": ""},
                [["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"]])  # fmt: skip


def apply(plan: Plan, *, remove: bool = False, runner: Runner = subprocess.run) -> list[str]:
    """Write (or remove) the files, then run the commands. Returns problems; never raises for a
    command that fails (unloading a job that was not loaded is expected to fail)."""
    problems: list[str] = []
    if not remove:
        for path, text in plan.files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    for i, cmd in enumerate(plan.commands):
        try:
            proc = runner(cmd, timeout=30, check=False, capture_output=True, text=True)
        except (OSError, subprocess.SubprocessError) as exc:
            problems.append(f"{cmd[0]}: {exc}")
            continue
        first_unload = plan.kind == "launchd" and i == 0 and not remove
        if getattr(proc, "returncode", 1) != 0 and not first_unload:
            problems.append(f"{' '.join(cmd[:3])}: {(getattr(proc, 'stderr', '') or '').strip()}")
    if remove:
        for path in plan.files:
            path.unlink(missing_ok=True)
    return problems


def is_enabled(home: Path | None = None, platform: str | None = None) -> Path | None:
    """The job file, if a schedule is installed."""
    plan = plan_disable(home, platform)
    return next((p for p in plan.files if p.exists()), None)
