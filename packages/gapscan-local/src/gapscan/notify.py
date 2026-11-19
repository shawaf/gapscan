"""Desktop notifications for local alerts (macOS Notification Center, or notify-send on Linux).

Off unless the user asks for it (`gapscan watch --notify`). The text can contain names that came
from a scanned project (package names from its lockfile), so it is passed to the notifier as a
plain argument, never spliced into a script: `osascript` reads it from `argv`, not from AppleScript
source, so a crafted package name cannot run AppleScript.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from typing import Any

MAX_TITLE = 80
MAX_BODY = 240
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")

Runner = Callable[..., Any]


def clean(text: str, limit: int) -> str:
    text = _CONTROL.sub(" ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def notify_command(title: str, body: str, platform: str | None = None) -> list[str] | None:
    """The argument list that shows one notification, or None when this system has no notifier."""
    title, body = clean(title, MAX_TITLE), clean(body, MAX_BODY)
    platform = platform or sys.platform
    if platform == "darwin":
        return [
            "osascript",
            "-e", "on run argv",
            "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
            "-e", "end run",
            title,
            body,
        ]  # fmt: skip
    if platform.startswith("linux") and shutil.which("notify-send"):
        return ["notify-send", "--app-name=GapScan", "--", title, body]
    return None


def desktop_notify(
    title: str, body: str, *, runner: Runner = subprocess.run, platform: str | None = None
) -> bool:
    """Show a notification; False when there is no notifier or it failed. Never raises."""
    args = notify_command(title, body, platform)
    if args is None:
        return False
    try:
        proc = runner(args, timeout=10, check=False, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        return False
    return getattr(proc, "returncode", 1) == 0
