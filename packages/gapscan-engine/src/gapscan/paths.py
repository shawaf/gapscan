"""Where the installed app keeps its data.

A source checkout keeps using `data/` in the project folder. The packaged app (and anyone who sets
GAPSCAN_HOME) keeps everything in one per-user folder instead, because a packaged app has no project
folder to write into."""

from __future__ import annotations

import os
import sys
from pathlib import Path

HOME_ENV = "GAPSCAN_HOME"


def app_dir() -> Path:
    """The per-user folder: models, security data, scan history and settings live under it."""
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "GapScan"
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "GapScan"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "gapscan"


def data_env(base: Path) -> dict[str, str]:
    """Environment settings that move every data folder under `base`."""
    data = base / "data"
    return {
        "GAPSCAN_DATA__DIR": str(data),
        "GAPSCAN_DATA__KB_DIR": str(data / "kb"),
        "GAPSCAN_DATA__ENRICHMENT_DIR": str(data / "enrichment"),
        "GAPSCAN_DATA__EVAL_DIR": str(data / "eval-targets"),
        "GAPSCAN_SCANNERS__OSV__DB_DIR": str(data / "osv-db"),
        "GAPSCAN_SCANNERS__TRIVY__CACHE_DIR": str(data / "trivy-cache"),
        "GAPSCAN_SCANNERS__SEMGREP__RULES_PATH": str(data / "semgrep-rules"),
    }


def use_app_dir(force: bool = False) -> Path | None:
    """Point every data folder at the per-user folder (packaged app, or GAPSCAN_HOME set).

    Locations already chosen through environment variables are kept. Returns the folder used."""
    if not (force or getattr(sys, "frozen", False) or os.environ.get(HOME_ENV)):
        return None
    base = app_dir()
    for key, value in data_env(base).items():
        os.environ.setdefault(key, value)
    return base
