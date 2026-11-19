"""Benchmark targets: a pinned registry and a safe shallow-clone fetcher.

Network access exists only in `fetch_target` (an explicit `gapscan eval fetch`, never during a
scan). Git hooks are disabled, the commit hash is verified against the pin, and nothing from a
target is ever built, installed or executed (hard rule #1)."""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

from pydantic import BaseModel


class Target(BaseModel):
    name: str
    repo: str
    ref: str  # tag or commit to fetch
    sha: str  # the commit the checkout must resolve to
    license: str
    language: str
    truth: str  # "benchmark-csv" | "none"
    truth_file: str = ""
    scan_subdir: str = ""
    description: str = ""


def load_targets(path: Path) -> dict[str, Target]:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    return {t["name"]: Target(**t) for t in raw["target"]}


def _git(args: list[str], cwd: Path, timeout: int = 900) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed arg list, no shell
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", *args],
        cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False,
    )  # fmt: skip
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args[:2])} failed: {(proc.stderr or proc.stdout).strip()[-300:]}"
        )
    return proc.stdout.strip()


def target_dir(root: Path, target: Target) -> Path:
    return root / target.name


def fetch_target(root: Path, target: Target) -> Path:
    """Shallow-fetch `target` at its pinned ref into root/<name> and verify the commit."""
    dest = target_dir(root, target)
    if (dest / ".git").is_dir() and _git(["rev-parse", "HEAD"], dest) == target.sha:
        return dest  # already there and verified
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").is_dir():
        _git(["init", "-q"], dest)
        _git(["remote", "add", "origin", target.repo], dest)
    _git(["fetch", "-q", "--depth", "1", "origin", target.ref], dest)
    _git(["checkout", "-q", "--detach", "FETCH_HEAD"], dest)
    head = _git(["rev-parse", "HEAD"], dest)
    if head != target.sha:
        raise RuntimeError(f"{target.name}: fetched {head} but the pin is {target.sha}")
    return dest


def is_fetched(root: Path, target: Target) -> bool:
    d = target_dir(root, target)
    try:
        return (d / ".git").is_dir() and _git(["rev-parse", "HEAD"], d) == target.sha
    except (RuntimeError, OSError):
        return False
