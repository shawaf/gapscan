"""What a run WOULD do, computed without doing it (the "Dry run" preset).

Lists the folder's files by language, which scanners would run and which would be skipped, whether the
model is ready, what the ignore file does, and how long the last similar run took. It reads file names
and sizes only: no scanner starts, the model is not called, and nothing is written to the project."""

from __future__ import annotations

import contextlib
import os
from collections import Counter
from pathlib import Path
from typing import Any

from ..config import Config
from ..context.callgraph import SKIP_DIRS
from ..context.treesitter import EXTENSIONS
from ..llm.client import LLMClient, LLMError
from ..normalize import IGNORE_FILENAME, load_ignore_rules
from ..scanners import build_scanners

MAX_FILES = 200_000  # a safety stop for enormous trees; the plan says when it was reached
OTHER = {
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".tf": "terraform",
    ".gradle": "gradle",
    ".xml": "xml",
    ".html": "html",
    ".sh": "shell",
}


def count_files(target: Path) -> dict[str, Any]:
    by_language: Counter[str] = Counter()
    total = size = 0
    truncated = False
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            total += 1
            if total > MAX_FILES:
                truncated = True
                break
            ext = os.path.splitext(name)[1].lower()
            lang = (
                EXTENSIONS.get(ext)
                or OTHER.get(ext)
                or ("dockerfile" if name == "Dockerfile" else None)
            )
            if lang:
                by_language["javascript" if lang == "tsx" else lang] += 1
                with contextlib.suppress(OSError):
                    size += (Path(root) / name).stat().st_size
        if truncated:
            break
    return {
        "files": min(total, MAX_FILES),
        "scannable": sum(by_language.values()),
        "by_language": dict(by_language.most_common()),
        "bytes": size,
        "truncated": truncated,
    }


def build_plan(
    cfg: Config, target: Path, options: dict[str, Any], last_seconds: float | None = None
) -> dict[str, Any]:
    scanners = []
    for s in build_scanners(cfg):
        available = s.is_available()
        version = ""
        if available:
            try:
                version = s.version()
            except Exception:  # noqa: BLE001 - a version probe failing must not fail the plan
                version = ""
        scanners.append({"name": s.name, "will_run": available, "version": version,
                         "why": "" if available else "not installed or its data is missing, so it would be skipped"})  # fmt: skip
    ai: dict[str, Any] = {"enabled": bool(options.get("triage")), "profile": cfg.llm.profile, "model": cfg.llm.model,
                          "limit": int(options.get("limit", 40)), "tool_calls": cfg.agent.max_tool_calls, "installed": None, "error": "",
                          "deep_dive": int(options.get("deep_dive_limit", 0)) if options.get("deep_dive") else 0,
                          "deep_dive_min_priority": cfg.agent.deep_dive_min_priority}  # fmt: skip
    if ai["enabled"]:
        try:
            names = {m["name"] for m in LLMClient(cfg.llm).list_models()}
            ai["installed"] = cfg.llm.model in names or f"{cfg.llm.model}:latest" in names
        except LLMError as exc:
            ai["error"] = str(exc)[:200]
    globs, rules = load_ignore_rules(target) if target.is_dir() else ([], set())
    return {
        "folder": str(target), "exists": target.is_dir(),
        **(count_files(target) if target.is_dir() else {"files": 0, "scannable": 0, "by_language": {}, "bytes": 0, "truncated": False}),
        "scanners": scanners, "ai": ai,
        "ignore": {"file": (target / IGNORE_FILENAME).is_file(), "paths": len(globs), "rules": len(rules)},
        "estimate_seconds": last_seconds,
        "changes": "Nothing. A dry run starts no scanner, does not call the model and writes nothing to the project.",
    }  # fmt: skip


def plan_lines(plan: dict[str, Any]) -> list[str]:
    """The plan as plain log lines (what the run log shows)."""
    lines = [f"dry run for {plan['folder']}: nothing is executed and nothing is changed"]
    if not plan["exists"]:
        return [*lines, "the folder no longer exists"]
    langs = (
        ", ".join(f"{k} {v}" for k, v in list(plan["by_language"].items())[:8]) or "none recognized"
    )
    lines.append(f"{plan['scannable']} scannable files of {plan['files']} ({langs})")
    for s in plan["scanners"]:
        if s["will_run"]:
            lines.append(
                f"scanner {s['name']}: would run" + (f" ({s['version']})" if s["version"] else "")
            )
        else:
            lines.append(f"scanner {s['name']}: would be skipped, {s['why']}")
    ai = plan["ai"]
    if ai["enabled"]:
        note = ", but the model is not installed" if ai["installed"] is False else ""
        lines.append(
            f"AI review: would review up to {ai['limit']} findings with {ai['model']} ({ai['profile']}){note}"
        )
        if ai.get("deep_dive"):
            lines.append(
                f"deep dive: would investigate up to {ai['deep_dive']} confirmed issues at "
                f"priority >= {ai['deep_dive_min_priority']:g}"
            )
    else:
        lines.append("AI review: off")
    if plan["ignore"]["file"]:
        lines.append(
            f"{IGNORE_FILENAME}: {plan['ignore']['paths']} path patterns, {plan['ignore']['rules']} rules"
        )
    if plan["estimate_seconds"]:
        secs = plan["estimate_seconds"]
        how_long = f"{round(secs)} s" if secs < 90 else f"{round(secs / 60)} min"
        lines.append(f"about {how_long}, from the last similar run")
    return lines
