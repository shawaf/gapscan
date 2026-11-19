"""Code volume per file and language, for the hotspot treemap and the scan statistics."""

from __future__ import annotations

import os
from pathlib import Path

from ..context.callgraph import SKIP_DIRS
from ..context.treesitter import detect_language
from .schema import Hotspot, ScanStats

MAX_FILES = 20_000
MAX_FILE_BYTES = 1_000_000


def measure(target: Path) -> tuple[ScanStats, dict[str, tuple[int, str]]]:
    """(stats, {relative file: (lines of code, language)}) for supported source files."""
    stats = ScanStats()
    sizes: dict[str, tuple[int, str]] = {}
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            lang = detect_language(name)
            if lang is None:
                continue
            path = Path(root) / name
            try:
                if path.stat().st_size > MAX_FILE_BYTES or stats.files_scanned >= MAX_FILES:
                    stats.files_skipped += 1
                    continue
                loc = sum(
                    1
                    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip()
                )
            except OSError:
                stats.files_skipped += 1
                continue
            rel = str(path.relative_to(target))
            sizes[rel] = (loc, lang)
            stats.files_scanned += 1
            stats.loc_total += loc
            stats.loc_by_language[lang] = stats.loc_by_language.get(lang, 0) + loc
    return stats, sizes


def build_hotspots(sizes: dict[str, tuple[int, str]], risk: dict[str, float],
                   counts: dict[str, int], max_sev: dict[str, str], limit: int = 400) -> list[Hotspot]:  # fmt: skip
    """Files ranked by accumulated risk, with every file that has findings kept even if tiny."""
    files = set(sizes) | set(risk)
    rows = [
        Hotspot(
            file=f,
            loc=sizes.get(f, (0, ""))[0],
            language=sizes.get(f, (0, ""))[1],
            findings=counts.get(f, 0),
            risk=round(risk.get(f, 0.0), 2),
            max_severity=max_sev.get(f, "info"),
        )  # fmt: skip
        for f in files
    ]
    rows.sort(key=lambda h: (-h.risk, -h.loc, h.file))
    return rows[:limit]
