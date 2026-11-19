"""Ordering of package version strings, used wherever a fix version is chosen."""

from __future__ import annotations

import re


def ver_key(v: str) -> tuple[tuple[int, str], ...]:
    """Sortable key for dotted versions; good enough to order fix versions."""
    return tuple((int(p), "") if p.isdigit() else (0, p) for p in re.split(r"[.\-+]", v.strip()))
