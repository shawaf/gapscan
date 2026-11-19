"""Per-weakness "what good looks like" checklists for the deep dive.

The data (checklists.json) is GapScan's own text, written from the bundled OWASP Cheat Sheet
snapshot; it is trusted guidance, not scanned content. It gives the model concrete, code-shaped
texts to search for before it claims a control is missing, the recommended fix, and fixes that
are known to be wrong (for example SHA-256 for passwords).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..models import Category, Finding
from .grouping import weakness_class

CHECKLISTS_PATH = Path(__file__).parent / "checklists.json"


@lru_cache(maxsize=1)
def load_checklists(path: Path = CHECKLISTS_PATH) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def checklist_key(f: Finding) -> str:
    if f.category == Category.SECRET:
        return "secret"
    if f.category == Category.DEPENDENCY:
        return "dependency"
    return weakness_class(f)


def checklist_for(members: list[Finding]) -> dict[str, Any] | None:
    """The checklist for the group's weakness, or None when GapScan has none for it."""
    classes = load_checklists()["classes"]
    for f in members:
        entry = classes.get(checklist_key(f))
        if entry is not None:
            return dict(entry)
    return None


def render_checklist(entry: dict[str, Any]) -> str:
    lines = [f"Source: OWASP {entry['source'].replace('_', ' ')}", "Controls that prevent it:"]
    for c in entry["controls"]:
        signals = ", ".join(f'"{s}"' for s in c["signals"])
        lines.append(f"- {c['control']}" + (f" (search for: {signals})" if signals else ""))
    lines.append(f"Recommended fix: {entry['fix']}")
    if entry.get("not_a_fix"):
        lines.append("Not a fix (never recommend these): " + "; ".join(entry["not_a_fix"]))
    if entry.get("verify"):
        lines.append("Typical verification: " + "; ".join(entry["verify"]))
    return "\n".join(lines)
