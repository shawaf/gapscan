"""What changed between two runs: one definition of new, fixed and unchanged findings, used by the
report's baseline section and by the manager's run comparison.

A finding is compared by its stable id among the *open* findings of each run: new when only the
newer run has it, fixed when only the older one does, unchanged when both do.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RunDiff:
    new: list[str]  # in the newer run's order
    fixed: list[str]  # in the older run's order
    unchanged: list[str]  # in the newer run's order


def diff_open(older: Iterable[str], newer: Iterable[str]) -> RunDiff:
    """Compare the open finding ids of two runs."""
    old, new = list(dict.fromkeys(older)), list(dict.fromkeys(newer))
    old_set, new_set = set(old), set(new)
    return RunDiff(new=[i for i in new if i not in old_set],
                   fixed=[i for i in old if i not in new_set],
                   unchanged=[i for i in new if i in old_set])  # fmt: skip


def brief(row: dict[str, Any]) -> dict[str, Any]:
    """One finding of a saved report, as a comparison lists it."""
    loc = row.get("file") or row.get("package") or "-"
    line = row.get("start_line")
    return {"id": row["id"], "title": row["title"],
            "severity": row.get("severity_adjusted") or row["severity"],
            "location": f"{loc}:{line}" if row.get("file") and line else loc,
            "verdict": row.get("verdict")}  # fmt: skip


def compare_reports(older: list[dict[str, Any]], newer: list[dict[str, Any]]) -> dict[str, Any]:
    """New and fixed findings (briefly) and the unchanged count, from the `findings` of two saved
    reports (`report.json`). Closed findings (decided or fixed) are not open, so they do not
    count."""
    a = {r["id"]: r for r in older if r.get("open")}
    b = {r["id"]: r for r in newer if r.get("open")}
    d = diff_open(a, b)
    return {"new": [brief(b[i]) for i in d.new], "fixed": [brief(a[i]) for i in d.fixed],
            "unchanged": len(d.unchanged)}  # fmt: skip
