"""Which lines the model has actually been shown, so anything it cites can be checked
(hard rule #5). Used by the deep dive (investigate.py) and by triage traces (trace.py)."""

from __future__ import annotations

import re
from collections import defaultdict

from ..models import CodeContext

_REF = re.compile(r"^\s*(?P<file>[^\s:][^:]*?):(?P<lo>\d+)(?:\s*-\s*(?P<hi>\d+))?\s*$")
_CODE_LINE = re.compile(r"^(?:>>|  )\s*(\d+) \|", re.MULTILINE)


class Seen:
    """Which lines of which files the model has been shown, plus searches that proved absence."""

    def __init__(self) -> None:
        self.lines: dict[str, set[int]] = defaultdict(set)
        # lower-cased text of each complete, empty search -> the glob it covered ("" = all files)
        self.empty_searches: dict[str, str] = {}

    def add(self, file: str, lo: int, hi: int) -> None:
        self.lines[_norm(file)].update(range(lo, hi + 1))

    def covers(self, ref: str) -> bool:
        m = _REF.match(ref)
        if m is None:
            return False
        lo = int(m["lo"])
        hi = int(m["hi"] or lo)
        if hi < lo:
            return False
        shown = self.lines.get(_norm(m["file"]), set())
        return lo in shown and hi in shown


def _norm(path: str) -> str:
    p = path.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def seen_from_context(context: CodeContext | None) -> Seen:
    """Lines the prompt itself shows: the finding's code window, same-file helpers and
    definitions, and its callers."""
    seen = Seen()
    if context is not None:
        # The code window, plus same-file helpers and module-level definitions (also numbered).
        for block in [context.code, *context.helpers, *context.definitions]:
            for n in _CODE_LINE.findall(block or ""):
                seen.add(context.file, int(n), int(n))
    if context is not None:
        for c in context.callers:
            seen.add(c.file, c.line, c.line)
    return seen
