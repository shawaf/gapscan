"""Score the taint engine against a labeled corpus.

Markers in the corpus (comments, any language):
    VULN:<kind>   this line is a sink that attacker data must reach
    SAFE          this line must produce no finding
    SAFE-FLOW     data read on this line must not reach any sink
Any finding on a line without a VULN marker for its kind counts as a false alarm.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engine import Hit, scan_dir

_VULN = re.compile(r"VULN:([\w+]+)")


@dataclass
class Score:
    expected: int = 0
    found: int = 0
    false_alarms: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    safe_flow_leaks: list[str] = field(default_factory=list)
    safe_flows: int = 0
    by_kind: dict[str, list[int]] = field(default_factory=dict)  # kind -> [expected, found]

    @property
    def recall(self) -> float:
        return self.found / self.expected if self.expected else 1.0

    @property
    def safe_flow_ok(self) -> float:
        return 1 - len(self.safe_flow_leaks) / self.safe_flows if self.safe_flows else 1.0


def score(corpus: Path, hits: list[Hit] | None = None) -> Score:
    hits = scan_dir(corpus) if hits is None else hits
    sc = Score()
    expected: dict[tuple[str, int], set[str]] = {}
    safe_flow: set[tuple[str, int]] = set()
    for f in sorted(corpus.rglob("*")):
        if not f.is_file():
            continue
        rel = str(f.relative_to(corpus))
        for i, line in enumerate(f.read_text("utf-8", "replace").splitlines(), 1):
            m = _VULN.search(line)
            if m:
                expected[(rel, i)] = set(m.group(1).split("+"))
            if "SAFE-FLOW" in line:
                safe_flow.add((rel, i))
    by_sink = {(h.file, h.line): h for h in hits}
    for (rel, i), kinds in expected.items():
        for kind in sorted(kinds):
            sc.expected += 1
            entry = sc.by_kind.setdefault(kind, [0, 0])
            entry[0] += 1
            if any(h.file == rel and h.line == i and h.kind == kind for h in hits):
                sc.found += 1
                entry[1] += 1
            else:
                sc.missed.append(f"{rel}:{i} {kind}")
    for h in hits:
        if h.kind not in expected.get((h.file, h.line), set()):
            sc.false_alarms.append(f"{h.file}:{h.line} {h.kind}")
    sc.safe_flows = len(safe_flow)
    for h in hits:
        if (h.source_file, h.source_line) in safe_flow:
            sc.safe_flow_leaks.append(f"{h.source_file}:{h.source_line} -> {h.file}:{h.line}")
    del by_sink
    return sc


def format_score(name: str, sc: Score) -> str:
    kinds = ", ".join(f"{k} {v[1]}/{v[0]}" for k, v in sorted(sc.by_kind.items()))
    return (
        f"{name}: caught {sc.found}/{sc.expected} sinks ({sc.recall:.0%}); "
        f"{len(sc.false_alarms)} false alarms; safe flows kept clean "
        f"{sc.safe_flows - len(sc.safe_flow_leaks)}/{sc.safe_flows}. [{kinds}]"
    )


_KIND_CWE = {"CWE-89": "sql", "CWE-78": "cmd", "CWE-22": "path", "CWE-79": "xss", "CWE-918": "ssrf",
             "CWE-502": "deserialization", "CWE-601": "redirect", "CWE-95": "code", "CWE-94": "code",
             "CWE-90": "ldap", "CWE-643": "xpath", "CWE-943": "nosql"}  # fmt: skip
TAINT_LANGS = ("python", "java", "javascript")


def score_labeled(fixtures: Path, tolerance: int = 3) -> dict[str, Any]:
    """Score against the independent hand-labeled fixtures (`labels.json`): recall on vulnerable
    labels of taint-type CWEs, and false alarms on the look-alike safe ("bait") labels."""
    import json

    labels = json.loads((fixtures / "labels.json").read_text("utf-8"))["cases"]
    hits = scan_dir(fixtures)
    out: dict[str, Any] = {
        "vulnerable": 0,
        "caught": 0,
        "bait": 0,
        "bait_flagged": 0,
        "missed": [],
        "flagged_bait": [],
    }
    for c in labels:
        kind = _KIND_CWE.get(c["cwe"])
        if kind is None or c["file"].split("/")[0] not in TAINT_LANGS:
            continue
        near = [
            h
            for h in hits
            if h.file == c["file"] and abs(h.line - c["line"]) <= tolerance and h.kind == kind
        ]
        if c["vulnerable"]:
            out["vulnerable"] += 1
            if near:
                out["caught"] += 1
            else:
                out["missed"].append(c["id"])
        else:
            out["bait"] += 1
            if near:
                out["bait_flagged"] += 1
                out["flagged_bait"].append(c["id"])
    return out
