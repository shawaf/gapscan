"""`taint` scanner adapter: runs the taint engine and reports source-to-sink paths."""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Category, Finding, Severity
from .engine import Hit, scan_dir

log = logging.getLogger(__name__)

_SEV = {s.value: s for s in Severity}


def hit_to_finding(h: Hit) -> Finding:
    path = " -> ".join(h.steps)
    return Finding(
        scanner="taint",
        rule_id=f"gapscan.taint.{h.kind}",
        title=h.title,
        severity=_SEV.get(h.severity, Severity.MEDIUM),
        category=Category.CODE,
        cwe=[h.cwe],
        file=h.file,
        start_line=h.line,
        end_line=h.line,
        snippet=h.snippet,
        message=(
            f"Untrusted data from a {h.source_kind} source ({h.source_file}:{h.source_line}) "
            f"reaches a {h.kind} sink without a recognized sanitizer. Path: {path}"
        ),
        raw={
            "taint_path": list(h.steps),
            "source": {"kind": h.source_kind, "file": h.source_file, "line": h.source_line},
            "cross_file": h.cross_file,
        },
    )


class TaintScanner:
    """In-process scanner: pure Python over tree-sitter, so it works wherever GapScan does."""

    name = "taint"

    def __init__(self, timeout_s: int = 300) -> None:
        self.timeout_s = timeout_s

    def is_available(self) -> bool:
        return True

    def version(self) -> str:
        return "1"

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        return [hit_to_finding(h) for h in scan_dir(target)]
