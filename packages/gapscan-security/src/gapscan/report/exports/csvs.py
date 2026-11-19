"""CSV exports. Cells that start with a formula character are neutralized so scanned content
cannot run as a spreadsheet formula."""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence

from ..schema import ReportData

_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: object) -> str:
    if isinstance(value, (list, tuple)):
        value = ";".join(str(v) for v in value)
    text = "" if value is None else str(value)
    return f"'{text}" if text.startswith(_FORMULA) else text


def _csv(header: list[str], rows: Sequence[Sequence[object]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    for row in rows:
        w.writerow([_cell(v) for v in row])
    return buf.getvalue()


def findings_csv(data: ReportData) -> str:
    header = ["id", "open", "severity", "category", "verdict", "confidence", "risk_points", "title", "file",
              "start_line", "end_line", "cwe", "owasp", "asvs", "scanners", "package", "version",
              "fixed_version", "cve", "kev", "epss", "decision"]  # fmt: skip
    rows = [[r.id, r.open, r.severity_adjusted or r.severity, r.category, r.verdict, r.confidence, r.risk_points,
             r.title, r.file, r.start_line, r.end_line, r.cwe, r.owasp, r.asvs, r.scanners, r.package,
             r.version, r.fixed_version, r.cve, r.kev, r.epss, r.decision] for r in data.findings]  # fmt: skip
    return _csv(header, rows)


def asvs_csv(data: ReportData) -> str:
    header = ["id", "level", "chapter", "section", "status", "requirement", "finding_ids"]
    a = data.asvs
    rows = [
        [r.id, r.level, r.chapter, r.section, r.status, r.text, r.finding_ids]
        for r in (a.requirements if a else [])
    ]
    return _csv(header, rows)
