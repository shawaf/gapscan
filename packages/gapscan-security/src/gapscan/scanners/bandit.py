"""Bandit adapter (Python). JSON output; bandit exits 1 when it finds issues."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..models import Category, Finding, Severity
from .base import CommandScanner, ScannerError, mark_suppressed, relpath

_HARDCODED_PW = {"B105", "B106", "B107"}
_SEV = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def parse_bandit(data: dict[str, Any], target: Path) -> list[Finding]:
    out: list[Finding] = []
    for r in data.get("results", []):
        cwe = r.get("issue_cwe", {}).get("id")
        lines = r.get("line_range") or [r.get("line_number")]
        out.append(
            Finding(
                scanner="bandit",
                rule_id=r["test_id"],
                title=r.get("test_name", r["test_id"]).replace("_", " "),
                message=r.get("issue_text", ""),
                severity=_SEV.get(r.get("issue_severity", ""), Severity.MEDIUM),
                # B105/B106/B107: hardcoded password string/argument/default.
                category=Category.SECRET if r["test_id"] in _HARDCODED_PW else Category.CODE,
                cwe=[f"CWE-{cwe}"] if cwe else [],
                file=relpath(r.get("filename"), target),
                start_line=min(lines) if lines else None,
                end_line=max(lines) if lines else None,
                snippet=r.get("code"),
                raw={"confidence": r.get("issue_confidence")},
            )
        )
    return out


_NOSEC = re.compile(r"#\s*nosec\b", re.IGNORECASE)


def mark_nosec(findings: list[Finding], target: Path) -> list[Finding]:
    """Findings bandit reports on a `# nosec` line (only with --ignore-nosec) stay, marked."""
    cache: dict[str, list[str]] = {}
    for f in findings:
        if not f.file or not f.start_line:
            continue
        if f.file not in cache:
            try:
                cache[f.file] = (target / f.file).read_text(errors="replace").splitlines()
            except OSError:
                cache[f.file] = []
        lines = cache[f.file]
        end = f.end_line or f.start_line
        if any(
            _NOSEC.search(lines[n - 1]) for n in range(f.start_line, end + 1) if n <= len(lines)
        ):
            mark_suppressed(f, "`# nosec`")
    return findings


class BanditScanner(CommandScanner):
    name = "bandit"
    binary = "bandit"
    ok_returncodes = frozenset({0, 1})

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        out = workdir / "bandit.json"
        # GapScan's own (empty) settings: a `.bandit` file in the scanned project would otherwise
        # be read and could skip every test. `# nosec` lines are reported and marked instead.
        ini = workdir / "gapscan.bandit"
        ini.write_text("[bandit]\n", encoding="utf-8")
        proc = self._exec(
            [self.binary, "-r", str(target), "-f", "json", "-o", str(out), "-q",
             "--ini", str(ini), "--ignore-nosec"]
        )  # fmt: skip
        self.check(proc)
        if not out.is_file():
            raise ScannerError("bandit produced no output")
        return mark_nosec(parse_bandit(json.loads(out.read_text()), target), target)
