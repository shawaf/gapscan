"""Stable finding IDs (needed by Stage 2: lifecycle tracking, diff-aware scanning, org memory).

A finding must keep its ID when the code around it moves or when scanners run in a different
order, so the ID is built from *what* the issue is and *where it is semantically*, not from
line numbers or the reporting scanner:

  category + file + issue key (sorted CWEs, else rule id) + digest of the flagged source text
  (whitespace-normalized) + an occurrence index to tell identical issues in one file apart.

Dependency findings use package, version, manifest file and CVE/advisory ids. Secret findings
never hash the secret's line (the digest of a low-entropy secret could be brute-forced), so
they rely on rule + occurrence order instead.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path

from .models import Category, Finding

_LINE_NUMBER_PREFIX = re.compile(r"^\s*\d+\s+", re.MULTILINE)  # e.g. Bandit's "10 foo()"
MAX_FILE_BYTES = 2_000_000


def normalize_text(text: str) -> str:
    """Drop line-number prefixes and all whitespace so reformatting keeps the digest."""
    return "".join(_LINE_NUMBER_PREFIX.sub("", text).split())


def _flagged_text(f: Finding, target: Path) -> str:
    """The flagged source lines from the file itself, else the scanner's snippet."""
    if f.file and f.start_line:
        root = target.resolve()
        path = (root / f.file).resolve()
        try:
            if (
                path.is_relative_to(root)
                and path.is_file()
                and path.stat().st_size <= MAX_FILE_BYTES
            ):
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                end = f.end_line or f.start_line
                return normalize_text("\n".join(lines[f.start_line - 1 : end]))
        except OSError:
            pass
    return normalize_text(f.snippet or "")


def _base_key(f: Finding, target: Path) -> str:
    if f.category == Category.DEPENDENCY:
        advisories = sorted(f.cve) or [f.rule_id]
        return "|".join(
            ["dep", f.file or "", f.package or "", f.version or "", ",".join(advisories)]
        )
    issue = ",".join(sorted(f.cwe)) or f.rule_id
    # Secrets: no content digest (see module docstring); their rule id keeps kinds apart.
    digest = "" if f.category == Category.SECRET else _flagged_text(f, target)
    rule = f.rule_id if f.category == Category.SECRET else ""
    return "|".join([f.category.value, f.file or "", issue, rule, digest])


def assign_stable_ids(findings: list[Finding], target: Path) -> None:
    """Set `id` on every finding in place. Identical issues in one file get an occurrence
    index in line order, so inserting code above them does not reshuffle their IDs."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[_base_key(f, target)].append(f)
    for key, members in groups.items():
        members.sort(key=lambda f: (f.start_line or 0, f.end_line or 0, f.rule_id))
        for index, f in enumerate(members):
            f.id = hashlib.sha256(f"{key}|{index}".encode()).hexdigest()[:16]
