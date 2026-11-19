"""Root-cause grouping for the deep dive.

Several scanners (and several rules of one scanner) often report the same bug: five rules flag
one string-built SQL query. Investigating each separately wastes model time and produces five
near-identical write-ups. Findings are grouped when they describe the same weakness at the same
place; the group is investigated once and the result is shown on every member.

Same weakness is decided from the rule text first (scanner CWEs are noisy: SQL injection rules
carry CWE-89, CWE-704 or CWE-915), then from the CWEs, then from the rule id. Lines on one line
can still be different bugs (command injection and XSS at the same `return`), so place alone is
never enough.
"""

from __future__ import annotations

import hashlib
import re

from ..models import Category, Finding

# (weakness class, pattern over rule id / title / message), first match wins.
_KINDS = [
    ("sql-injection", re.compile(r"sql", re.I)),
    ("xss", re.compile(r"xss|cross.site.script|html response", re.I)),
    # Not plain "command": config rules say things like "add a USER command".
    (
        "command-injection",
        re.compile(r"subprocess|command.injection|shell.true|os\.system|popen", re.I),
    ),
    ("deserialization", re.compile(r"deserial|pickle|marshal|yaml.load", re.I)),
    ("weak-hash", re.compile(r"md5|sha-?1\b|weak.hash|insecure.hash", re.I)),
    ("container-root", re.compile(r"missing-user|\broot\b|user for the container", re.I)),
    ("path-traversal", re.compile(r"path.traversal|directory.traversal", re.I)),
    ("ssrf", re.compile(r"ssrf|server.side.request", re.I)),
]


def weakness_class(f: Finding) -> str:
    for text in (f.rule_id, f"{f.title} {f.message}"):
        for name, pattern in _KINDS:
            if pattern.search(text):
                return name
    return ",".join(sorted(f.cwe)) or f.rule_id


# Findings about an import rather than a call (Bandit B4xx: "consider the security implications
# of the subprocess module"): they belong with the calls of that module in the same file.
_IMPORT_LEVEL = re.compile(r"\bimport\b|\bmodule\b", re.I)


def _import_level(f: Finding) -> bool:
    return bool(re.fullmatch(r"B4\d\d", f.rule_id)) or bool(_IMPORT_LEVEL.search(f.title))


def _same_root_cause(a: Finding, b: Finding) -> bool:
    if a.category != b.category:
        return False
    if a.category == Category.DEPENDENCY:  # one fix: upgrade that package version
        return (
            bool(a.package)
            and (a.package or "").lower() == (b.package or "").lower()
            and (a.version == b.version)
        )
    if a.file != b.file or a.file is None:
        return False
    if a.category == Category.SECRET:
        return a.start_line == b.start_line
    if weakness_class(a) != weakness_class(b):
        return False
    if a.start_line is None or b.start_line is None:  # file-level result (e.g. a Dockerfile rule)
        return True
    if _import_level(a) or _import_level(b):  # the import enables every use in the file
        return True
    a_end, b_end = a.end_line or a.start_line, b.end_line or b.start_line
    return a.start_line <= b_end and b.start_line <= a_end


def group_findings(findings: list[Finding]) -> list[list[Finding]]:
    """Connected groups of findings with the same root cause, each sorted by priority (the
    first member is the one investigated); groups keep the order of their first member."""
    parent = list(range(len(findings)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            if _same_root_cause(findings[i], findings[j]):
                parent[root(j)] = root(i)
    groups: dict[int, list[Finding]] = {}
    for i, f in enumerate(findings):
        groups.setdefault(root(i), []).append(f)
    return [sorted(g, key=lambda f: (-f.priority, f.id)) for g in groups.values()]


def group_id(members: list[Finding]) -> str:
    """Stable id from the member finding ids (which are themselves stable fingerprints)."""
    key = "|".join(sorted(f.id for f in members))
    return hashlib.sha256(key.encode()).hexdigest()[:16]
