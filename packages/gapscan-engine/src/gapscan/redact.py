"""Secret redaction (hard rule #4). Scanners other than gitleaks quote the offending source
line, which for a hardcoded secret contains the secret itself. Every finding passes through
here before it leaves the scanner layer, so no secret value reaches findings, caches, logs
or reports.

Two layers: (1) any snippet overlapping a line that a secret finding points to is replaced
wholesale; (2) token-shaped strings and credential assignments are masked in all snippets
and messages as a safety net.
"""

from __future__ import annotations

import re
from collections import defaultdict

from .models import Category, Finding

PLACEHOLDER = "[REDACTED SECRET]"
SNIPPET_PLACEHOLDER = "[snippet withheld: line contains a possible secret]"

_TOKEN_PATTERNS = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),  # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS access key ids
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),  # Slack
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),  # API keys of the sk- family
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),  # Google API keys
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWTs
]
_ASSIGNMENT = re.compile(
    r"""(?ix)
    ((?:secret|passw(?:or)?d|passwd|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)
     [\w-]*["']?\s*[:=]\s*)
    (["'])([^"'\n]{8,})\2
    """
)


def mask(text: str) -> str:
    """Mask token-shaped strings and credential assignments inside free text."""
    for pat in _TOKEN_PATTERNS:
        text = pat.sub(PLACEHOLDER, text)
    return _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{PLACEHOLDER}{m.group(2)}", text)


def redact_findings(findings: list[Finding]) -> list[Finding]:
    """Redact in place and return the same list."""
    secret_lines: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for f in findings:
        if f.category == Category.SECRET and f.file and f.start_line:
            secret_lines[f.file].append((f.start_line, f.end_line or f.start_line))
    for f in findings:
        if f.snippet and f.snippet != PLACEHOLDER:
            near = f.file and f.start_line is not None and any(
                f.start_line <= hi and lo <= (f.end_line or f.start_line)
                for lo, hi in secret_lines.get(f.file, [])
            )  # fmt: skip
            f.snippet = SNIPPET_PLACEHOLDER if near else mask(f.snippet)
        f.message = mask(f.message)
        f.title = mask(f.title)
    return findings
