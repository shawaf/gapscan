"""Deterministic review rules that run before the model and need no model.

Two kinds, both computed in Python and always shown with their reason (never silent):

* Noise: findings that are provably not a security weakness (code-quality hints, an Android
  launcher activity that must be exported, informational notices). Reported as dismissed with the
  rule that did it.
* Purpose of a weak algorithm: weak hashes, ciphers and random generators are judged by what the
  value is used for, which a model gets wrong more than half the time (published studies and our
  own runs). The names around the code decide: security-sensitive use is confirmed, clearly
  non-security use is dismissed, and anything unclear stays a (lower-confidence) weakness.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..models import CodeContext, Finding, TriageAnswer, Verdict, VerdictLabel
from .triage import build_verdict

RULES_PROMPT_VERSION = "rules_v1"
RULES_MODEL = "gapscan-rules"

# --------------------------------------------------------------------------- noise


def _rule_tail(finding: Finding) -> str:
    return finding.rule_id.rsplit(".", 1)[-1].lower()


# The open tag ends at the first ">" (self-closing "/>" has no body); a body ends at </activity>.
_ACTIVITY = re.compile(r"<activity\b[^>]*?(?:/>|>.*?</activity>)", re.DOTALL | re.IGNORECASE)


def _is_launcher_activity(finding: Finding, target: Path) -> bool:
    """True when the exported activity at the finding's line declares MAIN + LAUNCHER."""
    if not finding.file or finding.start_line is None or not finding.file.endswith(".xml"):
        return False
    path = (target / finding.file).resolve()
    if not path.is_relative_to(target.resolve()) or not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for m in _ACTIVITY.finditer(text):
        first = text.count("\n", 0, m.start()) + 1
        last = text.count("\n", 0, m.end()) + 1
        if first <= finding.start_line <= last:
            block = m.group(0)
            return (
                "android.intent.action.MAIN" in block
                and "android.intent.category.LAUNCHER" in block
            )
    return False


@dataclass(frozen=True)
class NoiseRule:
    name: str
    reason: str
    applies: Callable[[Finding, Path], bool]


NOISE_RULES: tuple[NoiseRule, ...] = (
    NoiseRule(
        "code-quality-hint",
        "A code-quality or style hint, not a security weakness (resource handling, default "
        "encoding, missing status check).",
        lambda f, _t: (
            _rule_tail(f)
            in {"open-never-closed", "unspecified-open-encoding", "use-raise-for-status"}
        ),
    ),
    NoiseRule(
        "launcher-activity",
        "The activity is the app's launcher (MAIN + LAUNCHER), which Android requires to be "
        "exported.",
        lambda f, t: _rule_tail(f) == "exported_activity" and _is_launcher_activity(f, t),
    ),
    NoiseRule(
        "cookie-hardening-hint",
        "Informational cookie hardening hint (default name, no domain, path or expiry set); it "
        "does not expose the session. Missing Secure or HttpOnly flags are reported separately.",
        lambda f, _t: (
            _rule_tail(f)
            in {
                "express-cookie-session-default-name",
                "express-cookie-session-no-domain",
                "express-cookie-session-no-path",
                "express-cookie-session-no-expires",
            }
        ),
    ),
    NoiseRule(
        "informational-notice",
        "An informational notice about which setting takes precedence, not a weakness itself; "
        "the actual setting is reported on its own.",
        lambda f, _t: _rule_tail(f) == "manifest-usescleartexttraffic-ignored-by-nsc",
    ),
)

# --------------------------------------------------------------------------- purpose

WEAK_ALGORITHM_CWES = {
    "CWE-327", "CWE-326", "CWE-328", "CWE-330", "CWE-331", "CWE-338", "CWE-916", "CWE-759",
    "CWE-760",
}  # fmt: skip
SENSITIVE = {
    "password", "passwd", "pwd", "passphrase", "secret", "token", "session", "auth",
    "authenticate", "authorization", "credential", "credentials", "signature", "sign", "signing",
    "hmac", "encrypt", "decrypt", "otp", "nonce", "csrf", "apikey", "salt", "login", "pin", "jwt",
    "cookie", "verify", "challenge", "reset",
}  # fmt: skip
BENIGN = {
    "etag", "cache", "cached", "checksum", "fingerprint", "dedupe", "dedup", "bucket", "shard",
    "partition", "thumbnail", "avatar", "color", "colour", "shuffle", "jitter", "backoff",
    "animation", "memoize", "lru",
}  # fmt: skip
# Words such as test, sample, demo or benchmark are NOT here: they appear in package and class
# names of real code (the OWASP Benchmark's own packages contain "benchmark") and say nothing
# about what a value is used for.
_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_NOT_SECURITY = re.compile(r"usedforsecurity\s*=\s*False", re.IGNORECASE)
_DECLARATION = re.compile(
    r"^\s*(?:\d+\s*[:|]?\s*)?(?:>>\s*)?(?:import|package|using|from)\b.*$", re.MULTILINE
)


def words(text: str) -> set[str]:
    return {w.lower() for w in _WORDS.findall(text)}


def purpose_of(finding: Finding, context: CodeContext | None) -> tuple[str, set[str]]:
    """("sensitive" | "benign" | "unknown", the words that decided it). Only names and code are
    read, never the file path (a path such as `testcode/` would otherwise excuse everything)."""
    text = " ".join(
        part
        for part in (
            context.function_signature if context else None,
            context.code if context else None,
            finding.snippet,
        )
        if part
    )
    if _NOT_SECURITY.search(text):
        return "benign", {"usedforsecurity=False"}
    tokens = words(_DECLARATION.sub("", text))  # package and import names say nothing about use
    sensitive = tokens & SENSITIVE
    if sensitive:
        return "sensitive", sensitive
    benign = tokens & BENIGN
    if benign:
        return "benign", benign
    return "unknown", set()


def _answer(
    finding: Finding, label: VerdictLabel, confidence: float, reasoning: str, note: str
) -> Verdict:
    v = build_verdict(
        finding,
        TriageAnswer(verdict=label, confidence=confidence, reasoning=reasoning[:700]),
        RULES_PROMPT_VERSION,
        RULES_MODEL,
    )
    return v.model_copy(update={"policy_notes": [*v.policy_notes, note]})


def noise_verdict(finding: Finding, target: Path) -> Verdict | None:
    for rule in NOISE_RULES:
        if rule.applies(finding, target):
            return _answer(
                finding,
                VerdictLabel.FALSE_POSITIVE,
                0.9,
                f"Not a security weakness. {rule.reason}",
                f"Dismissed by GapScan rule noise.{rule.name}, not by the model.",
            )
    return None


def purpose_verdict(finding: Finding, context: CodeContext | None) -> Verdict | None:
    if finding.category.value != "code" or not set(finding.cwe) & WEAK_ALGORITHM_CWES:
        return None
    kind, hits = purpose_of(finding, context)
    shown = ", ".join(sorted(hits)) or "nothing that says what it is for"
    if kind == "sensitive":
        return _answer(
            finding,
            VerdictLabel.TRUE_POSITIVE,
            0.85,
            f"A weak algorithm is used where the surrounding code names a security purpose "
            f"({shown}). Use a strong, purpose-built primitive instead.",
            "Weak-algorithm purpose check (GapScan rules, not the model): sensitive use.",
        )
    if kind == "benign":
        return _answer(
            finding,
            VerdictLabel.FALSE_POSITIVE,
            0.8,
            f"A weak algorithm, but the surrounding code shows a non-security purpose ({shown}) "
            f"and nothing security-sensitive. Acceptable here; switch if the purpose changes.",
            "Weak-algorithm purpose check (GapScan rules, not the model): non-security use.",
        )
    return _answer(
        finding,
        VerdictLabel.LIKELY_TRUE_POSITIVE,
        0.6,
        "A weak algorithm is used and the surrounding code does not show a non-security purpose, "
        "so it is treated as a weakness.",
        "Weak-algorithm purpose check (GapScan rules, not the model): purpose unclear.",
    )


def deterministic_verdict(
    finding: Finding, context: CodeContext | None, target: Path
) -> Verdict | None:
    """A verdict from rules alone, or None when the model should decide."""
    return noise_verdict(finding, target) or purpose_verdict(finding, context)
