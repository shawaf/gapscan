"""Facts about a secret finding, derived locally from its value without keeping or sending it.

The model never sees secret values (hard rule), so it cannot tell a real key from a placeholder.
GapScan can: it reads the flagged line from disk, computes a few properties (format, length,
character mix, placeholder words) and throws the value away. Only these facts are stored, shown
to the model and used by the triage policy. Also: whether git ignores the file (not committed),
and Firebase client keys, which are public by design and collapse to one informational finding.
"""

from __future__ import annotations

import math
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from .context.variants import shipped_in
from .models import Category, Finding, Severity

FIREBASE_FILES = {"google-services.json", "GoogleService-Info.plist"}
# The Google Services Gradle plugin output, or the same values copied by hand into Android resources
_FIREBASE_RES = re.compile(r'name="(?:google_api_key|google_app_id|gcm_defaultSenderId)"')
# Keys their vendors issue to be embedded in clients: finding one is not a leak
_PUBLIC_FORMATS: list[tuple[str, re.Pattern[str]]] = [
    ("PostHog project key (public)", re.compile(r"\bphc_[A-Za-z0-9]{20,}")),
    ("Stripe publishable key (public)", re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{16,}")),
]
_FORMATS: list[tuple[str, re.Pattern[str]]] = [
    ("private key (PEM)", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Google service account key", re.compile(r'"type"\s*:\s*"service_account"|"private_key_id"')),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}")),
    ("Slack webhook", re.compile(r"hooks\.slack\.com/services/[A-Z0-9]+/")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{16,}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
]
_PLACEHOLDER = re.compile(
    r"(?i)(changeme|change_me|replace|your[_\-\s]?\w*?(api|secret|key|token|password)|_here$|example|dummy|sample|"
    r"placeholder|xxxx|\*\*\*\*|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%[A-Z_]+%|todo|fixme|"
    r"00000000|12345678|test[_\-]?(key|secret|token)|fake|redacted)"
)
_VALUE = re.compile(r"""[=:]\s*["']?([^\s"',;]{8,})""")
# `name = OtherClass.member` with no quotes: an identifier in code, not a value
_CODE_REF = re.compile(r"""[=:]\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\s*[,;)]?\s*$""")


def _sequential(value: str) -> bool:
    """Doc examples like `abCd3fGhijK1mN0pQr5t`: the letters walk up the alphabet."""
    letters = [c for c in value.lower() if c.isalpha()]
    if len(letters) < 8:
        return False
    steps = sum(1 for a, b in zip(letters, letters[1:], strict=False) if 0 < ord(b) - ord(a) <= 2)
    return steps >= 0.8 * (len(letters) - 1)


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values()) if text else 0.0


def _read_lines(target: Path, finding: Finding) -> str:
    if not finding.file or not finding.start_line:
        return ""
    try:
        lines = (target / finding.file).read_text("utf-8", "replace").splitlines()
    except OSError:
        return ""
    start = max(0, finding.start_line - 1)
    end = min(len(lines), max(finding.end_line or finding.start_line, finding.start_line) + 1)
    return "\n".join(lines[start : min(end, start + 30)])


def _read_file(target: Path, rel: str) -> str:
    try:
        return (target / rel).read_text("utf-8", "replace")[:200_000]
    except OSError:
        return ""


def describe(text: str) -> dict[str, object]:
    """Properties of the flagged text. The text itself is not returned."""
    facts: dict[str, object] = {}
    public = next((name for name, rx in _PUBLIC_FORMATS if rx.search(text)), "")
    fmt = public or next((name for name, rx in _FORMATS if rx.search(text)), "")
    facts["format"] = fmt or "unrecognized"
    facts["public_client_key"] = bool(public)
    facts["code_reference"] = bool(
        not fmt and any(_CODE_REF.search(ln) for ln in text.splitlines())
    )
    m = _VALUE.search(text)
    value = m.group(1) if m else text.strip()
    facts["placeholder"] = (
        bool(_PLACEHOLDER.search(value)) or len(set(value)) <= 3 or _sequential(value)
    )
    facts["length"] = len(value)
    ent = _entropy(value)
    facts["randomness"] = "high" if ent >= 3.5 else "medium" if ent >= 2.5 else "low"
    facts["env_reference"] = bool(
        re.search(r"process\.env|os\.environ|getenv|System\.getenv|\$\{", text)
    )
    return facts


def git_ignored(target: Path, files: list[str]) -> set[str]:
    """Which of these files git ignores (never committed unless forced). Uses `git check-ignore`,
    which reads .gitignore files only: no hooks, nothing of the project is executed."""
    if not files or shutil.which("git") is None or not (target / ".git").exists():
        return set()
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argument list, file names on stdin
            ["git", "-C", str(target), "check-ignore", "--stdin", "--no-index"],
            input="\n".join(files), capture_output=True, text=True, timeout=20, check=False,
        )  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return set()
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


def annotate_secrets(findings: list[Finding], target: Path) -> list[Finding]:
    """Add `raw["secret_facts"]` to every secret finding, collapse Firebase client keys to one
    informational finding per file, and return the list."""
    secrets = [f for f in findings if f.category == Category.SECRET]
    ignored = git_ignored(target, sorted({f.file for f in secrets if f.file}))
    out: list[Finding] = []
    firebase_seen: set[str] = set()
    firebase_res = {
        f.file for f in secrets
        if f.file and "/res/values" in f"/{f.file}" and f.file.endswith(".xml")
        and _FIREBASE_RES.search(_read_file(target, f.file))
    }  # fmt: skip
    for f in findings:
        if f.category != Category.SECRET:
            out.append(f)
            continue
        facts = describe(_read_lines(target, f))
        facts["gitignored"] = bool(f.file and f.file in ignored)
        facts["shipped_in_app"] = bool(f.raw.get("shipped_in_app"))
        benign = any(facts.get(k) for k in ("placeholder", "env_reference", "code_reference",
                                             "public_client_key"))  # fmt: skip
        if not facts["shipped_in_app"] and f.file and not benign:
            shipped = shipped_in(target, f.file)
            if shipped:  # compiled into the APK of these variants
                facts["shipped_in_app"] = True
                facts["shipped_variants"] = shipped
        name = Path(f.file or "").name
        firebase = name in FIREBASE_FILES or f.file in firebase_res
        if firebase and facts["format"] in ("Google API key", "unrecognized"):
            if f.file in firebase_seen:
                continue  # one finding per file: every client entry repeats the same project key
            firebase_seen.add(f.file or "")
            facts["firebase_client_key"] = True
            f.severity = Severity.INFO
            f.title = "Firebase client API key (public by design: restrict it, do not hide it)"
            f.message = (
                "Firebase API keys (google-services.json, GoogleService-Info.plist or the Android "
                "string resources generated from them) identify the "
                "project and ship in every app build; Google documents them as not secret. "
                "Protect the project instead: restrict the key to your app's package and SHA-1 "
                "(Android) or bundle ID (iOS) and to the APIs it needs in Google Cloud Console, "
                "enable App Check, and lock down Firebase Security Rules."
            )
        elif facts["public_client_key"] or facts["code_reference"]:
            f.severity = Severity.LOW if facts["code_reference"] else Severity.INFO
            if facts["public_client_key"]:
                f.title = f"{facts['format']}: issued to be embedded in apps, not a leak"
        elif facts["placeholder"] and facts["format"] == "unrecognized":
            # still reviewed; a real key in a known format is never lowered
            f.severity = Severity.LOW
        elif facts["gitignored"] and not facts["shipped_in_app"]:
            f.severity = {Severity.CRITICAL: Severity.HIGH, Severity.HIGH: Severity.MEDIUM}.get(
                f.severity, f.severity
            )
        f.raw["secret_facts"] = facts
        out.append(f)
    return out


def summary(facts: dict[str, object]) -> str:
    """One line for the model and the report: never the value itself."""
    parts = [f"format: {facts.get('format')}", f"length {facts.get('length')}",
             f"randomness {facts.get('randomness')}"]  # fmt: skip
    if facts.get("placeholder"):
        parts.append("looks like a placeholder")
    if facts.get("env_reference"):
        parts.append("read from the environment, not written in the code")
    if facts.get("gitignored"):
        parts.append("file is ignored by git (not committed)")
    if facts.get("shipped_in_app"):
        variants = facts.get("shipped_variants")
        parts.append("packaged inside the app build" + (
            f" (compiled into the {', '.join(str(v) for v in variants)} builds)"
            if isinstance(variants, list) and variants else ""))  # fmt: skip
    if facts.get("code_reference"):
        parts.append("the right-hand side is an identifier in code, not a literal value")
    if facts.get("public_client_key"):
        parts.append("a key its vendor issues for use in client apps (public)")
    if facts.get("firebase_client_key"):
        parts.append("Firebase client key (public by design)")
    return "; ".join(parts)
