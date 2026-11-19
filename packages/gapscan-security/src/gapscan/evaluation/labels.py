"""Ground truth for the hand-labeled fixtures and matching of findings to it.

A finding's truth: it is *vulnerable* only if it sits within TOLERANCE lines of a label that is
marked vulnerable and describes a compatible weakness (shared CWE, or the same OWASP Top 10
category). Everything else is not a vulnerability by the fixtures' construction: findings at
look-alike safe sites ("bait") and stray findings elsewhere in a labeled file."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding

TOLERANCE = 3  # lines either side of the labeled sink (multi-line statements)


@dataclass(frozen=True)
class Label:
    id: str
    file: str
    line: int
    cwe: str
    owasp: str
    vulnerable: bool
    kind: str  # standard | bait | injection


def load_labels(directory: Path) -> list[Label]:
    raw = json.loads((directory / "labels.json").read_text(encoding="utf-8"))
    return [
        Label(c["id"], c["file"], c["line"], c["cwe"], c["owasp"], c["vulnerable"], c["kind"])
        for c in raw["cases"]
    ]


# Scanners tag the same weakness with different CWEs (Bandit's yaml_load is CWE-20, Semgrep's
# Flask SQL rule carries CWE-704), so a finding at a labeled sink also counts as "about" the
# weakness when its rule id or title names it. Words are specific on purpose: "requests" or "file"
# would also match best-practice rules next to the sink.
KEYWORDS: dict[str, tuple[str, ...]] = {
    "CWE-89": ("sql",),
    "CWE-78": ("command", "subprocess", "system-call", "os-system", "shell", "popen", "exec"),
    "CWE-22": ("traversal", "path-join", "send-file", "zip", "extractall", "tar"),
    "CWE-79": ("xss", "cross-site"),
    "CWE-918": ("ssrf", "request-forgery"),
    "CWE-502": ("deserial", "pickle", "yaml", "unmarshal", "objectinputstream"),
    "CWE-327": ("md5", "sha1", "ecb", "weak-hash", "insecure-hash", "cipher", "des "),
    "CWE-338": ("random",),
    "CWE-330": ("random",),
    "CWE-798": ("secret", "hardcoded", "api-key", "password"),
    "CWE-95": ("eval",),
    "CWE-611": ("xxe", "xml-external", "external-entit", "doctype", "xmlparser", "documentbuilder"),
    "CWE-601": ("redirect",),
    "CWE-295": ("tls", "ssl", "certificate", "verify", "trust", "hostname"),
    "CWE-347": ("jwt",),
    "CWE-1336": ("template", "ssti"),
    "CWE-942": ("cors", "access-control"),
    "CWE-614": ("secure-flag", "httponly", "insecure-cookie", "cookie-secure", "no-secure"),
    "CWE-312": ("cleartext", "shared-pref", "sharedpref", "userdefaults", "plaintext"),
}


def compatible(label: Label, finding: Finding) -> bool:
    # Same CWE, or a rule that names the weakness. Sharing only an OWASP Top 10 category is not
    # enough: "cookie has no domain" is not "cookie sent over plain HTTP", and counting it would
    # overstate recall and make the model look wrong for dismissing it.
    if label.cwe in finding.cwe:
        return True
    text = f"{finding.rule_id} {finding.title}".lower()
    return any(word in text for word in KEYWORDS.get(label.cwe, ()))


def near(label: Label, finding: Finding) -> bool:
    if finding.file != label.file or finding.start_line is None:
        return False
    end = finding.end_line or finding.start_line
    return finding.start_line <= label.line + TOLERANCE and end >= label.line - TOLERANCE


@dataclass(frozen=True)
class Truth:
    vulnerable: bool
    site: str | None  # id of the label this finding belongs to (None: stray finding)
    kind: str  # kind of that label, or "stray"


def finding_truth(finding: Finding, labels: list[Label]) -> Truth:
    nearby = [lb for lb in labels if near(lb, finding)]
    for lb in nearby:  # a compatible vulnerable site wins
        if lb.vulnerable and compatible(lb, finding):
            return Truth(True, lb.id, lb.kind)
    if nearby:
        lb = min(nearby, key=lambda x: abs((finding.start_line or 0) - x.line))
        return Truth(False, lb.id, lb.kind)
    return Truth(False, None, "stray")
