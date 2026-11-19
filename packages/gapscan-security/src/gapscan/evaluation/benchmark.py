"""OWASP Benchmark scorecard (BenchmarkJava, BenchmarkPython): for each test case the project publishes whether it
holds a real vulnerability. A tool "flags" a test case when it reports a finding in that file for
the expected weakness. Per category: TPR = real cases flagged / real cases, FPR = fake cases
flagged / fake cases, score = TPR - FPR (Youden), the method behind published tool scorecards."""

from __future__ import annotations

import csv
import random
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding

# Benchmark category -> CWEs a finding may carry to count as the same weakness class.
CATEGORY_CWES: dict[str, set[str]] = {
    "cmdi": {"CWE-78", "CWE-77", "CWE-88"},
    "crypto": {"CWE-327", "CWE-326", "CWE-328"},
    "hash": {"CWE-328", "CWE-327", "CWE-916", "CWE-759", "CWE-760"},
    "ldapi": {"CWE-90"},
    "pathtraver": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "securecookie": {"CWE-614", "CWE-1004", "CWE-311"},
    "sqli": {"CWE-89", "CWE-564"},
    "trustbound": {"CWE-501"},
    "weakrand": {"CWE-330", "CWE-338", "CWE-331"},
    "xpathi": {"CWE-643"},
    "xss": {"CWE-79", "CWE-80"},
    # BenchmarkPython only
    "codeinj": {"CWE-94", "CWE-95"},
    "deserialization": {"CWE-502"},
    "redirect": {"CWE-601"},
    "xxe": {"CWE-611", "CWE-776"},
}
_TEST_FILE = re.compile(r"(BenchmarkTest\d{5})\.(java|py)$")


@dataclass(frozen=True)
class TestCase:
    name: str
    category: str
    real: bool
    cwe: str


def load_expected(csv_path: Path) -> dict[str, TestCase]:
    cases: dict[str, TestCase] = {}
    with csv_path.open(encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#") or len(row) < 4:
                continue
            cases[row[0]] = TestCase(
                row[0], row[1], row[2].strip().lower() == "true", f"CWE-{row[3].strip()}"
            )
    return cases


def test_name(finding: Finding) -> str | None:
    m = _TEST_FILE.search(finding.file or "")
    return m.group(1) if m else None


def flags(finding: Finding, case: TestCase) -> bool:
    """Does this finding report the weakness class this test case is about?"""
    return bool(set(finding.cwe) & (CATEGORY_CWES.get(case.category, set()) | {case.cwe}))


def flagged_cases(findings: list[Finding], cases: dict[str, TestCase]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        name = test_name(f)
        if name in cases and flags(f, cases[name]):
            out[name].append(f)
    return out


def scorecard(flagged: set[str], cases: dict[str, TestCase]) -> dict[str, object]:
    per: dict[str, dict[str, int]] = defaultdict(
        lambda: {"real": 0, "real_flagged": 0, "fake": 0, "fake_flagged": 0}
    )
    for c in cases.values():
        b = per[c.category]
        key = "real" if c.real else "fake"
        b[key] += 1
        b[f"{key}_flagged"] += int(c.name in flagged)
    cats = {}
    for name, b in sorted(per.items()):
        tpr = b["real_flagged"] / b["real"] if b["real"] else 0.0
        fpr = b["fake_flagged"] / b["fake"] if b["fake"] else 0.0
        cats[name] = {**b, "tpr": round(tpr, 3), "fpr": round(fpr, 3), "score": round(tpr - fpr, 3)}
    real = sum(b["real"] for b in per.values())
    fake = sum(b["fake"] for b in per.values())
    tpr = sum(b["real_flagged"] for b in per.values()) / real if real else 0.0
    fpr = sum(b["fake_flagged"] for b in per.values()) / fake if fake else 0.0
    avg = sum(c["score"] for c in cats.values()) / len(cats) if cats else 0.0
    return {"overall": {"tpr": round(tpr, 3), "fpr": round(fpr, 3), "score": round(tpr - fpr, 3),
                        "category_average_score": round(avg, 3), "real": real, "fake": fake},
            "categories": cats}  # fmt: skip


def triage_sample(
    flagged: dict[str, list[Finding]], cases: dict[str, TestCase], per_group: int, seed: int = 11
) -> list[tuple[Finding, TestCase]]:
    """A reproducible sample for the (slow) model review: per category, up to `per_group` flagged
    real cases and `per_group` flagged fake ones, taking each case's highest-priority finding."""
    rng = random.Random(seed)
    groups: dict[tuple[str, bool], list[str]] = defaultdict(list)
    for name in flagged:
        groups[(cases[name].category, cases[name].real)].append(name)
    picked: list[tuple[Finding, TestCase]] = []
    for key in sorted(groups):
        names = sorted(groups[key])
        rng.shuffle(names)
        for name in names[:per_group]:
            best = max(flagged[name], key=lambda f: f.priority)
            picked.append((best, cases[name]))
    return picked
