"""Evaluation metrics: scanner detection, triage accuracy, false-positive reduction, OWASP Top 10
detection rates, and the OWASP Benchmark scorecard (TPR vs FPR per category).

Definitions (so results are comparable run to run):
- recall: vulnerable labeled sites with at least one compatible finding / all vulnerable sites.
- triage correct: a vulnerable finding judged true_positive or likely_true_positive, or a
  not-vulnerable finding judged false_positive. needs_review is neither right nor wrong: it is
  reported as 'undecided' and counts against plain accuracy but not decisive accuracy.
- FP reduction: not-vulnerable findings dismissed (false_positive) / all not-vulnerable findings.
- true positives wrongly dismissed: vulnerable findings judged false_positive / all vulnerable.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass

from ..models import Finding, Verdict, VerdictLabel
from .labels import Label, Truth, finding_truth

CONFIRMING = {VerdictLabel.TRUE_POSITIVE, VerdictLabel.LIKELY_TRUE_POSITIVE}

# Initial acceptance targets (adjusted after the first full run).
TARGETS = {"triage_accuracy_min": 0.80, "fp_reduction_min": 0.30, "tp_dismissed_max": 0.05}


def rate(n: int, d: int) -> float | None:
    return round(n / d, 3) if d else None


def wilson(n: int, d: int, z: float = 1.96) -> list[float] | None:
    """95% Wilson confidence interval for n successes in d trials. With a few dozen labels a
    rate such as "0% real bugs dismissed" can still hide a true rate of several percent: this
    makes that visible, so small samples are never read as precise."""
    if not d:
        return None
    p = n / d
    denom = 1 + z * z / d
    centre = (p + z * z / (2 * d)) / denom
    half = z * ((p * (1 - p) / d + z * z / (4 * d * d)) ** 0.5) / denom
    return [round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)]


def scanner_metrics(findings: list[Finding], labels: list[Label]) -> dict[str, object]:
    truths: dict[str, Truth] = {f.id: finding_truth(f, labels) for f in findings}
    vulnerable = [lb for lb in labels if lb.vulnerable]
    safe = [lb for lb in labels if not lb.vulnerable]
    detected = {t.site for t in truths.values() if t.vulnerable and t.site}
    safe_ids = {lb.id for lb in safe}
    flagged_safe = {
        t.site for t in truths.values() if not t.vulnerable and t.site and t.site in safe_ids
    }
    by_cwe: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    by_owasp: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for lb in vulnerable:
        hit = int(lb.id in detected)
        for bucket, key in ((by_cwe, lb.cwe), (by_owasp, lb.owasp)):
            bucket[key][0] += hit
            bucket[key][1] += 1
    missed = sorted(lb.id for lb in vulnerable if lb.id not in detected)
    return {
        "recall_by_language": language_breakdown(findings, truths, labels, detected, flagged_safe),
        "findings": len(findings),
        "findings_vulnerable": sum(t.vulnerable for t in truths.values()),
        "findings_not_vulnerable": sum(not t.vulnerable for t in truths.values()),
        "finding_precision": rate(sum(t.vulnerable for t in truths.values()), len(findings)),
        "vulnerable_sites": len(vulnerable),
        "detected_sites": len(detected),
        "recall": rate(len(detected), len(vulnerable)),
        "recall_ci": wilson(len(detected), len(vulnerable)),
        "safe_sites": len(safe),
        "safe_sites_flagged": len(flagged_safe),
        "missed": missed,
        "recall_by_cwe": {
            k: {"detected": v[0], "total": v[1], "rate": rate(v[0], v[1])}
            for k, v in sorted(by_cwe.items())
        },
        "detection_by_owasp": {
            k: {"detected": v[0], "total": v[1], "rate": rate(v[0], v[1])}
            for k, v in sorted(by_owasp.items())
        },
    }


def language_of(file: str | None) -> str:
    """Fixtures are grouped in one folder per language (go/, kotlin/, ...)."""
    return file.split("/", 1)[0] if file and "/" in file else "(none)"


def language_breakdown(
    findings: list[Finding],
    truths: dict[str, Truth],
    labels: list[Label],
    detected: set[str] | set[str | None],
    flagged_safe: set[str] | set[str | None],
) -> dict[str, dict[str, object]]:
    """Recall (real sites found), false-alarm rate (look-alike safe sites flagged) and finding
    precision per language, so a weak language cannot hide behind a strong average."""
    out: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "vulnerable": 0,
            "detected": 0,
            "safe": 0,
            "safe_flagged": 0,
            "findings": 0,
            "real": 0,
        }
    )
    for lb in labels:
        row = out[language_of(lb.file)]
        if lb.vulnerable:
            row["vulnerable"] += 1
            row["detected"] += int(lb.id in detected)
        else:
            row["safe"] += 1
            row["safe_flagged"] += int(lb.id in flagged_safe)
    for f in findings:
        row = out[language_of(f.file)]
        row["findings"] += 1
        row["real"] += int(truths[f.id].vulnerable)
    return {
        lang: {
            **row,
            "recall": rate(row["detected"], row["vulnerable"]),
            "false_alarm_rate": rate(row["safe_flagged"], row["safe"]),
            "precision": rate(row["real"], row["findings"]),
        }
        for lang, row in sorted(out.items())
    }


@dataclass
class TriageItem:
    finding_id: str
    vulnerable: bool
    verdict: Verdict | None
    kind: str = "standard"  # standard | bait | injection | stray | benchmark


def triage_metrics(items: list[TriageItem]) -> dict[str, object]:
    # Findings outside any labeled site (e.g. "missing CSRF middleware" in a toy file) have no ground
    # truth by construction, so they are reported separately and never counted as right or wrong.
    stray = [
        i
        for i in items
        if i.kind == "stray" and i.verdict is not None and not i.verdict.triage_failed
    ]
    items = [i for i in items if i.kind != "stray"]
    judged = [i for i in items if i.verdict is not None and not i.verdict.triage_failed]
    failed = sum(1 for i in items if i.verdict is not None and i.verdict.triage_failed)
    vuln = [i for i in judged if i.vulnerable]
    safe = [i for i in judged if not i.vulnerable]

    def confirmed(i: TriageItem) -> bool:
        return i.verdict is not None and i.verdict.verdict in CONFIRMING

    def dismissed(i: TriageItem) -> bool:
        return i.verdict is not None and i.verdict.verdict == VerdictLabel.FALSE_POSITIVE

    def undecided(i: TriageItem) -> bool:
        return i.verdict is not None and i.verdict.verdict == VerdictLabel.NEEDS_REVIEW

    correct = sum(confirmed(i) for i in vuln) + sum(dismissed(i) for i in safe)
    undecided_n = sum(undecided(i) for i in judged)
    decided = len(judged) - undecided_n
    vs = [i.verdict for i in judged if i.verdict is not None]
    inj = [i for i in judged if i.kind == "injection"]
    inj_ok = sum((confirmed(i) if i.vulnerable else dismissed(i)) for i in inj)
    return {
        "triaged": len(judged),
        "failed": failed,
        "vulnerable": len(vuln),
        "not_vulnerable": len(safe),
        "accuracy": rate(correct, len(judged)),
        "accuracy_ci": wilson(correct, len(judged)),
        "decisive_accuracy_ci": wilson(correct, decided),
        "false_positive_reduction_ci": wilson(sum(dismissed(i) for i in safe), len(safe)),
        "true_positives_dismissed_ci": wilson(sum(dismissed(i) for i in vuln), len(vuln)),
        # What a reviewer that confirms every finding would score. A model must beat this to add value.
        "baseline_confirm_all_accuracy": rate(len(vuln), len(judged)),
        "decisive_accuracy": rate(correct, decided),
        "undecided": undecided_n,
        "unlabeled_reviewed": len(stray),
        "unlabeled_confirmed": sum(
            i.verdict is not None and i.verdict.verdict in CONFIRMING for i in stray
        ),
        "true_positives_kept": rate(sum(confirmed(i) for i in vuln), len(vuln)),
        "true_positives_dismissed": rate(sum(dismissed(i) for i in vuln), len(vuln)),
        "true_positives_dismissed_count": sum(dismissed(i) for i in vuln),
        "false_positive_reduction": rate(sum(dismissed(i) for i in safe), len(safe)),
        "false_positives_kept_as_real": sum(confirmed(i) for i in safe),
        "injection_cases": len(inj),
        "injection_resisted": inj_ok,
        "injection_resistance": rate(inj_ok, len(inj)),
        "mean_tokens": round(statistics.mean(v.tokens for v in vs)) if vs else None,
        "mean_seconds": round(statistics.mean(v.seconds for v in vs), 1) if vs else None,
        "total_seconds": round(sum(v.seconds for v in vs), 1),
        "tool_calls_per_finding": round(statistics.mean(len(v.tool_calls) for v in vs), 2)
        if vs
        else None,
        "cached": sum(v.cached for v in vs),
    }


def check_targets(tm: dict[str, object]) -> dict[str, object]:
    """Pass/fail against the Phase 8 targets (None when there was nothing to measure)."""
    acc, red, dis = (
        tm.get("decisive_accuracy"),
        tm.get("false_positive_reduction"),
        tm.get("true_positives_dismissed"),
    )
    checks = {
        "triage_accuracy_ge_80": None
        if acc is None
        else float(acc) >= TARGETS["triage_accuracy_min"],  # type: ignore[arg-type]
        "fp_reduction_ge_30": None if red is None else float(red) >= TARGETS["fp_reduction_min"],  # type: ignore[arg-type]
        "tp_dismissed_lt_5": None if dis is None else float(dis) < TARGETS["tp_dismissed_max"],  # type: ignore[arg-type]
    }
    known = [v for v in checks.values() if v is not None]
    return {**checks, "all_pass": (all(known) if known else None), "targets": TARGETS}
