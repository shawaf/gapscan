"""The documented, deterministic risk score. No model is involved anywhere in it.

Each open finding contributes points; points add up and are squashed into 0-100 so that more
findings always mean more risk but the scale never overflows:

    points  = base(severity) x verdict factor x confidence factor x exposure x code-kind factor
    value   = 100 x (1 - exp(-sum(points) / K))

Dismissed findings (false_positive verdict or a reviewer decision) contribute nothing; a
dependency in the CISA KEV catalog counts as critical; EPSS raises dependency points.
"""

from __future__ import annotations

import math

from ..models import Category, Finding, Severity, Verdict, VerdictLabel
from .schema import RiskScore, ScoreComponent

BASE_POINTS = {Severity.CRITICAL: 10.0, Severity.HIGH: 5.0, Severity.MEDIUM: 2.0, Severity.LOW: 0.5,
               Severity.INFO: 0.1}  # fmt: skip
VERDICT_FACTOR = {
    VerdictLabel.TRUE_POSITIVE: 1.0,
    VerdictLabel.LIKELY_TRUE_POSITIVE: 0.7,
    VerdictLabel.NEEDS_REVIEW: 0.5,
    VerdictLabel.FALSE_POSITIVE: 0.0,
}
NOT_TRIAGED_FACTOR = 0.6  # scanner finding the model has not reviewed (or whose triage failed)
INTERNET_FACING = 1.25
TEST_CODE = 0.4
TOOLING_CODE = 0.5
VENDOR_CODE = 0.2
SECRET_BONUS = 1.5  # a real credential is worse than its severity label suggests
EPSS_BONUS = 1.0  # dependency points x (1 + EPSS_BONUS * epss)
K = 40.0  # scale: 40 points ~ 63/100, 120 points ~ 95/100
GRADES = [(8.0, "A"), (18.0, "B"), (40.0, "C"), (65.0, "D"), (101.0, "F")]


def grade_for(value: float) -> str:
    return next(g for limit, g in GRADES if value < limit)


def finding_points(f: Finding, verdict: Verdict | None, dismissed: bool = False) -> float:
    if dismissed:
        return 0.0
    if verdict is not None and not verdict.triage_failed:
        factor = VERDICT_FACTOR[verdict.verdict] * (0.5 + 0.5 * verdict.confidence)
        severity = verdict.severity_adjusted or f.severity
    else:
        factor, severity = NOT_TRIAGED_FACTOR, f.severity
    if f.kev:
        severity = Severity.CRITICAL
    points = BASE_POINTS[severity] * factor
    if f.internet_facing:
        points *= INTERNET_FACING
    if f.is_vendor_code:
        points *= VENDOR_CODE
    elif f.is_test_code:
        points *= TEST_CODE
    elif f.is_tooling_code and f.category == Category.CODE:
        points *= TOOLING_CODE
    if f.category == Category.SECRET:
        points *= SECRET_BONUS
    if f.category == Category.DEPENDENCY and f.epss is not None:
        points *= 1 + EPSS_BONUS * f.epss
    return points


def explanation() -> list[str]:
    base = ", ".join(f"{s.value} {p:g}" for s, p in BASE_POINTS.items())
    return [
        f"Each open finding earns points from its severity: {base}.",
        "The points are scaled by the review verdict (confirmed 1.0, likely 0.7, needs review 0.5, "
        f"not reviewed {NOT_TRIAGED_FACTOR}; false positives 0) and by the model's confidence "
        "(from 0.5x at 0 to 1x at 1.0).",
        f"x{INTERNET_FACING} if the code looks internet-facing (routes, handlers); x{TEST_CODE} in "
        f"test code; x{TOOLING_CODE} for code findings in build and developer scripts that do not ship "
        f"(tools/, scripts/, fastlane/, buildSrc/, docs/); x{VENDOR_CODE} in vendored code; x{SECRET_BONUS} for secrets; dependencies add "
        "their EPSS exploit probability, and CISA KEV-listed ones count as critical.",
        f"The total is squashed with 100 x (1 - e^(-points/{K:g})), so more findings always raise the "
        "score but it never exceeds 100.",
        "Grades: A below 8, B below 18, C below 40, D below 65, F from 65 (one confirmed critical vulnerability alone scores 22, a C). Findings a reviewer "
        "accepted or marked false positive are excluded. No language model takes part in this calculation.",
    ]


def compute_score(
    findings: list[Finding],
    verdicts: dict[str, Verdict],
    dismissed_ids: set[str] | None = None,
) -> RiskScore:
    dismissed_ids = dismissed_ids or set()
    by_cat: dict[str, list[float]] = {c.value: [] for c in Category}
    for f in findings:
        by_cat[f.category.value].append(
            finding_points(f, verdicts.get(f.id), f.id in dismissed_ids)
        )
    components = [
        ScoreComponent(name=cat, points=round(sum(p), 2), findings=sum(1 for x in p if x > 0))
        for cat, p in by_cat.items()
    ]
    raw = sum(c.points for c in components)
    value = round(100.0 * (1.0 - math.exp(-raw / K)), 1)
    return RiskScore(value=value, grade=grade_for(value), raw_points=round(raw, 2),
                     components=components, explanation=explanation())  # fmt: skip
