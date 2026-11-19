"""ASVS coverage for the configured level, with honest statuses.

- evidence_of_failure: an open finding is linked to the requirement.
- no_issue_found_by_tools: no open finding, and OWASP's requirement-level CWE link (the archived
  v5.0 CWE export, not the looser OpenCRE grouping) ties this requirement to a weakness class
  scanners report on. This is NOT proof the requirement is met, and whether your rule set
  contains a rule for that CWE is not checked.
- manual_review_required: no such link exists (authorization design, business logic, process
  controls); it is never reported as passed.
"""

from __future__ import annotations

from pathlib import Path

from ..owasp.asvs import requirements_for_level
from ..owasp.packs import AsvsPack
from .schema import AsvsCoverage, AsvsRequirement, AsvsStatus

MAPPINGS = Path(__file__).resolve().parent.parent / "owasp" / "mappings" / "cwe_to_asvs.csv"
NOTE = (
    "'No issue found by tools' means no finding maps to this requirement through OWASP's CWE links; "
    "it is not evidence that the requirement is satisfied, and it does not check that your rule set "
    "has a rule for that weakness. Requirements without such a link are listed as manual review "
    "and are never counted as passed."
)


def tool_verifiable_requirements() -> frozenset[str]:
    """Requirements with a requirement-level CWE link from OWASP's own mapping (via == 'be')."""
    return AsvsPack().checkable()


def build_coverage(level: int, asvs_to_findings: dict[str, list[str]]) -> AsvsCoverage:
    verifiable = tool_verifiable_requirements()
    reqs: list[AsvsRequirement] = []
    for r in requirements_for_level(level):
        ids = asvs_to_findings.get(r.id, [])
        status: AsvsStatus
        if ids:
            status = "evidence_of_failure"
        elif r.id in verifiable:
            status = "no_issue_found_by_tools"
        else:
            status = "manual_review_required"
        reqs.append(AsvsRequirement(id=r.id, chapter=r.chapter, section=r.section, text=r.description,
                                    level=r.level, status=status, finding_ids=ids))  # fmt: skip
    total = len(reqs)
    count = {s: sum(1 for r in reqs if r.status == s) for s in
             ("evidence_of_failure", "no_issue_found_by_tools", "manual_review_required")}  # fmt: skip
    tool_side = count["evidence_of_failure"] + count["no_issue_found_by_tools"]
    return AsvsCoverage(
        level=level, total=total, evidence_of_failure=count["evidence_of_failure"],
        no_issue_found_by_tools=count["no_issue_found_by_tools"],
        manual_review_required=count["manual_review_required"],
        tool_verifiable_pct=round(100 * tool_side / total, 1) if total else 0.0,
        manual_pct=round(100 * count["manual_review_required"] / total, 1) if total else 0.0,
        requirements=reqs, note=NOTE,
    )  # fmt: skip
