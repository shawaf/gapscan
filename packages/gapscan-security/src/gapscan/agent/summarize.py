"""Repo-level summary: top risks, themes and recommended priorities.

All numbers are computed here in Python (hard rule from CLAUDE.md: the dashboard and reports
never take numbers from the model). The model only writes the narrative, and every finding id
it cites is checked against the real ones; invented ids are dropped, and a risk left with no
valid id is removed.
"""

from __future__ import annotations

from collections import Counter

from ..core.interfaces import LLMError, LLMProvider
from ..llm.cache import ResponseCache
from ..llm.prompts import latest_version, render_prompt
from ..llm.structured import StructuredOutputError, structured_chat
from ..models import Finding, RepoNarrative, RepoSummary, ScanResult, Verdict, VerdictLabel
from ..owasp.packs import TOP10
from ..redact import mask

PROMPT_NAME = "summary"
DIGEST_SIZE = 25


def compute_stats(findings: list[Finding], verdicts: list[Verdict]) -> dict[str, dict[str, int]]:
    """Counts shown next to the narrative; the single source of every number in the summary."""
    by_id = {v.finding_id: v for v in verdicts}
    triaged = [by_id[f.id] for f in findings if f.id in by_id]
    return {
        "findings_by_severity": dict(Counter(f.severity.value for f in findings)),
        "findings_by_category": dict(Counter(f.category.value for f in findings)),
        "findings_by_owasp_top10": dict(Counter(c for f in findings for c in f.control_ids(TOP10))),
        "verdicts": dict(
            Counter(("triage_failed" if v.triage_failed else v.verdict.value) for v in triaged)
        ),  # fmt: skip
        "triage": {
            "triaged": len(triaged),
            "not_triaged": len(findings) - len(triaged),
            "total": len(findings),
        },  # fmt: skip
    }


def _digest(findings: list[Finding], verdicts: list[Verdict], n: int) -> list[dict[str, object]]:
    by_id = {v.finding_id: v for v in verdicts}
    rows = []
    # Highest priority first; confirmed/unreviewed before dismissed ones, which are not risks.
    ranked = sorted(findings, key=lambda f: -f.priority)
    for f in ranked:
        v = by_id.get(f.id)
        if v is not None and v.verdict == VerdictLabel.FALSE_POSITIVE:
            continue
        where = f"{f.package} {f.version}" if f.package else "-"
        rows.append({
            "id": f.id, "priority": f.priority, "severity": f.severity.value,
            "category": f.category.value, "title": mask(f.title)[:100],
            "location": f"{f.file}:{f.start_line}" if f.file else where,
            "verdict": v.verdict.value if v and not v.triage_failed else "not triaged",
            "confidence": f"{v.confidence:.2f}" if v and not v.triage_failed else "-",
            "reasoning": mask(v.reasoning)[:200] if v and not v.triage_failed else "",
        })  # fmt: skip
        if len(rows) >= n:
            break
    return rows


def _validated(narrative: RepoNarrative, known: set[str]) -> tuple[RepoNarrative, int]:
    """Drop cited ids that do not exist, and risks left without any real id."""
    dropped = 0
    risks = []
    for r in narrative.top_risks:
        ids = [i for i in r.finding_ids if i in known]
        dropped += len(r.finding_ids) - len(ids)
        if ids:
            risks.append(r.model_copy(update={"finding_ids": ids}))
        else:
            dropped += 1
    return narrative.model_copy(update={"top_risks": risks}), dropped


def summarize_repo(
    client: LLMProvider,
    result: ScanResult,
    verdicts: list[Verdict],
    *,
    cache: ResponseCache | None = None,
) -> RepoSummary:
    version = latest_version(PROMPT_NAME)
    summary = RepoSummary(
        stats=compute_stats(result.findings, verdicts),
        prompt_version=version,
        model=client.model,
    )
    rows = _digest(result.findings, verdicts, DIGEST_SIZE)
    if not rows:  # nothing to write about: no model call
        return summary.model_copy(update={"narrative": RepoNarrative(headline="No open findings.")})
    prompt = render_prompt(version, findings=rows)
    try:
        res = structured_chat(
            client, [{"role": "user", "content": prompt}], RepoNarrative,
            max_tokens=1000, cache=cache, prompt_version=version,
        )  # fmt: skip
    except (StructuredOutputError, LLMError) as exc:
        return summary.model_copy(update={"failed": True, "error": str(exc)[:300]})
    narrative, dropped = _validated(res.value, {f.id for f in result.findings})
    return summary.model_copy(update={"narrative": narrative, "dropped_unknown_ids": dropped})
