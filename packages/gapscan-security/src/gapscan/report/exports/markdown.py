"""A short Markdown summary for pull requests, tickets and chat. Counts come from the report data;
model-written text is labeled."""

from __future__ import annotations

from ..schema import ReportData

_SEV = ["critical", "high", "medium", "low", "info"]


def _esc(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def markdown_summary(data: ReportData) -> str:
    c, s = data.counts, data.score
    out = [f"# GapScan report: {data.meta.project}", "",
           f"Scanned {data.meta.scan_created_at[:10]}, report generated {data.meta.generated_at[:10]} "
           f"with GapScan {data.meta.gapscan_version}.", "",
           f"**Risk score {s.value:.0f}/100 (grade {s.grade})**: {c.open} open findings of {c.total} "
           f"({c.dismissed} dismissed). {c.llm_triaged} reviewed by the model, {c.not_triaged} not reviewed.", ""]  # fmt: skip
    f = data.freshness
    if f.stale:
        out += [
            f"> **Warning:** vulnerability data is {f.vuln_data_age_days} days old (limit exceeded).",
            "",
        ]
    out += ["## Open findings by severity", "", "| Severity | Count |", "|---|---|"]
    out += [f"| {sev} | {c.by_severity.get(sev, 0)} |" for sev in _SEV]
    if data.baseline:
        b = data.baseline
        out += ["", f"## Change since {b.previous_created_at[:10] or 'the previous scan'}", "",
                f"{b.new} new, {b.fixed} fixed, {b.unchanged} still open."]  # fmt: skip
    out += [
        "",
        "## Top risks",
        "",
        "| # | Severity | Finding | Location | Review |",
        "|---|---|---|---|---|",
    ]
    for i, t in enumerate(data.top_risks, 1):
        out.append(
            f"| {i} | {t.severity} | {_esc(t.title)} | `{_esc(t.location)}` | {t.verdict.replace('_', ' ')} |"
        )
    out += ["", "## OWASP Top 10:2025", "", "| Category | Open findings |", "|---|---|"]
    out += [f"| {o.id} {o.name} | {len(o.finding_ids)} |" for o in data.owasp]
    if data.dependencies.upgrade_plan:
        out += [
            "",
            "## Upgrade plan",
            "",
            "| Package | From | To | Findings resolved |",
            "|---|---|---|---|",
        ]
        out += [f"| {u.package}{' (KEV)' if u.kev else ''} | {u.from_version} | {u.to_version} | {u.resolves} |"
                for u in data.dependencies.upgrade_plan[:15]]  # fmt: skip
    if data.asvs:
        a = data.asvs
        out += ["", f"## ASVS {data.freshness.owasp.get('OWASP ASVS', '')} level {a.level}", "",
                f"{a.evidence_of_failure} requirements with evidence of failure; {a.manual_review_required} of "
                f"{a.total} ({a.manual_pct}%) need manual review. {a.note}"]  # fmt: skip
    if data.narrative and data.narrative.headline:
        out += ["", f"## Summary (AI-generated, {f.model})", "", data.narrative.headline, ""]
        out += [f"- {p}" for p in data.narrative.recommended_priorities]
    out += ["", "## Limitations", ""] + [f"- {x}" for x in data.limitations]
    out += ["", "_OWASP category and requirement names: OWASP Foundation, CC BY-SA 4.0._", ""]
    return "\n".join(out)
