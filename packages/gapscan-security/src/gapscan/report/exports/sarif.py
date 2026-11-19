"""SARIF 2.1.0 for IDEs and code-scanning UIs. Each result carries GapScan's stable finding id as
a partial fingerprint, so the same issue is recognized across runs and edits. Findings a reviewer
or the model dismissed are kept but marked as suppressed."""

from __future__ import annotations

from typing import Any

from ..schema import FindingRow, ReportData

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub's numeric "security-severity" bands (>= 9 critical, >= 7 high, >= 4 medium, > 0 low).
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "2.5",
    "info": "0.5",
}


def _rule(r: FindingRow) -> dict[str, Any]:
    return {
        "id": r.rule_id,
        "name": r.rule_id.rsplit(".", 1)[-1][:60],
        "shortDescription": {"text": r.title[:200]},
        "properties": {
            "tags": ["security", *r.cwe, *r.owasp],
            "security-severity": _SECURITY_SEVERITY[r.severity_adjusted or r.severity],
        },
    }


def _result(r: FindingRow, detail_text: str) -> dict[str, Any]:
    severity = r.severity_adjusted or r.severity
    uri = r.file or "(unknown)"
    result: dict[str, Any] = {
        "ruleId": r.rule_id,
        "level": _LEVEL[severity],
        "message": {"text": f"{r.title}. Review: {r.verdict.replace('_', ' ')}{detail_text}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": r.start_line or 1, "endLine": r.end_line or r.start_line or 1},
        }}],
        "partialFingerprints": {"gapscanFingerprint/v1": r.id},
        "properties": {
            "severity": severity, "category": r.category, "verdict": r.verdict, "confidence": r.confidence,
            "riskPoints": r.risk_points, "cwe": r.cwe, "owasp": r.owasp, "scanners": r.scanners,
            "kev": r.kev, "llmOnly": r.llm_only,
        },
    }  # fmt: skip
    if r.package:
        result["properties"].update(
            package=r.package, version=r.version, fixedVersion=r.fixed_version, cve=r.cve
        )
    if not r.open:
        why = (
            f"reviewer decision: {r.decision}"
            if r.decision
            else "judged a false positive by the model"
        )
        result["suppressions"] = [{"kind": "external", "justification": why}]
    return result


def to_sarif(data: ReportData) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for r in data.findings:
        rules.setdefault(r.rule_id, _rule(r))
        d = data.details.get(r.id)
        extra = f" (model confidence {r.confidence:.0%})" if r.confidence is not None else ""
        if d and d.fix_suggestion:
            extra += f". Suggested fix (AI-generated): {d.fix_suggestion}"
        results.append(_result(r, extra))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "GapScan", "version": data.meta.gapscan_version, "rules": list(rules.values()),
                "informationUri": "https://owasp.org/",
            }},
            "automationDetails": {"id": f"gapscan/{data.meta.project}"},
            "results": results,
        }],
    }  # fmt: skip
