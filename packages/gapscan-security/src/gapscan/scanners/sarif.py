"""Generic SARIF 2.1.0 ingest. Used directly for CodeQL or any other tool, and by
the Semgrep adapter."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..models import Category, Finding, Severity
from .base import mark_suppressed, relpath

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}
_SEC_SEV = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
]
_TEXT_SEV = {s.value: s for s in Severity} | {
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "error": Severity.HIGH,
}


def _severity(result: dict[str, Any], rule: dict[str, Any]) -> Severity:
    props = rule.get("properties", {})
    if (raw := props.get("security-severity")) is not None:
        try:
            score = float(raw)
            return next((s for t, s in _SEC_SEV if score >= t), Severity.INFO)
        except ValueError:
            pass
    for tag in props.get("tags", []):
        if str(tag).lower() in ("critical", "high", "medium", "low"):
            return _TEXT_SEV[str(tag).lower()]
    # Semgrep puts the severity in the rule's default level (ERROR/WARNING/INFO).
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
    return _LEVEL.get(level, Severity.MEDIUM)


def _title(short: str, message: str) -> str:
    """A one-line title: the rule's short description, else the first sentence of the message."""
    text = short or " ".join(message.split())
    m = re.match(r"(.{20,200}?[.!?])(\s|$)", text)
    if m and not short:
        text = m.group(1)
    return text if len(text) <= 160 else text[:157].rstrip() + "..."


def parse_sarif(
    data: dict[str, Any], target: Path, scanner: str, category: Category = Category.CODE
) -> list[Finding]:
    findings: list[Finding] = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = {r["id"]: r for r in driver.get("rules", []) if "id" in r}
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            region = loc.get("region", {})
            props = rule.get("properties", {})
            blob = " ".join(str(t) for t in props.get("tags", [])) + " " + str(props.get("cwe", ""))
            cwes = sorted({f"CWE-{n}" for n in _CWE_RE.findall(blob)}, key=lambda c: int(c[4:]))
            message = res.get("message", {}).get("text", "")
            short = rule.get("shortDescription", {}).get("text") or ""
            if short.startswith("Semgrep Finding:"):  # just the rule id: the message says more
                short = ""
            finding = Finding(
                scanner=scanner,
                rule_id=rule_id,
                title=_title(short, message),
                message=message,
                severity=_severity(res, rule),
                category=category,
                cwe=cwes,
                file=relpath(loc.get("artifactLocation", {}).get("uri"), target),
                start_line=region.get("startLine"),
                end_line=region.get("endLine", region.get("startLine")),
                snippet=region.get("snippet", {}).get("text"),
                raw={"ruleId": rule_id, "level": res.get("level")},
            )
            # A result the project suppressed (e.g. `nosemgrep`) is kept, marked, not dropped.
            if res.get("suppressions"):
                kinds = sorted({str(x.get("kind", "")) for x in res["suppressions"]} - {""})
                how = "a suppression comment in the source" if "inSource" in kinds else (
                    "a suppression recorded in the SARIF file")  # fmt: skip
                mark_suppressed(finding, how)
            findings.append(finding)
    return findings


def load_sarif(path: Path, target: Path, scanner: str = "sarif") -> list[Finding]:
    return parse_sarif(json.loads(path.read_text(encoding="utf-8")), target, scanner)


class SarifIngest:
    """Scanner-protocol wrapper that ingests a pre-existing SARIF file (no binary)."""

    name = "sarif"

    def __init__(self, sarif_path: Path) -> None:
        self.sarif_path = sarif_path

    def is_available(self) -> bool:
        return self.sarif_path.is_file()

    def version(self) -> str:
        return "sarif-2.1.0"

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        return load_sarif(self.sarif_path, target)
