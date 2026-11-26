"""Results from other tools, brought into a scan as evidence: `gapscan scan --import FILE`.

Three formats are recognized from their content:

- **SARIF 2.1.0** from any static tool (CodeQL, a commercial SAST, ...): ordinary code findings.
- **OWASP ZAP** JSON report (`zap-baseline.py -J`, `zap-full-scan.py -J`, or the "Traditional JSON"
  report) and **nuclei** JSON Lines (`nuclei -jsonl -o out.jsonl`): *runtime* findings, observed
  against a running instance of the application.

A runtime finding carries the request that showed it (method, URL, parameter) and the scanner's own
evidence string as its quoted evidence (hard rule 5); the text is masked like any other finding
(hard rule 4). `link_runtime_proof` then marks the static findings that a runtime result confirms:
same CWE, and the URL's route written as a literal in the finding's file, at most HANDLER_SPAN
lines above the finding (the decorator or registration of the handler that contains it). Those
findings gain the runtime scanner in `sources` and a line of reachability evidence saying what was
seen.

The files are only read. Nothing is fetched and nothing is executed: the user ran ZAP or nuclei
themselves, against a target they are allowed to test.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from ..models import Category, Finding, Severity
from ..redact import mask
from .sarif import parse_sarif

MAX_IMPORT_BYTES = 200 * 1024 * 1024  # a report larger than this is not a report
MAX_EVIDENCE = 400  # characters of a tool's evidence string kept as the quote
RUNTIME = "runtime"  # raw["evidence_kind"] of findings observed against a running application

_ZAP_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
_NUCLEI_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}
_TAGS = re.compile(r"<[^>]+>")
_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


class ImportError_(ValueError):
    """The file is not a format GapScan can import; the message says why."""


@dataclass(frozen=True)
class Imported:
    scanner: str  # sarif | zap | nuclei
    findings: list[Finding]


def _text(value: Any, limit: int = 2000) -> str:
    text = " ".join(_TAGS.sub(" ", str(value or "")).split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _route(url: str) -> str:
    """The path of a URL without a trailing slash: the part an application's code names."""
    path = urlsplit(url).path or "/"
    return path.rstrip("/") or "/"


def _runtime_finding(
    *,
    scanner: str,
    rule_id: str,
    title: str,
    severity: Severity,
    cwe: list[str],
    method: str,
    url: str,
    param: str,
    evidence: str,
    description: str,
    extra: dict[str, Any],
) -> Finding:
    where = f"{method} {url}".strip() + (f" (parameter {param})" if param else "")
    quote = _text(evidence, MAX_EVIDENCE)
    message = f"{scanner} observed this at runtime: {where}."
    if description:
        message += " " + _text(description, 600)
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        title=_text(title, 160) or rule_id,
        message=mask(message),
        severity=severity,
        category=Category.CODE,
        cwe=cwe,
        snippet=mask(f"{where}\n{quote}") if quote else mask(where),
        raw={
            "evidence_kind": RUNTIME,
            "method": method,
            "url": mask(url),
            "route": _route(url),
            "param": param,
            **extra,
        },
    )


def parse_zap(data: dict[str, Any]) -> list[Finding]:
    """A ZAP JSON report: one finding per alert instance (URL, method, parameter)."""
    findings: list[Finding] = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = str(alert.get("riskcode", "1"))
            cweid = str(alert.get("cweid") or "")
            cwe = [f"CWE-{cweid}"] if cweid.isdigit() and cweid not in ("0", "-1") else []
            instances = alert.get("instances") or [{}]
            for inst in instances:
                findings.append(
                    _runtime_finding(
                        scanner="zap",
                        rule_id=f"zap-{alert.get('pluginid', 'unknown')}",
                        title=alert.get("alert") or alert.get("name") or "",
                        severity=_ZAP_RISK.get(risk, Severity.LOW),
                        cwe=cwe,
                        method=str(inst.get("method") or ""),
                        url=str(inst.get("uri") or ""),
                        param=str(inst.get("param") or ""),
                        evidence=str(inst.get("evidence") or inst.get("attack") or ""),
                        description=alert.get("desc") or "",
                        extra={
                            "confidence": alert.get("confidence"),
                            "wascid": alert.get("wascid"),
                        },
                    )
                )
    return findings


def parse_nuclei(lines: list[str]) -> list[Finding]:
    """nuclei JSON Lines: one finding per matched template and URL."""
    findings: list[Finding] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ImportError_(f"not JSON Lines: {exc}") from exc
        info = item.get("info", {}) or {}
        cls = info.get("classification", {}) or {}
        raw_cwes = cls.get("cwe-id") or []
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]
        cwe = sorted({f"CWE-{n}" for c in raw_cwes for n in _CWE.findall(str(c))},
                     key=lambda c: int(c[4:]))  # fmt: skip
        url = str(item.get("matched-at") or item.get("url") or item.get("host") or "")
        extracted = item.get("extracted-results") or []
        evidence = ", ".join(map(str, extracted)) or str(item.get("matcher-name") or "")
        req = str(item.get("request") or "")
        first = req.split(" ", 1)[0]
        method = first if first.isalpha() and first.isupper() and len(first) <= 7 else ""
        findings.append(
            _runtime_finding(
                scanner="nuclei",
                rule_id=f"nuclei-{item.get('template-id', 'unknown')}",
                title=info.get("name") or item.get("template-id") or "",
                severity=_NUCLEI_SEV.get(
                    str(info.get("severity", "unknown")).lower(), Severity.INFO
                ),
                cwe=cwe,
                method=method,
                url=url,
                param="",
                evidence=evidence,
                description=info.get("description") or "",
                extra={"cve": cls.get("cve-id"), "template": item.get("template-id")},
            )
        )
        cves = cls.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        findings[-1].cve = [str(c).upper() for c in cves if str(c).upper().startswith("CVE-")]
    return findings


def load_import(path: Path, target: Path) -> Imported:
    """Read one file and recognize its format from the content."""
    if not path.is_file():
        raise ImportError_(f"{path}: not found")
    if path.stat().st_size > MAX_IMPORT_BYTES:
        raise ImportError_(f"{path}: larger than {MAX_IMPORT_BYTES // 2**20} MB")
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None  # perhaps JSON Lines whose first line is an object
        if isinstance(data, dict):
            if "runs" in data and ("version" in data or "$schema" in data):
                return Imported("sarif", parse_sarif(data, target, "sarif"))
            if "site" in data and isinstance(data["site"], list):
                return Imported("zap", parse_zap(data))
            if "template-id" in data:
                return Imported("nuclei", parse_nuclei([text]))
            raise ImportError_(f"{path}: JSON, but not SARIF, a ZAP report or nuclei output")
        first = stripped.splitlines()[0]
        if '"template-id"' in first:
            return Imported("nuclei", parse_nuclei(text.splitlines()))
    elif stripped.startswith("["):  # nuclei -json-export writes one array
        try:
            items = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ImportError_(f"{path}: not valid JSON: {exc}") from exc
        if isinstance(items, list) and all(
            isinstance(i, dict) and "template-id" in i for i in items
        ):
            return Imported("nuclei", parse_nuclei([json.dumps(i) for i in items]))
    raise ImportError_(f"{path}: not SARIF, a ZAP JSON report or nuclei JSON Lines")


def _route_literal(route: str) -> re.Pattern[str] | None:
    """`/api/users` as a quoted string in code (also with a trailing slash). The site root and
    one-character routes say nothing about a specific handler, so they never link."""
    if len(route) < 3:
        return None
    return re.compile(r"""["'`]""" + re.escape(route) + r"""/?["'`?]""")


HANDLER_SPAN = 40  # lines between a route literal and the finding it may confirm


def _serves(pattern: re.Pattern[str], text: str, line: int | None) -> bool:
    """The route is named at or above the finding, close enough to be its handler: a decorator
    (`@app.route("/user")`) or a registration (`app.get("/user", ...)`) a few lines up. A finding
    with no line (or far from every mention) is not linked."""
    if line is None:
        return False
    for m in pattern.finditer(text):
        at = text.count("\n", 0, m.start()) + 1
        if at <= line <= at + HANDLER_SPAN:
            return True
    return False


def link_runtime_proof(
    findings: list[Finding], target: Path, max_file_bytes: int = 2_000_000
) -> int:
    """Mark static findings that a runtime finding confirms. Returns how many were linked."""
    runtime = [f for f in findings if f.raw.get("evidence_kind") == RUNTIME and f.cwe]
    static = [f for f in findings if f.file and f.raw.get("evidence_kind") != RUNTIME and f.cwe]
    if not runtime or not static:
        return 0
    contents: dict[str, str] = {}
    root = target.resolve()

    def read(rel: str) -> str:
        if rel not in contents:
            path = (root / rel).resolve()
            ok = (
                path.is_relative_to(root)
                and path.is_file()
                and path.stat().st_size <= max_file_bytes
            )
            contents[rel] = path.read_text(encoding="utf-8", errors="replace") if ok else ""
        return contents[rel]

    linked = 0
    for s in static:
        assert s.file is not None
        seen: list[str] = []
        for r in runtime:
            if not set(s.cwe) & set(r.cwe):
                continue
            pattern = _route_literal(str(r.raw.get("route", "")))
            if pattern is None or not _serves(pattern, read(s.file), s.start_line):
                continue
            where = f"{r.raw.get('method') or ''} {r.raw.get('url') or ''}".strip()
            seen.append(f"Confirmed at runtime by {r.scanner}: {r.title} at {where}")
            if r.scanner not in s.sources:
                s.sources.append(r.scanner)
            proof = s.raw.setdefault("runtime_proof", [])
            proof.append(
                {"scanner": r.scanner, "id": r.id, "rule_id": r.rule_id, "url": r.raw.get("url")}
            )
        if seen:
            linked += 1
            s.reachability_evidence = seen[:3] + s.reachability_evidence
            if s.reachability not in ("reachable",):
                s.reachability = "reachable"
    return linked


class RuntimeProof:
    """The normalize step that links runtime findings to the code they confirm (a `context`
    annotator: after the stable IDs, so the link names the runtime finding's ID, before scoring)."""

    stage: Literal["evidence", "context"] = "context"

    def annotate(self, findings: list[Finding], target: Path) -> list[Finding]:
        link_runtime_proof(findings, target)
        return findings

    def data_dates(self) -> dict[str, str]:
        return {}
