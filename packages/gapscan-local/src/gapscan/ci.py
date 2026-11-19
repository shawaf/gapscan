"""`gapscan ci`: the same engine as `scan`, shaped for pipelines, pre-commit and pull requests.

Scan, keep only what the change introduced (git ref, baseline scan, or staged files), apply the
policy, and return a summary, a Markdown comment and an exit code. No network here: posting the
comment is a separate step (`scm.py`) that the pipeline runs after this.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .diffscan import (
    Changes,
    changes_since,
    introduced_by_baseline,
    introduced_by_changes,
    staged_changes,
)
from .models import Finding, ScanResult
from .pipeline import run_scan
from .policy import Action, Policy, evaluate

FAST_SCANNERS = ("semgrep", "taint", "gitleaks", "malware")  # seconds, not minutes
MAX_COMMENT_ROWS = 20
_MD_UNSAFE = re.compile(r"[`<>|\r\n]")


@dataclass
class CIResult:
    scanned: int  # findings in the whole scan
    considered: int  # findings introduced by the change
    rows: list[tuple[Finding, Action, str]] = field(default_factory=list)
    mode: str = "all findings"

    @property
    def blocked(self) -> bool:
        return any(a == "block" for _, a, _ in self.rows)

    def count(self, action: Action) -> int:
        return sum(1 for _, a, _ in self.rows if a == action)


def _esc(text: str, limit: int = 160) -> str:
    return _MD_UNSAFE.sub(" ", text)[:limit].strip()


def dismissed_ids(triage_file: Path | None, decisions_file: Path | None) -> set[str]:
    """Findings a model or a person already judged false positives: they never block."""
    out: set[str] = set()
    if triage_file and triage_file.is_file():
        for v in json.loads(triage_file.read_text("utf-8")):
            if v.get("verdict") == "false_positive" and not v.get("triage_failed"):
                out.add(v["finding_id"])
    if decisions_file and decisions_file.is_file():
        from .report.decisions import load_decisions

        out |= {
            d.finding_id
            for d in load_decisions(decisions_file).decisions
            if d.decision == "false_positive"
        }
    return out


def run_ci(
    config: Config,
    target: Path,
    policy: Policy,
    *,
    base_ref: str | None = None,
    baseline: Path | None = None,
    staged: bool = False,
    fast: bool = False,
    dismissed: set[str] | None = None,
) -> tuple[CIResult, ScanResult]:
    cfg = config
    if fast:
        cfg = config.model_copy(deep=True)
        cfg.scanners.enabled = [s for s in config.scanners.enabled if s in FAST_SCANNERS]
    scan = run_scan(cfg, target)
    findings = scan.findings
    mode = "all findings"
    if staged:
        ch: Changes = staged_changes(target)
        findings = [f for f in findings if f.file in ch.files or any(f.file == p for p in ch.files)]
        mode = "staged files"
    elif baseline is not None:
        old = ScanResult.model_validate_json(baseline.read_text("utf-8"))
        findings = introduced_by_baseline(findings, {f.id for f in old.findings})
        mode = f"new since baseline ({baseline.name})"
    elif base_ref:
        findings = introduced_by_changes(findings, changes_since(target, base_ref))
        mode = f"introduced since {base_ref}"
    rows = evaluate(policy, findings, dismissed)
    return CIResult(len(scan.findings), len(findings), rows, mode), scan


def render_comment(res: CIResult) -> str:
    """Markdown for a pull-request comment. Finding text comes from the scanned project, so it is
    flattened and stripped of markup characters before it is shown."""
    shown = [(f, a, n) for f, a, n in res.rows if a in ("block", "comment")]
    head = "### GapScan (offline)\n"
    if not res.rows:
        return (
            head + f"No findings in scope ({res.mode}). Scanned {res.scanned} findings in total.\n"
        )
    status = "**Blocking findings**" if res.blocked else "No blocking findings"
    out = [
        head,
        f"{status} · {res.count('block')} block · {res.count('comment')} comment · "
        f"{res.count('monitor')} monitor · scope: {res.mode}\n",
    ]
    if shown:
        out += ["| | Severity | Finding | Where |", "|---|---|---|---|"]
        for f, a, _ in shown[:MAX_COMMENT_ROWS]:
            where = (
                f"`{_esc(f.file or '', 80)}:{f.start_line}`"
                if f.start_line
                else f"`{_esc(f.file or '', 80)}`"
            )
            title = _esc(f.title, 100) + (
                f" ({_esc(f.package)} {_esc(f.version or '')})" if f.package else ""
            )
            out.append(
                f"| {'⛔' if a == 'block' else '💬'} | {f.severity.value} | {title} | {where} |"
            )
        if len(shown) > MAX_COMMENT_ROWS:
            out.append(f"\n…and {len(shown) - MAX_COMMENT_ROWS} more.")
        for f, _a, _ in shown[:5]:
            path = f.raw.get("taint_path")
            if path:
                out.append(f"\n<details><summary>Data flow: {_esc(f.title, 80)}</summary>\n")
                out += [f"{i + 1}. {_esc(str(s), 200)}" for i, s in enumerate(path)]
                out.append("\n</details>")
    out.append("\n_AI-assisted triage runs locally; no code left your network._")
    return "\n".join(out) + "\n"
