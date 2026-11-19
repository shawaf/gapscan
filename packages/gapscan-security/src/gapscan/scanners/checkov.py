"""Checkov adapter for IaC (Terraform, Dockerfile, Kubernetes). JSON on stdout."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from ..context.callgraph import SKIP_DIRS
from ..models import Category, Finding, Severity
from .base import CommandScanner, ScannerError, mark_suppressed, relpath

_SEV = {s.value.upper(): s for s in Severity}


def _path(c: dict[str, Any], target: Path) -> str | None:
    # With -f Checkov reports absolute paths (file_abs_path); with -d, paths relative to the target.
    if c.get("file_abs_path"):
        return relpath(str(c["file_abs_path"]), target)
    return relpath((c.get("file_path") or "").lstrip("/"), target)


def parse_checkov(data: dict[str, Any] | list[dict[str, Any]], target: Path) -> list[Finding]:
    reports = data if isinstance(data, list) else [data]
    out: list[Finding] = []
    for rep in reports:
        results = rep.get("results", {})
        failed = [(c, False) for c in results.get("failed_checks", [])]
        skipped = [(c, True) for c in results.get("skipped_checks", [])]
        for c, suppressed in failed + skipped:
            lines = c.get("file_line_range") or [None, None]
            code = "".join(ln[1] for ln in c.get("code_block") or [])
            out.append(
                Finding(
                    scanner="checkov",
                    rule_id=c["check_id"],
                    title=c.get("check_name", c["check_id"]),
                    message=f"{c.get('check_name', '')} (resource: {c.get('resource', '?')})",
                    severity=_SEV.get(str(c.get("severity") or "").upper(), Severity.MEDIUM),
                    category=Category.CONFIG,
                    file=_path(c, target),
                    start_line=lines[0],
                    end_line=lines[1],
                    snippet=code or None,
                    raw={"guideline": c.get("guideline"), "resource": c.get("resource")},
                )
            )
            if suppressed:  # an inline `checkov:skip` in the project: kept, marked
                reason = str((c.get("check_result") or {}).get("suppress_comment") or "").strip()
                mark_suppressed(out[-1], "`checkov:skip`" + (f": {reason[:120]}" if reason else ""))
    return out


# Files Checkov's terraform, dockerfile and kubernetes frameworks read. GapScan lists them itself
# and passes them with -f: with -d, Checkov also loads a `.checkov.yaml` from the scanned folder,
# which can skip or narrow checks, and `--config-file` does not override it (verified on 3.3.20).
_IAC_FILE = re.compile(r"(\.tf|\.tf\.json|\.ya?ml|\.json)$|dockerfile|containerfile", re.IGNORECASE)
_NOT_IAC = re.compile(r"(^|[-.])lock\.json$|^package(-lock)?\.json$|^\.checkov\.ya?ml$", re.I)
MAX_FILES_PER_RUN = 200


def iac_files(target: Path) -> list[Path]:
    found: list[Path] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and d != ".terraform")
        for name in sorted(files):
            full = Path(root) / name
            if _IAC_FILE.search(name) and not _NOT_IAC.search(name) and not full.is_symlink():
                found.append(full)
    return found


class CheckovScanner(CommandScanner):
    name = "checkov"
    binary = "checkov"
    ok_returncodes = frozenset({0, 1})

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        files = iac_files(target)
        findings: list[Finding] = []
        for i in range(0, len(files), MAX_FILES_PER_RUN):
            chunk = [a for f in files[i : i + MAX_FILES_PER_RUN] for a in ("-f", str(f))]
            # No --quiet: it hides skipped checks, and inline skips must stay visible.
            proc = self._exec(
                [
                    self.binary, *chunk, "--framework", "terraform", "dockerfile", "kubernetes",
                    "--output", "json", "--skip-download", "--compact",
                ]
            )  # fmt: skip
            self.check(proc)
            if not proc.stdout.strip():
                continue  # none of these files is IaC
            try:
                findings += parse_checkov(json.loads(proc.stdout), target)
            except json.JSONDecodeError as exc:
                raise ScannerError(f"checkov output was not JSON: {exc}") from exc
        return findings
