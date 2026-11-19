"""Scanner protocol, subprocess helper and the parallel runner.

Hard rules: argument lists only (never shell=True), always a timeout, and never
execute/build/import the scanned code. A failing scanner never fails the run.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import ClassVar

from ..core.interfaces import Scanner as Scanner  # declared in core; re-exported here
from ..models import Finding, ScannerRun
from ..versions import ver_key

log = logging.getLogger(__name__)


class ScannerError(RuntimeError):
    """A scanner ran but did not produce usable output."""


def relpath(path: str | None, target: Path) -> str | None:
    """Make a scanner-reported path relative to the scan target."""
    if not path:
        return None
    p = path.removeprefix("file://")
    try:
        return str(Path(p).resolve().relative_to(target.resolve()))
    except (ValueError, OSError):
        return p.removeprefix("./")


def pick_fix(installed: str | None, fixed: str | None) -> str | None:
    """Reduce a fix list like '1.11.27, 2.2.9, 3.0.1' or '>=4.17.11' to the one version a
    user should upgrade to: the lowest fix at or above the installed version."""
    if not fixed:
        return None
    candidates = [c.strip().lstrip("<>=~^ ") for c in fixed.split(",") if c.strip()]
    if not candidates:
        return None
    if installed:
        above = [c for c in candidates if ver_key(c) >= ver_key(installed)]
        if above:
            return min(above, key=ver_key)
    return max(candidates, key=ver_key)


def mark_suppressed(finding: Finding, how: str) -> Finding:
    """Keep a finding the project silenced in its own code (`# nosec`, `nosemgrep`,
    `checkov:skip`, a SARIF suppression), visibly marked. Scanned content is untrusted (hard rule
    #3): an inline comment must not be able to make a finding disappear without a trace. The
    sanctioned way to ignore findings is `.gapscanignore`, which is applied and counted."""
    finding.raw["suppressed_in_code"] = how
    note = (f"Suppressed in the code ({how}); GapScan reports it anyway so the decision stays "
            "visible.")  # fmt: skip
    finding.message = f"{finding.message} {note}".strip()
    return finding


class CommandScanner:
    """Base for adapters wrapping a CLI. Subclasses define the command and parser.

    Every command runs with its working directory set to GapScan's own work folder (`cwd`, set by
    `run_all`), never the scanned project: several tools read config and ignore files
    (`.trivyignore`, `trivy.yaml`, ...) from the working directory, and a scanned project must not
    be able to configure them."""

    cwd: Path | None = None

    name: str
    binary: ClassVar[str]
    version_args: ClassVar[Sequence[str]] = ("--version",)
    ok_returncodes: ClassVar[frozenset[int]] = frozenset({0})

    def __init__(self, timeout_s: int = 300) -> None:
        self.timeout_s = timeout_s

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def version(self) -> str:
        # Only informational: a slow start (Checkov takes seconds to import, more on a busy machine
        # while the other scanners run) must never cost the scan itself.
        try:
            proc = self._exec([self.binary, *self.version_args], timeout_s=60)
        except subprocess.TimeoutExpired:
            log.warning("%s --version did not answer in 60s; scanning anyway", self.name)
            return "unknown"
        lines = (proc.stdout or proc.stderr).strip().splitlines()
        return lines[0].strip() if lines else ""

    def env(self) -> dict[str, str]:
        return {}

    def _exec(
        self, argv: list[str], timeout_s: int | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - arg list, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s or self.timeout_s,
            check=False,
            env={**os.environ, **self.env()},
            cwd=self.cwd,
        )

    def check(self, proc: subprocess.CompletedProcess[str]) -> None:
        if proc.returncode not in self.ok_returncodes:
            tail = (proc.stderr or proc.stdout).strip()[-300:]
            raise ScannerError(f"{self.name} exited {proc.returncode}: {tail}")


def run_all(
    scanners: Sequence[Scanner], target: Path, workdir: Path, timeout_s: int = 300
) -> tuple[list[Finding], list[ScannerRun]]:
    """Run scanners in parallel; collect findings and a per-scanner status."""
    # Absolute paths: every tool runs with its own work folder as the working directory.
    target, workdir = target.resolve(), workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    def one(s: Scanner) -> tuple[list[Finding], ScannerRun]:
        started = time.monotonic()
        if not s.is_available():
            return [], ScannerRun(scanner=s.name, status="unavailable", error="binary not found")
        sub = workdir / s.name
        sub.mkdir(parents=True, exist_ok=True)
        runner = getattr(s, "inner", s)  # wrappers such as the image job delegate to `inner`
        if isinstance(runner, CommandScanner):
            runner.cwd = sub  # never the scanned project (see CommandScanner)
        try:
            version = s.version()
            findings = s.run(target, sub)
            status, error = "ok", ""
        except subprocess.TimeoutExpired:
            version, findings, status, error = "", [], "timeout", f"exceeded {timeout_s}s"
        except Exception as exc:  # noqa: BLE001 - isolate every scanner failure
            log.warning("scanner %s failed: %s", s.name, exc)
            version, findings, status, error = "", [], "failed", str(exc)[:500]
        return findings, ScannerRun(
            scanner=s.name,
            status=status,
            version=version,
            duration_s=round(time.monotonic() - started, 2),
            error=error,
            finding_count=len(findings),
            note=str(getattr(s, "note", "") or ""),
        )

    if not scanners:
        return [], []
    with ThreadPoolExecutor(max_workers=len(scanners)) as pool:
        results = list(pool.map(one, scanners))
    return [f for fs, _ in results for f in fs], [r for _, r in results]
