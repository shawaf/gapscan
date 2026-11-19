"""Gitleaks adapter. Secret values are NEVER stored: Secret/Match are dropped and
the snippet is a fixed placeholder (hard rule #4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Category, Finding, Severity
from .base import CommandScanner, ScannerError, relpath

REDACTED = "[REDACTED SECRET]"


def parse_gitleaks(data: list[dict[str, Any]] | None, target: Path) -> list[Finding]:
    out: list[Finding] = []
    for r in data or []:
        out.append(
            Finding(
                scanner="gitleaks",
                rule_id=r.get("RuleID", "secret"),
                title=r.get("Description", "Hardcoded secret"),
                message=f"Possible secret detected by rule {r.get('RuleID')}",
                severity=Severity.HIGH,
                category=Category.SECRET,
                cwe=["CWE-798"],
                file=relpath(r.get("File"), target),
                start_line=r.get("StartLine"),
                end_line=r.get("EndLine"),
                snippet=REDACTED,
                raw={"entropy": r.get("Entropy"), "fingerprint": r.get("Fingerprint")},
            )
        )
    return out


# Without --config, gitleaks loads .gitleaks.toml (and .gitleaksignore) from the scanned folder,
# so a scanned project could allowlist its own secrets and hide them (hard rule #3: scanned
# content is untrusted). GapScan always passes its own config: gitleaks' default rules.
PINNED_CONFIG = "[extend]\nuseDefault = true\n"


def pinned_config_args(workdir: Path) -> list[str]:
    config = workdir / "gitleaks-config.toml"
    config.write_text(PINNED_CONFIG, encoding="utf-8")
    ignore_dir = workdir / "gitleaks-ignore"  # an empty folder: no .gitleaksignore is honored
    ignore_dir.mkdir(exist_ok=True)
    return ["--config", str(config), "--gitleaks-ignore-path", str(ignore_dir)]


class GitleaksScanner(CommandScanner):
    name = "gitleaks"
    binary = "gitleaks"
    version_args = ("version",)
    ok_returncodes = frozenset({0, 1})

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        out = workdir / "gitleaks.json"
        proc = self._exec(
            [
                self.binary, "dir", str(target), "--report-format", "json",
                "--report-path", str(out), "--redact", "--no-banner", "--exit-code", "1",
                *pinned_config_args(workdir),
            ]
        )  # fmt: skip
        self.check(proc)
        if not out.is_file():
            raise ScannerError("gitleaks produced no report")
        return parse_gitleaks(json.loads(out.read_text() or "[]"), target)
