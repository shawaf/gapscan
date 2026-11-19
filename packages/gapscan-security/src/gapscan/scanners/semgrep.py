"""Semgrep CE adapter: local rules only, metrics off, SARIF output."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..models import Category, Finding
from .base import CommandScanner, ScannerError
from .sarif import load_sarif

log = logging.getLogger(__name__)
# Experimental semgrep flag (verified on 1.176.0): skip the scanned project's `.semgrepignore`.
IGNORE_SEMGREPIGNORE = "--x-ignore-semgrepignore-files"

# Language/rule folders of the semgrep-rules repo that matter for GapScan's targets
# (backend, web frontend, native mobile, Flutter, IaC). The repo root also holds non-rule
# YAML (CI config etc.) that makes semgrep reject the whole config, so we pick folders.
RULE_PACKS = (
    "python", "javascript", "typescript", "java", "kotlin", "go", "swift", "dart", "csharp", "php",
    "generic", "dockerfile", "terraform", "yaml", "json", "html", "bash", "scala",
)  # fmt: skip


# First path segment of rule ids that describe infrastructure/config, not application code.
IAC_RULE_PREFIXES = {"dockerfile", "terraform", "yaml", "kubernetes", "docker-compose"}


# GapScan's own rules (Apache-2.0), shipped inside the package. They always run, with or without
# the community rule folder. The packaged app does not ship the community rules (their license
# forbids it), so these are its whole Semgrep coverage: Python, JavaScript/TypeScript, Java,
# Kotlin, Swift, Dart, Go, C# and PHP.
OWN_RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep"
_OWN_ID = re.compile(r"(gapscan\.[a-z]+\.[\w-]+)$")  # any language folder, present or future


def own_rule_configs(own_rules: Path = OWN_RULES) -> list[Path]:
    return sorted(p for p in own_rules.iterdir() if p.is_dir()) if own_rules.is_dir() else []


def rule_configs(rules_path: Path) -> list[Path]:
    """Rule folders to pass as --config. A directory that is itself a rule set is used as is."""
    packs = [rules_path / p for p in RULE_PACKS if (rules_path / p).is_dir()]
    return packs or [rules_path]


def check_sarif_errors(sarif: dict[str, object]) -> None:
    """Semgrep reports config problems as SARIF notifications and may still exit cleanly."""
    errors = []
    for run in sarif.get("runs", []):  # type: ignore[attr-defined]
        for inv in run.get("invocations", []):
            for n in inv.get("toolExecutionNotifications", []):
                if n.get("level") == "error":
                    errors.append(n.get("message", {}).get("text", "unknown error"))
    if errors:
        raise ScannerError("semgrep reported errors: " + "; ".join(errors)[:400])


def postprocess(findings: list[Finding]) -> list[Finding]:
    """Normalize Semgrep's raw SARIF findings: registry-style rule ids and the right category."""
    for f in findings:
        # Rule ids carry the local rules path as a prefix; keep the registry-style id.
        own = _OWN_ID.search(f.rule_id)
        f.rule_id = own.group(1) if own else f.rule_id.split("semgrep-rules.")[-1]
        if "secrets" in f.rule_id or set(f.cwe) & {"CWE-798", "CWE-259"}:
            f.category = Category.SECRET
        elif f.rule_id.split(".")[0] in IAC_RULE_PREFIXES:
            f.category = Category.CONFIG  # Dockerfile/Terraform/YAML rules are config findings
    return findings


class SemgrepScanner(CommandScanner):
    name = "semgrep"
    binary = "semgrep"
    ok_returncodes = frozenset({0, 1})
    note = ""  # shown on the run when the scan could not be fully hardened

    def __init__(self, rules_path: Path, timeout_s: int = 300, own_rules: Path = OWN_RULES) -> None:
        super().__init__(timeout_s)
        self.rules_path = rules_path.resolve()  # absolute: tools run from GapScan's work folder
        self.own_rules = own_rules.resolve()

    def is_available(self) -> bool:
        return super().is_available() and (
            self.rules_path.exists() or bool(own_rule_configs(self.own_rules))
        )

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        self.note = ""
        out = workdir / "semgrep.sarif"
        folders = [*(rule_configs(self.rules_path) if self.rules_path.exists() else []),
                   *own_rule_configs(self.own_rules)]  # fmt: skip
        configs = [a for c in folders for a in ("--config", str(c))]
        # A scanned project must not be able to silence the scan: ignore its `.semgrepignore`
        # files (any folder) and report `nosemgrep` lines, which SARIF then marks as suppressed.
        hardening = [IGNORE_SEMGREPIGNORE, "--disable-nosem"]
        base = [self.binary, "scan", *configs, "--metrics=off", "--disable-version-check",
                "--quiet", "--sarif", "--output", str(out)]  # fmt: skip
        proc = self._exec([*base, *hardening, str(target)])
        if proc.returncode == 2 and IGNORE_SEMGREPIGNORE in (proc.stderr or ""):
            # The flag is experimental; if a newer semgrep drops it, scan anyway and say so.
            self.note = (".semgrepignore files in the project were honored (this semgrep has no "
                         f"{IGNORE_SEMGREPIGNORE}): check them for hidden paths")  # fmt: skip
            log.warning("semgrep: %s", self.note)
            proc = self._exec([*base, "--disable-nosem", str(target)])
        if not out.is_file():
            self.check(proc)
            raise ScannerError("semgrep produced no SARIF output")
        check_sarif_errors(json.loads(out.read_text(encoding="utf-8")))
        self.check(proc)
        return postprocess(load_sarif(out, target, self.name))
