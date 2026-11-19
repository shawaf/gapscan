"""Policies: per rule, category or severity choose what happens to a finding.

    monitor   reported in the dashboard and the summary, never blocks (the default)
    comment   also shown in the pull-request comment
    block     makes `gapscan ci` exit non-zero

A policy file (`gapscan.policy.toml` in the project, or the path in `--policy`) is a list of rules;
the first rule that matches a finding decides. Findings the reviewer already judged false
positives (verdict) or decided on never block.

    default = "monitor"

    [[rule]]
    name = "no new criticals"
    severity = "critical"          # this severity or worse
    action = "block"

    [[rule]]
    name = "injection in code"
    cwe = ["CWE-89", "CWE-78"]
    asset = "code"
    action = "block"

    [[rule]]
    rule_id = "gapscan.typosquat"  # glob
    action = "comment"
"""

from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from .models import Finding, Severity

Action = Literal["monitor", "comment", "block"]
POLICY_FILE = "gapscan.policy.toml"
_RANK = {"monitor": 0, "comment": 1, "block": 2}


class PolicyRule(BaseModel):
    name: str = ""
    action: Action
    rule_id: str = ""  # glob
    category: str = ""
    asset: str = ""
    severity: Severity | None = None  # at least this severe
    cwe: list[str] = Field(default_factory=list)
    path: str = ""  # glob on the file
    scanner: str = ""
    reachability: list[str] = Field(default_factory=list)  # e.g. ["reachable"]

    def matches(self, f: Finding) -> bool:
        if self.rule_id and not fnmatch.fnmatch(f.rule_id, self.rule_id):
            return False
        if self.category and f.category.value != self.category:
            return False
        if self.asset and f.asset != self.asset:
            return False
        if self.severity is not None and f.severity.rank < self.severity.rank:
            return False
        if self.cwe and not set(self.cwe) & set(f.cwe):
            return False
        if self.path and not fnmatch.fnmatch(f.file or "", self.path):
            return False
        if self.scanner and self.scanner not in (f.sources or [f.scanner]):
            return False
        return not (self.reachability and f.reachability not in self.reachability)


class Policy(BaseModel):
    default: Action = "monitor"
    rule: list[PolicyRule] = Field(default_factory=list)

    def action_for(self, f: Finding) -> tuple[Action, str]:
        for r in self.rule:
            if r.matches(f):
                return r.action, r.name or "rule"
        return self.default, "default"


def load_policy(path: Path | None, target: Path | None = None) -> Policy:
    candidates = [path] if path else ([target / POLICY_FILE] if target else [])
    for p in candidates:
        if p is not None and p.is_file():
            return Policy.model_validate(tomllib.loads(p.read_text("utf-8")))
    return Policy()


def evaluate(
    policy: Policy, findings: list[Finding], dismissed: set[str] | None = None
) -> list[tuple[Finding, Action, str]]:
    """(finding, action, rule name) for every finding that is not dismissed, strictest first."""
    dismissed = dismissed or set()
    rows = [(f, *policy.action_for(f)) for f in findings if f.id not in dismissed]
    return sorted(rows, key=lambda r: (-_RANK[r[1]], -r[0].priority))
