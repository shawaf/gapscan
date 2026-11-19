"""The security domain's target packs (ARCHITECTURE.md section 3): one per OWASP standard that has
mapping data. Each pack lists its controls and maps a finding's evidence to them from tables built
out of OWASP's published data, never from model output.

- Top 10:2025 and ASVS 5.0.0 map by CWE (`mappings/cwe_to_*.csv`, built by `owasp/build.py`).
- MASVS 2.1.0 maps by rule id: GapScan's own mobile rules declare their control in their
  metadata, which Semgrep's SARIF drops, so `rules/rule_controls.csv` keeps it
  (`tools/build_rule_controls.py`).

The API Security Top 10 2023 has no mapping data yet, so it has no pack; its findings view stays
empty rather than guessed.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from ..controls import map_controls
from ..core.interfaces import TargetPack
from ..core.models import Category, Control, ControlRef, Finding
from .asvs import ASVS_VERSION, load_requirements
from .classify import MAPPINGS_DIR, Tables, load_tables, normalize_cwe

TOP10 = "owasp-top10"
ASVS = "owasp-asvs"
MASVS = "owasp-masvs"
API_TOP10 = "owasp-api-top10"  # no pack yet: no mapping data

SUPPLY_CHAIN = "A03:2025"  # Software Supply Chain Failures covers vulnerable dependencies
MAX_ASVS_PER_FINDING = 8
MASVS_VERSION = "2.1.0"  # OWASP/masvs release v2.1.0, the latest release (checked 2026-10-14)
RULE_CONTROLS = Path(__file__).resolve().parent.parent / "rules" / "rule_controls.csv"


def _cwes(finding: Finding) -> list[str]:
    return [c for c in (normalize_cwe(x) for x in finding.cwe) if c]


class Top10Pack:
    id = TOP10
    name = "OWASP Top 10"

    def __init__(self, tables: Tables | None = None) -> None:
        self.tables = tables or load_tables()
        self.version = str(self.tables.versions["top10"]["edition"])  # type: ignore[index]

    def _ref(self, category: str) -> ControlRef:
        return ControlRef(target=self.id, version=self.version, control_id=category)

    def controls(self) -> list[Control]:
        return [Control(ref=self._ref(c), title=name)
                for c, name in sorted(self.tables.top10_names.items())]  # fmt: skip

    def checkable(self) -> frozenset[str]:
        """Categories that CWE-tagged findings can land in (every category with a CWE list)."""
        return frozenset(c for ids in self.tables.top10.values() for c in ids)

    def controls_for(self, finding: Finding) -> list[ControlRef]:
        """The first category is the primary one; vulnerable dependencies lead with A03."""
        ids = [SUPPLY_CHAIN] if finding.category == Category.DEPENDENCY else []
        for c in _cwes(finding):
            ids += [x for x in self.tables.top10.get(c, []) if x not in ids]
        return [self._ref(x) for x in ids]


class AsvsPack:
    id = ASVS
    name = "OWASP ASVS"
    version = ASVS_VERSION

    def __init__(self, tables: Tables | None = None) -> None:
        self.tables = tables or load_tables()

    def _ref(self, requirement: str) -> ControlRef:
        return ControlRef(target=self.id, version=self.version, control_id=requirement)

    def controls(self) -> list[Control]:
        return [Control(ref=self._ref(r.id), title=r.description, group=r.chapter, level=r.level)
                for r in load_requirements()]  # fmt: skip

    def checkable(self) -> frozenset[str]:
        """Requirements with a requirement-level CWE link from OWASP's own mapping (`via` 'be',
        the archived v5.0 CWE export), not the looser OpenCRE grouping."""
        return _asvs_requirement_links()

    def controls_for(self, finding: Finding) -> list[ControlRef]:
        """Requirement-level links first (see `classify.load_tables`), at most eight."""
        ids: list[str] = []
        for c in _cwes(finding):
            ids += [x for x in self.tables.asvs.get(c, []) if x not in ids]
        return [self._ref(x) for x in ids[:MAX_ASVS_PER_FINDING]]


@lru_cache(maxsize=1)
def _asvs_requirement_links() -> frozenset[str]:
    with (MAPPINGS_DIR / "cwe_to_asvs.csv").open(encoding="utf-8", newline="") as fh:
        return frozenset(r["asvs"] for r in csv.DictReader(fh) if r["via"] == "be")


@lru_cache(maxsize=1)
def _rule_controls(path: Path = RULE_CONTROLS) -> dict[str, dict[str, list[str]]]:
    """target -> rule id -> control ids."""
    out: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    with path.open(encoding="utf-8", newline="") as fh:
        for r in csv.DictReader(fh):
            out[r["target"]][r["rule_id"]].append(r["control_id"])
    return {t: dict(rules) for t, rules in out.items()}


class MasvsPack:
    id = MASVS
    name = "OWASP MASVS"
    version = MASVS_VERSION

    def _ref(self, control: str) -> ControlRef:
        return ControlRef(target=self.id, version=self.version, control_id=control)

    def controls(self) -> list[Control]:
        with (MAPPINGS_DIR / "masvs_controls.csv").open(encoding="utf-8", newline="") as fh:
            return [Control(ref=self._ref(r["control_id"]), title=r["title"], group=r["group"])
                    for r in csv.DictReader(fh)]  # fmt: skip

    def controls_for(self, finding: Finding) -> list[ControlRef]:
        return [self._ref(c) for c in _rule_controls().get(self.id, {}).get(finding.rule_id, [])]

    def checkable(self) -> frozenset[str]:
        """Controls at least one of GapScan's own rules declares."""
        return frozenset(c for ids in _rule_controls().get(self.id, {}).values() for c in ids)


def security_target_packs(tables: Tables | None = None) -> list[TargetPack]:
    """The packs findings are mapped against, in the order their controls are listed."""
    t = tables or load_tables()
    return [Top10Pack(t), AsvsPack(t), MasvsPack()]


def classify_finding(f: Finding, packs: list[TargetPack] | None = None) -> None:
    """Map one finding to the security packs' controls (`gapscan.controls.map_controls`)."""
    map_controls([f], packs or _default_packs())


def classify_findings(findings: list[Finding], packs: list[TargetPack] | None = None) -> None:
    map_controls(findings, packs or _default_packs())


@lru_cache(maxsize=1)
def _default_packs() -> list[TargetPack]:
    return security_target_packs()
