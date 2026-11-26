"""The steps a domain pack registers for the engine: the
engine collects evidence, annotates findings and picks data-flow traces only through these, so it
never imports the security pack (the `engine` import contract)."""

from __future__ import annotations

from pathlib import Path

from gapscan.config import Config
from gapscan.core.interfaces import Annotator
from gapscan.models import Category, Finding, ScanResult, Severity
from gapscan.normalize import normalize
from gapscan.pipeline import collect_evidence
from gapscan.registry import Registry, registry
from gapscan.scanners import scan_target
from gapscan.scanners.imports import RuntimeProof
from gapscan.security_pack import Reachability, SecretFacts, VulnEnrichment


def finding(cwe: str, category: Category = Category.CODE) -> Finding:
    return Finding(id="x", scanner="semgrep", rule_id="r", title="t", severity=Severity.HIGH,
                   category=category, file="a.py", start_line=1, cwe=[cwe])  # fmt: skip


def test_the_security_pack_registers_its_scan_step_annotators_and_flow_filter() -> None:
    reg = registry()
    assert reg.collectors == [scan_target]
    without_config = reg.annotators_for(None)
    assert [type(a) for a in without_config] == [
        SecretFacts,
        Reachability,
        RuntimeProof,
    ]  # KEV needs data
    with_config = reg.annotators_for(Config())
    assert [type(a) for a in with_config] == [SecretFacts, Reachability, VulnEnrichment]
    assert all(isinstance(a, Annotator) for a in with_config)
    assert [a.stage for a in with_config] == ["evidence", "context", "context"]


def test_data_flow_is_traced_for_tainted_data_only() -> None:
    reg = registry()
    assert reg.wants_flow(finding("CWE-89"))  # injection: where the data comes from matters
    assert not reg.wants_flow(finding("CWE-327"))  # weak algorithm: judged by the choice
    assert not reg.wants_flow(finding("CWE-89", Category.DEPENDENCY))
    assert Registry().wants_flow(finding("CWE-327"))  # with no pack, every code finding


def test_with_no_pack_the_engine_collects_nothing_and_annotates_nothing(tmp_path: Path) -> None:
    empty = Config(scanners={"packs": []})
    assert collect_evidence(empty, tmp_path).findings == []
    secret = finding("CWE-798", Category.SECRET)
    out = normalize(ScanResult(target="t", findings=[secret]), tmp_path, annotators=[])
    assert "secret_facts" not in out.findings[0].raw and out.vuln_data == {}
    annotated = normalize(ScanResult(target="t", findings=[secret]), tmp_path)
    assert "secret_facts" in annotated.findings[0].raw  # the default packs' annotators
