"""Controls and target packs: findings carry `controls`, the old tag fields are
read-only views, and the security pack maps Top 10, ASVS and MASVS from tables, never from models."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from gapscan.core.interfaces import TargetPack
from gapscan.core.models import (
    LEGACY_CONTROL_FIELDS,
    Category,
    ControlRef,
    Finding,
    MappingSource,
    ScanResult,
    Severity,
)
from gapscan.owasp.asvs import load_requirements
from gapscan.owasp.packs import (
    API_TOP10,
    ASVS,
    MASVS,
    MASVS_VERSION,
    TOP10,
    AsvsPack,
    MasvsPack,
    Top10Pack,
    classify_finding,
    security_target_packs,
)
from gapscan.scanners.sarif import parse_sarif
from gapscan.scanners.semgrep import postprocess

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"


def finding(**kw) -> Finding:
    base = {"scanner": "semgrep", "rule_id": "r", "title": "t", "severity": Severity.HIGH,
            "category": Category.CODE}  # fmt: skip
    return Finding(**{**base, **kw})


# --- the packs ---------------------------------------------------------------------------------


def test_pack_ids_match_the_legacy_views_in_core() -> None:
    assert set(LEGACY_CONTROL_FIELDS.values()) == {TOP10, ASVS, API_TOP10, MASVS}


def test_every_security_pack_conforms_and_lists_its_controls() -> None:
    packs = {p.id: p for p in security_target_packs()}
    assert set(packs) == {TOP10, ASVS, MASVS}  # API Top 10 has no mapping data: no pack
    for pack in packs.values():
        assert isinstance(pack, TargetPack)
        controls = pack.controls()
        assert controls and all(c.ref.target == pack.id for c in controls)
        assert all(c.ref.version == pack.version for c in controls)
        assert len({c.ref for c in controls}) == len(controls)
    assert [c.ref.control_id for c in packs[TOP10].controls()] == [
        f"A{i:02d}:2025" for i in range(1, 11)
    ]
    assert len(packs[ASVS].controls()) == len(load_requirements())
    assert len(packs[MASVS].controls()) == 24  # MASVS v2.1.0: 8 groups, 24 controls


def test_masvs_is_the_latest_release_of_the_expected_edition() -> None:
    expected = json.loads(
        (ROOT / "packages/gapscan-security/src/gapscan/owasp/expected_editions.json").read_text()
    )
    assert MASVS_VERSION.split(".")[0] == expected["masvs"]


def test_every_control_a_rule_declares_exists_in_masvs() -> None:
    from gapscan.owasp.packs import _rule_controls

    known = {c.ref.control_id for c in MasvsPack().controls()}
    declared = {c for ids in _rule_controls()[MASVS].values() for c in ids}
    assert declared and declared <= known, declared - known


def test_rule_controls_table_matches_the_rules() -> None:
    """Regenerate with `uv run python tools/build_rule_controls.py` when this fails."""
    pytest.importorskip("yaml")
    spec = importlib.util.spec_from_file_location("brc", ROOT / "tools/build_rule_controls.py")
    assert spec and spec.loader
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    assert (
        ROOT / "packages/gapscan-security/src/gapscan/rules/rule_controls.csv"
    ).read_text() == tool.render()


# --- mapping findings --------------------------------------------------------------------------


def test_controls_keep_pack_order_and_the_primary_category_first() -> None:
    f = finding(rule_id="gapscan.kotlin.weak-key-length", cwe=["CWE-326"])
    classify_finding(f)
    assert [c.target for c in f.controls][0] == TOP10
    assert f.control_ids(TOP10) == ["A04:2025"]
    assert f.control_ids(ASVS) and f.control_ids(MASVS) == ["MASVS-CRYPTO-1"]
    assert f.mapping_source == MappingSource.TABLE
    assert (
        ControlRef(target=MASVS, version=MASVS_VERSION, control_id="MASVS-CRYPTO-1") in f.controls
    )


def test_recorded_semgrep_output_reaches_masvs_controls() -> None:
    """Semgrep's SARIF drops rule metadata; the rule-id table brings the MASVS control back."""
    target = Path("/scan")
    raw = json.loads((DATA / "semgrep-kotlin-masvs.sarif").read_text().replace("TARGET", "/scan"))
    fs = postprocess(parse_sarif(raw, target, "semgrep"))
    assert len(fs) > 10
    for f in fs:
        classify_finding(f)
    assert all(f.rule_id.startswith("gapscan.kotlin.") for f in fs)
    assert all(f.control_ids(MASVS) for f in fs), [f.rule_id for f in fs if not f.masvs]
    weak = next(f for f in fs if f.rule_id == "gapscan.kotlin.weak-key-length")
    assert weak.masvs == ["MASVS-CRYPTO-1"]


def test_a_finding_no_pack_maps_keeps_its_controls() -> None:
    mine = ControlRef(target="example", version="1", control_id="C-1")
    f = finding(cwe=["CWE-99999"], controls=[mine])
    classify_finding(f)
    assert f.controls == [mine] and f.mapping_source == MappingSource.SCANNER


def test_packs_can_be_chosen_per_call() -> None:
    f = finding(rule_id="gapscan.kotlin.weak-key-length", cwe=["CWE-326"])
    classify_finding(f, [MasvsPack()])
    assert {c.target for c in f.controls} == {MASVS}
    g = finding(cwe=["CWE-89"], category=Category.DEPENDENCY)
    classify_finding(g, [Top10Pack(), AsvsPack()])
    assert g.control_ids(TOP10) == ["A03:2025", "A05:2025"]


# --- the read-only views -----------------------------------------------------------------------


def test_old_tag_input_becomes_controls_with_the_edition() -> None:
    f = finding(owasp_top10=["A05:2025"], asvs=["v5.0.0-1.2.4"], masvs=["MASVS-CODE-4"])
    assert ControlRef(target=TOP10, version="2025", control_id="A05:2025") in f.controls
    assert ControlRef(target=ASVS, version="5.0.0", control_id="v5.0.0-1.2.4") in f.controls
    assert f.owasp_top10 == ["A05:2025"] and f.asvs == ["v5.0.0-1.2.4"]
    assert f.masvs == ["MASVS-CODE-4"] and f.api_top10 == []


def test_views_are_read_only() -> None:
    f = finding()
    with pytest.raises(AttributeError):
        f.owasp_top10 = ["A05:2025"]  # type: ignore[misc]


def test_dumps_keep_the_old_keys_and_round_trip_through_controls() -> None:
    f = finding(rule_id="gapscan.kotlin.weak-key-length", cwe=["CWE-326"])
    classify_finding(f)
    dumped = json.loads(f.model_dump_json())
    assert dumped["owasp_top10"] == ["A04:2025"] and dumped["masvs"] == ["MASVS-CRYPTO-1"]
    again = Finding.model_validate_json(f.model_dump_json())
    assert again.controls == f.controls and again.id == f.id


def test_a_scan_saved_before_controls_existed_still_loads() -> None:
    old = {"target": "/x", "findings": [{
        "scanner": "semgrep", "rule_id": "r", "title": "t", "severity": "high", "category": "code",
        "cwe": ["CWE-89"], "owasp_top10": ["A05:2025"], "asvs": ["v5.0.0-1.2.4"], "api_top10": [],
        "masvs": [], "mapping_source": "table"}]}  # fmt: skip
    f = ScanResult.model_validate(old).findings[0]
    assert f.owasp_top10 == ["A05:2025"] and f.asvs == ["v5.0.0-1.2.4"]
    assert f.mapping_source == MappingSource.TABLE


def test_target_packs_come_from_the_registry_and_normalize_uses_the_ones_given(tmp_path) -> None:
    from gapscan.normalize import normalize
    from gapscan.registry import Registry, registry

    assert [t.id for t in registry().target_packs] == [TOP10, ASVS, MASVS]
    reg = Registry()
    reg.add_target_pack(MasvsPack())
    with pytest.raises(ValueError, match="twice"):
        reg.add_target_pack(MasvsPack())
    raw = ScanResult(target=str(tmp_path), findings=[
        finding(rule_id="gapscan.kotlin.weak-key-length", cwe=["CWE-326"], file="a.kt", start_line=1)
    ])  # fmt: skip
    only_masvs = normalize(raw, tmp_path, target_packs=[MasvsPack()]).findings[0]
    assert {c.target for c in only_masvs.controls} == {MASVS}
    every = normalize(raw, tmp_path).findings[0]  # default: the registered packs
    assert {c.target for c in every.controls} == {TOP10, ASVS, MASVS}
