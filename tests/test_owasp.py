from __future__ import annotations

import json
from pathlib import Path

import pytest

from gapscan.config import Config
from gapscan.models import Category, Finding, MappingSource, Severity
from gapscan.owasp.asvs import load_requirements, requirement_id, requirements_for_level
from gapscan.owasp.build import build, parse_be_to_v5, parse_v4_to_v5
from gapscan.owasp.classify import load_tables, normalize_cwe
from gapscan.owasp.packs import MAX_ASVS_PER_FINDING, SUPPLY_CHAIN, classify_finding
from gapscan.scanners.bandit import parse_bandit
from gapscan.scanners.gitleaks import parse_gitleaks
from gapscan.scanners.osv import parse_osv
from gapscan.scanners.sarif import parse_sarif
from gapscan.store.raw import RawStore

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
TARGET = ROOT / "eval" / "fixtures" / "vuln-app"


def finding(cwe, cat=Category.CODE):
    return Finding(
        scanner="s", rule_id="r", title="t", severity=Severity.HIGH, category=cat, cwe=cwe
    )


def test_table_matches_published_top10_facts():
    t = load_tables()
    assert sorted(t.top10_names) == [f"A{i:02d}:2025" for i in range(1, 11)]
    assert t.top10_names["A05:2025"] == "Injection"
    # The Injection page states "37 CWEs in this category"; the table must agree.
    assert sum("A05:2025" in v for v in t.top10.values()) == 37
    assert "A05:2025" in t.top10["CWE-79"]  # XSS is part of Injection in 2025
    assert "A01:2025" in t.top10["CWE-918"]  # SSRF is part of A01 in 2025
    assert t.versions["top10"]["edition"] == "2025" and t.versions["asvs"]["version"] == "5.0.0"


@pytest.mark.parametrize(
    ("cwe", "category"),
    [("CWE-89", "A05:2025"), ("CWE-78", "A05:2025"), ("CWE-502", "A08:2025"),
     ("CWE-327", "A04:2025"), ("CWE-798", "A07:2025"), ("CWE-22", "A01:2025")],
)  # fmt: skip
def test_classify_known_cwes(cwe, category):
    f = finding([cwe])
    classify_finding(f)
    assert f.owasp_top10[0] == category and f.mapping_source == MappingSource.TABLE


def test_classify_asvs_links():
    f = finding(["CWE-89"])
    classify_finding(f)
    assert "v5.0.0-1.2.4" in f.asvs  # SQL injection prevention requirement
    f = finding(["CWE-78"])
    classify_finding(f)
    assert f.asvs[0] == "v5.0.0-1.2.5"  # requirement-level link ranks before OpenCRE ones


def test_asvs_capped_and_ordered():
    f = finding(["CWE-798"])
    classify_finding(f)
    assert 0 < len(f.asvs) <= MAX_ASVS_PER_FINDING


def test_dependencies_are_supply_chain_first():
    f = finding(["CWE-89"], Category.DEPENDENCY)
    classify_finding(f)
    assert f.owasp_top10 == [SUPPLY_CHAIN, "A05:2025"]
    g = finding([], Category.DEPENDENCY)
    classify_finding(g)
    assert g.owasp_top10 == [SUPPLY_CHAIN]


def test_unmapped_or_missing_cwe_gets_no_tags_not_guesses():
    f = finding(["CWE-250"])  # real CWE that is in no Top 10:2025 category
    classify_finding(f)
    assert f.owasp_top10 == []  # no guessed category (it may still have ASVS links)
    unknown = finding(["CWE-99999"])
    classify_finding(unknown)
    assert unknown.owasp_top10 == [] and unknown.asvs == []
    assert unknown.mapping_source == MappingSource.SCANNER
    g = finding([])
    classify_finding(g)
    assert g.owasp_top10 == [] and g.asvs == []


def test_normalize_cwe():
    assert normalize_cwe("cwe-089") == "CWE-89" and normalize_cwe("89") == "CWE-89"
    assert normalize_cwe("CWE-x") is None


def test_every_fixture_finding_with_a_cwe_gets_the_mapped_category():
    """Phase 2 'done when', on real recorded scanner output."""
    load = lambda n: json.loads((DATA / n).read_text().replace("TARGET", str(TARGET)))  # noqa: E731
    fs = (
        parse_sarif(load("semgrep.sarif"), TARGET, "semgrep")
        + parse_bandit(load("bandit.json"), TARGET)
        + parse_gitleaks(load("gitleaks.json"), TARGET)
        + parse_osv(load("osv.json"), TARGET)
    )
    t = load_tables()
    with_cwe = [f for f in fs if f.cwe]
    assert len(with_cwe) > 20
    for f in with_cwe:
        classify_finding(f)
        expected = {c for cwe in f.cwe for c in t.top10.get(cwe, [])}
        if f.category == Category.DEPENDENCY:
            expected.add(SUPPLY_CHAIN)
        assert set(f.owasp_top10) == expected, (f.rule_id, f.cwe)
    sqli = next(f for f in with_cwe if f.cwe == ["CWE-89"] and f.scanner == "semgrep")
    assert sqli.owasp_top10 == ["A05:2025"]


def test_asvs_requirements_and_levels():
    reqs = load_requirements()
    assert reqs[0].id == "v5.0.0-1.1.1" and requirement_id("V12.3.4") == "v5.0.0-12.3.4"
    l1, l2, l3 = (len(requirements_for_level(n)) for n in (1, 2, 3))
    assert 0 < l1 < l2 < l3 == len(reqs)
    with pytest.raises(ValueError):
        requirements_for_level(4)
    assert Config().general.asvs_level == 2


def test_parse_v4_to_v5_keeps_only_real_relocations():
    text = """---
v4.0.3-1.1.5:
  tag-v5.0.0: MOVED TO v5.0.0-13.1.1
v4.0.3-1.2.4:
  tag-v5.0.0: MODIFIED, MOVED TO v5.0.0-6.1.3, SPLIT TO v5.0.0-6.3.4
v4.0.3-1.1.1:
  tag-v5.0.0: DELETED, NOT IN SCOPE
v4.0.3-1.2.3:
  tag-v5.0.0: DELETED, COVERED BY v5.0.0-6.1.3
v4.0.3-2.1.1:
  tag-v5.0.0: DELETED, MERGED TO v5.0.0-6.2.1
"""
    m = parse_v4_to_v5(text)
    assert m == {
        "v4.0.3-1.1.5": ["v5.0.0-13.1.1"],
        "v4.0.3-1.2.4": ["v5.0.0-6.1.3", "v5.0.0-6.3.4"],
        "v4.0.3-2.1.1": ["v5.0.0-6.2.1"],
    }
    assert parse_be_to_v5("v5.0.be-5.6.1: v5.0.0-1.1.1\nv5.0.be-9.9.9: DELETED\n") == {
        "v5.0.be-5.6.1": "v5.0.0-1.1.1"
    }


def test_committed_tables_match_a_fresh_build_from_raw_data(tmp_path):
    raw = ROOT / "data" / "owasp"
    if not (raw / "manifest.json").is_file():
        pytest.skip("raw OWASP data not downloaded")
    build(RawStore(raw), tmp_path)
    committed = ROOT / "packages" / "gapscan-security" / "src" / "gapscan" / "owasp" / "mappings"
    for name in ("cwe_to_top10.csv", "cwe_to_asvs.csv", "asvs_requirements.csv"):
        assert (tmp_path / name).read_bytes() == (committed / name).read_bytes(), name


def test_build_refuses_tampered_raw_data(tmp_path):
    store = RawStore(tmp_path / "raw")
    store.save("top10-2025/A01_2025-X.md", b"x", url="u", source="s", version="v")
    (tmp_path / "raw" / "top10-2025" / "A01_2025-X.md").write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="verification"):
        build(store, tmp_path / "out")
