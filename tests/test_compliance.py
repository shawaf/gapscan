"""The compliance framework catalog."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from gapscan.compliance.catalog import CATALOG_PATH, Catalog, catalog_payload, load_catalog


def test_catalog_loads_and_only_owasp_is_built():
    cat = load_catalog()
    available = [f.id for f in cat.frameworks if f.status == "available"]
    assert available == ["owasp"]
    assert {f.group for f in cat.frameworks} == {g.id for g in cat.groups}


def test_payload_counts_are_computed_from_the_catalog():
    p = catalog_payload()
    frameworks = p["frameworks"]
    assert isinstance(frameworks, list)
    counts = p["counts"]
    assert counts["available"] + counts["planned"] == len(frameworks)
    assert counts["wave_1"] + counts["wave_2"] + counts["wave_3"] == counts["planned"]
    groups = p["groups"]
    assert isinstance(groups, list)
    assert sum(g["planned"] for g in groups) == counts["planned"]
    assert sum(g["wave_1"] for g in groups) == counts["wave_1"]
    wave1 = {f["id"] for f in frameworks if f["wave"] == 1}
    assert wave1 == {"nist-ssdf", "iso-27001", "soc2", "nist-csf", "cis", "pci-dss"}


def test_catalog_rejects_inconsistent_entries():
    raw = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    bad = dict(raw, frameworks=[*raw["frameworks"], raw["frameworks"][1]])
    with pytest.raises(ValidationError, match="duplicate"):
        Catalog.model_validate(bad)
    planned_but_built = dict(raw["frameworks"][1], wave=0)
    with pytest.raises(ValidationError, match="wave 0"):
        Catalog.model_validate(dict(raw, frameworks=[planned_but_built]))
    with pytest.raises(ValidationError, match="unknown group"):
        Catalog.model_validate(dict(raw, frameworks=[dict(raw["frameworks"][1], group="nope")]))
