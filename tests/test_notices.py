"""License notices that must travel with what GapScan ships (docs/licenses.md)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from gapscan.offline.bundle import (
    MITRE_COPYRIGHT,
    MITRE_CWE_LICENSE,
    BundleManifest,
    notices,
)
from gapscan.report.dashboard import TEMPLATE_PATH

ROOT = Path(__file__).resolve().parent.parent
MANAGER_TEMPLATE = (
    ROOT
    / "packages"
    / "gapscan-local"
    / "src"
    / "gapscan"
    / "server"
    / "templates"
    / "manager.html"
)
INLINED = ("preact", "echarts", "zrender", "highlight.js", "tslib")


def test_the_mitre_license_is_reproduced_whole():
    # The CWE Terms of Use grant, word for word (https://cwe.mitre.org/about/termsofuse.html).
    assert MITRE_CWE_LICENSE.startswith("CWE™ is free to use by any organization or individual")
    assert "reproduce MITRE’s copyright designation and this license in any such copy" in (
        MITRE_CWE_LICENSE
    )
    assert MITRE_CWE_LICENSE.endswith("if you require further clarification on this issue.")
    assert "  " not in MITRE_CWE_LICENSE  # the source-code line splits added no gaps
    assert MITRE_COPYRIGHT.startswith("Copyright © 2006–2026, The MITRE Corporation.")


def test_bundles_and_the_repository_carry_the_mitre_notice(tmp_path):
    text = notices(BundleManifest(created_at="2026-10-09"), tmp_path)
    repo = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    for doc in (text, repo):
        assert MITRE_COPYRIGHT in doc and MITRE_CWE_LICENSE in doc
        assert "CC BY-SA 4.0" in doc


@pytest.mark.parametrize("template", [TEMPLATE_PATH, MANAGER_TEMPLATE], ids=["report", "manager"])
def test_single_file_pages_embed_the_inlined_libraries_licenses(template):
    if not template.is_file():
        pytest.skip("template not built (make dashboard / make manager)")
    html = template.read_text(encoding="utf-8")
    m = re.search(r'<script type="text/plain" id="third-party-notices">(.*?)</script>', html, re.S)
    assert m, "notices block missing"
    block = m.group(1)
    for name in INLINED:
        assert f"=== {name} " in block, name
    assert "Apache License" in block and "--- NOTICE ---" in block  # ECharts' NOTICE travels too
