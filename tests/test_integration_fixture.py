"""Phase 1 'done when': scanning eval/fixtures produces normalized findings from at least
Semgrep, OSV-Scanner and Gitleaks. Needs the real binaries and offline data, so it is
skipped on machines without them (CI uses the recorded-output tests instead)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gapscan.cli import app

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "eval" / "fixtures" / "vuln-app"
needs = pytest.mark.skipif(
    not all(shutil.which(b) for b in ("semgrep", "osv-scanner", "gitleaks"))
    or not (ROOT / "data" / "osv-db").is_dir()
    or not (ROOT / "data" / "semgrep-rules").is_dir(),
    reason="scanner binaries or offline data not installed",
)


@needs
def test_fixture_scan_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    out = tmp_path / "f.json"
    res = CliRunner().invoke(app, ["scan", str(FIXTURE), "-o", str(out)])
    assert res.exit_code == 0, res.stdout
    data = json.loads(out.read_text())
    assert (
        data["schema_version"] == 1 and data["created_at"].endswith("Z") and data["gapscan_version"]
    )
    ok = {r["scanner"] for r in data["runs"] if r["status"] == "ok"}
    assert {"semgrep", "osv", "gitleaks"} <= ok
    sources = {s for f in data["findings"] for s in f["sources"]}
    assert {"semgrep", "osv", "gitleaks"} <= sources
    # Some issues are reported by several tools and must have been merged.
    assert any(len(f["sources"]) > 1 for f in data["findings"])
    # Hard rule #4: no secret value anywhere in the output.
    text = out.read_text()
    for secret in ("ghp_aB3dE5", "AKIAJ3XK7QW2", "wJ8nQ2xLm4Rt"):
        assert secret not in text
    assert data["sbom"] is None or data["sbom"].get("bomFormat") == "CycloneDX"
