"""Add per-standard coverage to the dashboard fixture (dashboard/fixtures/report.json).

The fixture is a triaged report kept for UI work. This recomputes its `coverage` section with the
real builder (gapscan.report.coverage) from the fixture's own open findings and their Top 10 and
ASVS tags, so the Coverage page has realistic data without replacing the rest of the fixture.

    uv run python tools/fixture_coverage.py
"""

from __future__ import annotations

import json
from pathlib import Path

from gapscan.owasp.packs import ASVS, TOP10
from gapscan.registry import registry
from gapscan.report.coverage import coverage_by_target

FIXTURE = Path(__file__).resolve().parent.parent / "dashboard" / "fixtures" / "report.json"


def main() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    open_controls = [
        (r["id"], [(TOP10, c) for c in r.get("owasp", [])] + [(ASVS, c) for c in r.get("asvs", [])])
        for r in data["findings"]
        if r.get("open")
    ]
    level = data["meta"].get("asvs_level", 2)
    data["coverage"] = [
        c.model_dump(mode="json")
        for c in coverage_by_target(registry().target_packs, open_controls, level)
    ]
    FIXTURE.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for c in data["coverage"]:
        print(f"{c['name']} {c['version']}: {c['evidence_of_failure']} failing of {c['total']}")


if __name__ == "__main__":
    main()
