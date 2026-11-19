"""Regenerate packages/gapscan-security/src/gapscan/rules/rule_controls.csv from the metadata of GapScan's own Semgrep rules.

Semgrep's SARIF output drops custom rule metadata (it keeps only CWE and tags), so the controls a
rule declares (for example `masvs: ["MASVS-CRYPTO-1"]`) are collected here into a table the target
packs read by rule id. Run after adding or changing a rule's control metadata:

    uv run python tools/build_rule_controls.py

`tests/test_target_packs.py` fails when the table is out of date. Needs PyYAML (dev dependencies).
"""

from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "packages" / "gapscan-security" / "src" / "gapscan" / "rules" / "semgrep"
OUT = ROOT / "packages" / "gapscan-security" / "src" / "gapscan" / "rules" / "rule_controls.csv"
# Rule metadata key -> target pack id (gapscan.owasp.packs).
METADATA_TARGETS = {"masvs": "owasp-masvs"}


def render(rules_dir: Path = RULES) -> str:
    rows: set[tuple[str, str, str]] = set()
    for path in sorted(rules_dir.rglob("*.y*ml")):
        for rule in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("rules", []):
            meta = rule.get("metadata") or {}
            for key, target in METADATA_TARGETS.items():
                for control in meta.get(key) or []:
                    rows.add((rule["id"], target, str(control)))
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["rule_id", "target", "control_id"])
    w.writerows(sorted(rows))
    return buf.getvalue()


if __name__ == "__main__":
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({render().count(chr(10)) - 1} rows)", file=sys.stderr)
