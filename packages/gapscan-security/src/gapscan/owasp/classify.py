"""The CWE -> OWASP Top 10:2025 and ASVS 5.0.0 mapping tables, built from OWASP's published data
(`owasp/build.py`). CWE is the pivot. The target packs (`owasp/packs.py`) use these tables to map
findings to controls; tags never come from model output.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

MAPPINGS_DIR = Path(__file__).parent / "mappings"
_VIA_ORDER = {"be": 0, "opencre": 1}  # requirement-level links before looser OpenCRE ones


@dataclass(frozen=True)
class Tables:
    top10: dict[str, list[str]]  # CWE-n -> categories
    top10_names: dict[str, str]  # A05:2025 -> Injection
    asvs: dict[str, list[str]]  # CWE-n -> requirement ids, best links first
    versions: dict[str, object]
    cwe_names: dict[str, str]  # CWE-n -> short name (from the Top 10 pages)


def _read(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


@lru_cache(maxsize=1)
def load_tables(directory: Path | None = None) -> Tables:
    d = directory or MAPPINGS_DIR
    top10: dict[str, list[str]] = defaultdict(list)
    names: dict[str, str] = {}
    cwe_names: dict[str, str] = {}
    for r in _read(d / "cwe_to_top10.csv"):
        top10[r["cwe"]].append(r["category"])
        names[r["category"]] = r["category_name"]
        cwe_names[r["cwe"]] = r["cwe_name"]
    links: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for r in _read(d / "cwe_to_asvs.csv"):
        links[r["cwe"]].append((_VIA_ORDER[r["via"]], r["asvs"]))
    asvs = {c: [a for _, a in sorted(v)] for c, v in links.items()}
    versions = json.loads((d / "versions.json").read_text(encoding="utf-8"))
    return Tables(dict(top10), names, asvs, versions, cwe_names)


def normalize_cwe(cwe: str) -> str | None:
    digits = cwe.upper().removeprefix("CWE-").strip()
    return f"CWE-{int(digits)}" if digits.isdigit() else None
