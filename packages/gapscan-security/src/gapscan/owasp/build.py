"""Build the OWASP mapping tables from the raw files in data/owasp/ (dev-time, offline).

Outputs (committed, in owasp/mappings/):
  cwe_to_top10.csv   CWE -> OWASP Top 10:2025 category, from the CWE list in each category page
  cwe_to_asvs.csv    CWE -> ASVS 5.0.0 requirement ids, with the route that produced each link
  asvs_requirements.csv  the ASVS 5.0.0 requirement list with levels (copied from the CSV)
  versions.json      exact source versions and checksums, so reports never mix editions

ASVS 5.0 dropped its CWE mappings, so two routes are combined:
  "be"       OWASP's archived v5.0.be CWE export, carried to v5.0.0 ids by OWASP's
             mapping_v5.0.be_to_v5.0.0.yml (direct, requirement-level)
  "opencre"  CWE -> CRE -> ASVS 4.0.3 requirement (OpenCRE), carried to v5.0.0 by OWASP's
             mapping_v4.0.3_to_v5.0.0.yml (MOVED/MERGED/SPLIT only; deleted ones are dropped)
OpenCRE links are looser (a CRE groups many requirements), hence the separate `via` column.
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..store.raw import RawStore

MAPPINGS_DIR = Path(__file__).parent / "mappings"
ASVS_DIR = "asvs-5.0.0"
ASVS_CSV = f"{ASVS_DIR}/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"

_CWE_LINE = re.compile(r"^\* \[CWE-(\d+)\s+(.*?)\]\(https://cwe\.mitre\.org", re.MULTILINE)
_CATEGORY_FILE = re.compile(r"^(A(\d{2}))_2025-(.+)\.md$")
_YML_LINE = re.compile(r"^(v[\d.a-z]+-[\d.]+):\s*(.*)$")
_V5_ID = re.compile(r"v5\.0\.0-\d+\.\d+\.\d+")


def parse_top10(store: RawStore) -> list[tuple[str, str, str, str]]:
    """(cwe, category 'A05:2025', category name, cwe name) for every mapped CWE."""
    rows = []
    for entry in store.manifest().entries:
        m = _CATEGORY_FILE.match(entry.path.removeprefix("top10-2025/"))
        if not m or not entry.path.startswith("top10-2025/"):
            continue
        text = store.read_raw(entry.path).decode("utf-8")
        section = text.split("## List of Mapped CWEs", 1)
        if len(section) < 2:
            raise ValueError(f"{entry.path}: no 'List of Mapped CWEs' section")
        category = f"A{m.group(2)}:2025"
        name = m.group(3).replace("_", " ")
        for cwe, cwe_name in _CWE_LINE.findall(section[1]):
            rows.append((f"CWE-{cwe}", category, name, cwe_name))
    return rows


def _read_yml_map(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = _YML_LINE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
        elif line.startswith("  tag-v5.0.0:") and out:  # nested form used by the 4.0.3 file
            out["_last_value"] = line.split(":", 1)[1].strip()
    return out


def parse_v4_to_v5(text: str) -> dict[str, list[str]]:
    """4.0.3 requirement -> v5.0.0 ids. Only MOVED/MERGED/SPLIT; DELETED-only are dropped."""
    result: dict[str, list[str]] = {}
    key: str | None = None
    for line in text.splitlines():
        m = re.match(r"^(v4\.0\.3-[\d.]+):\s*$", line)
        if m:
            key = m.group(1)
            continue
        if key and line.strip().startswith("tag-v5.0.0:"):
            value = line.split(":", 1)[1]
            if re.search(r"MOVED TO|MERGED TO|SPLIT TO", value):
                # "DELETED, COVERED BY ..." is excluded; "MERGED TO" kept; COVERED BY ids are
                # only taken when a MOVED/MERGED/SPLIT keyword is present as well.
                ids = _V5_ID.findall(re.sub(r"COVERED BY[^,]*(?:, v5\.0\.0-[\d.]+)*", "", value))
                if ids:
                    result[key] = ids
            key = None
    return result


def parse_be_to_v5(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(v5\.0\.be-[\d.]+):\s*(v5\.0\.0-[\d.]+)\s*$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def asvs_links_via_be(store: RawStore) -> list[tuple[str, str]]:
    be_cwe: dict[str, str] = json.loads(
        store.read_raw(f"{ASVS_DIR}/mappings/v5.0.be_cwe_mapping.json")
    )
    be_to_v5 = parse_be_to_v5(
        store.read_raw(f"{ASVS_DIR}/mappings/mapping_v5.0.be_to_v5.0.0.yml").decode()
    )
    return sorted({(f"CWE-{cwe}", be_to_v5[be]) for be, cwe in be_cwe.items() if be in be_to_v5})


def _opencre_pages(store: RawStore, std: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for e in store.manifest().entries:
        if e.path.startswith(f"opencre/{std}/"):
            items += json.loads(store.read_raw(e.path))["standards"]
    return items


def asvs_links_via_opencre(store: RawStore) -> list[tuple[str, str]]:
    cwe_to_cres: dict[str, set[str]] = defaultdict(set)
    for s in _opencre_pages(store, "cwe"):
        for link in s.get("links", []):
            if link["document"]["doctype"] == "CRE":
                cwe_to_cres[f"CWE-{s['sectionID']}"].add(link["document"]["id"])
    cre_to_v4: dict[str, set[str]] = defaultdict(set)
    for s in _opencre_pages(store, "asvs"):
        if "/v4.0.3/" not in s.get("hyperlink", ""):
            continue  # only 4.0.3 is in OpenCRE; the v4->v5 file is keyed on it
        for link in s.get("links", []):
            if link["document"]["doctype"] == "CRE":
                cre_to_v4[link["document"]["id"]].add("v4.0.3-" + s["sectionID"].removeprefix("V"))
    v4_to_v5 = parse_v4_to_v5(
        store.read_raw(f"{ASVS_DIR}/mappings/mapping_v4.0.3_to_v5.0.0.yml").decode()
    )
    links: set[tuple[str, str]] = set()
    for cwe, cres in cwe_to_cres.items():
        for cre in cres:
            for v4 in cre_to_v4.get(cre, ()):
                links.update((cwe, v5) for v5 in v4_to_v5.get(v4, ()))
    return sorted(links)


def _cwe_key(cwe: str) -> int:
    return int(cwe.split("-")[1])


def build(store: RawStore, out_dir: Path = MAPPINGS_DIR) -> dict[str, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    problems = store.verify()
    if problems:
        raise RuntimeError("raw OWASP data failed verification: " + "; ".join(problems))
    # Top 10
    top10 = sorted(parse_top10(store), key=lambda r: (_cwe_key(r[0]), r[1]))
    with (out_dir / "cwe_to_top10.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["cwe", "category", "category_name", "cwe_name"])
        w.writerows(top10)
    # ASVS
    be, cre = asvs_links_via_be(store), asvs_links_via_opencre(store)
    rows = dict.fromkeys(be, "be")
    for c, a in cre:
        rows.setdefault((c, a), "opencre")
    with (out_dir / "cwe_to_asvs.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["cwe", "asvs", "via"])
        for (c, a), via in sorted(rows.items(), key=lambda kv: (_cwe_key(kv[0][0]), kv[0][1])):
            w.writerow([c, a, via])
    (out_dir / "asvs_requirements.csv").write_bytes(store.read_raw(ASVS_CSV))
    # Versions + provenance
    by_path = {e.path: e for e in store.manifest().entries}
    top_versions = {e.version for p, e in by_path.items() if p.startswith("top10-2025/")}
    opencre_entries = [e for p, e in by_path.items() if p.startswith("opencre/")]
    versions = {
        "top10": {"edition": "2025", "source": sorted(top_versions)},
        "asvs": {"version": "5.0.0", "csv_sha256": by_path[ASVS_CSV].sha256,
                 "release": by_path[ASVS_CSV].version},  # fmt: skip
        "asvs_mapping_files": {p: by_path[p].version for p in by_path if "/mappings/" in p},
        "opencre": {"snapshot": sorted({e.retrieved_at[:10] for e in opencre_entries})},
        "license": "CC BY-SA 4.0 (OWASP); attribution required in reports",
    }  # fmt: skip
    (out_dir / "versions.json").write_text(json.dumps(versions, indent=2) + "\n", encoding="utf-8")
    return {"top10_rows": len(top10), "asvs_links_be": len(be), "asvs_links_opencre": len(cre),
            "asvs_links_total": len(rows)}  # fmt: skip
