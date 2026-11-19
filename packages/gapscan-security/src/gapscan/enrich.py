"""Offline vulnerability enrichment: CISA KEV and FIRST EPSS, read from local mirrors.

Both files ship in the offline bundle. No network access here (hard rule #2).
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class Enrichment:
    kev: set[str] = field(default_factory=set)
    epss: dict[str, float] = field(default_factory=dict)
    dates: dict[str, str] = field(default_factory=dict)  # dataset -> snapshot date

    def for_cves(self, cves: list[str]) -> tuple[bool, float | None]:
        scores = [self.epss[c] for c in cves if c in self.epss]
        return any(c in self.kev for c in cves), (max(scores) if scores else None)


def load_kev(path: Path) -> tuple[set[str], str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    ids = {v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v}
    return ids, str(data.get("dateReleased", ""))[:10]


def load_epss(path: Path) -> tuple[dict[str, float], str]:
    """EPSS CSV: optional '#model_version:...,score_date:...' line, then cve,epss,percentile."""
    scores: dict[str, float] = {}
    date = ""
    with path.open(encoding="utf-8", newline="") as fh:
        first = fh.readline()
        if first.startswith("#"):
            for part in first.lstrip("#").strip().split(","):
                if part.startswith("score_date:"):
                    date = part.split(":", 1)[1][:10]
        else:
            fh.seek(0)
        for row in csv.DictReader(fh):
            try:
                scores[row["cve"]] = float(row["epss"])
            except (KeyError, ValueError):
                continue
    return scores, date


def load_enrichment(directory: Path) -> Enrichment:
    """Load whatever mirrors exist; missing files just mean no enrichment."""
    out = Enrichment()
    kev_path, epss_path = directory / "kev.json", directory / "epss.csv"
    if kev_path.is_file():
        out.kev, out.dates["cisa_kev"] = load_kev(kev_path)
    else:
        log.warning("KEV mirror not found at %s; KEV prioritization disabled", kev_path)
    if epss_path.is_file():
        out.epss, out.dates["epss"] = load_epss(epss_path)
    else:
        log.warning("EPSS mirror not found at %s; EPSS scoring disabled", epss_path)
    return out
