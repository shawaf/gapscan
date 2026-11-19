"""ASVS 5.0.0 requirement list and level filtering (the CSV is OWASP's own release asset).

Level semantics: the CSV's `L` column is the lowest level that includes the requirement, so
level N covers every requirement with L <= N.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

MAPPINGS_DIR = Path(__file__).parent / "mappings"
ASVS_VERSION = "5.0.0"


@dataclass(frozen=True)
class Requirement:
    id: str  # stable format: v5.0.0-<chapter>.<section>.<requirement>
    chapter: str
    section: str
    description: str
    level: int


def requirement_id(csv_id: str) -> str:
    """'V1.2.5' -> 'v5.0.0-1.2.5'."""
    return f"v{ASVS_VERSION}-{csv_id.removeprefix('V')}"


@lru_cache(maxsize=1)
def load_requirements(path: Path | None = None) -> tuple[Requirement, ...]:
    path = path or MAPPINGS_DIR / "asvs_requirements.csv"
    with path.open(encoding="utf-8", newline="") as fh:
        return tuple(
            Requirement(
                id=requirement_id(r["req_id"]),
                chapter=f"{r['chapter_id']} {r['chapter_name']}",
                section=f"{r['section_id']} {r['section_name']}",
                description=r["req_description"],
                level=int(r["L"]),
            )
            for r in csv.DictReader(fh)
        )


def requirements_for_level(level: int) -> list[Requirement]:
    if level not in (1, 2, 3):
        raise ValueError(f"ASVS level must be 1, 2 or 3, got {level}")
    return [r for r in load_requirements() if r.level <= level]
