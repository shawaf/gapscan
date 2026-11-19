"""The compliance framework catalog: which frameworks are available or planned, by group and wave.

Only the OWASP family is built today. Every other entry is a plan and
carries no edition, mapping or coverage yet, so nothing here may be shown as a compliance result.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CATALOG_PATH = Path(__file__).parent / "catalog.json"


class Group(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    label: str  # short, for the domain picker
    name: str  # long, for section headings
    text: str


class Framework(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    group: str
    region: str
    wave: Literal[0, 1, 2, 3]  # 0 = built; 1 to 3 = planned build order
    status: Literal["available", "planned"]
    text: Literal["open", "restricted"]  # restricted: copyrighted, ship IDs and own summaries only
    evidence: str  # what scans can show for it, in our own words


class Catalog(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = Field(alias="schema")
    note: str
    groups: list[Group]
    frameworks: list[Framework]

    @model_validator(mode="after")
    def _consistent(self) -> Catalog:
        groups = {g.id for g in self.groups}
        ids = [f.id for f in self.frameworks]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate framework id")
        for f in self.frameworks:
            if f.group not in groups:
                raise ValueError(f"{f.id}: unknown group {f.group}")
            if (f.status == "available") != (f.wave == 0):
                raise ValueError(f"{f.id}: only built frameworks have wave 0")
        return self


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    return Catalog.model_validate_json(CATALOG_PATH.read_text(encoding="utf-8"))


def catalog_payload() -> dict[str, object]:
    """The catalog with counts per status and wave, computed here so the UI only renders."""
    cat = load_catalog()
    counts: dict[str, int] = {"available": 0, "planned": 0, "wave_1": 0, "wave_2": 0, "wave_3": 0}
    for f in cat.frameworks:
        counts[f.status] += 1
        if f.wave:
            counts[f"wave_{f.wave}"] += 1
    groups = []
    for g in cat.groups:
        planned = [f for f in cat.frameworks if f.group == g.id and f.status == "planned"]
        groups.append(
            {**g.model_dump(), "planned": len(planned), "wave_1": sum(f.wave == 1 for f in planned)}
        )
    return {
        "note": cat.note,
        "groups": groups,
        "frameworks": [f.model_dump() for f in cat.frameworks],
        "counts": counts,
    }
