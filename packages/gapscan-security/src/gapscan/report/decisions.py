"""Reviewer decisions (accepted risk / false positive / fixed), kept in a file the user owns.

The dashboard exports it, `gapscan report --decisions` reads it on the next scan, and because
finding IDs are stable fingerprints the decisions carry over when code moves."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from .schema import DecisionKind

DECISIONS_VERSION = 1
FILENAME = "gapscan-decisions.json"


class Decision(BaseModel):
    finding_id: str
    decision: DecisionKind
    note: str = ""
    by: str = ""
    date: str = ""


class Decisions(BaseModel):
    version: int = DECISIONS_VERSION
    decisions: list[Decision] = Field(default_factory=list)

    def by_id(self) -> dict[str, Decision]:
        return {d.finding_id: d for d in self.decisions}  # later entries win


def load_decisions(path: Path | None) -> Decisions:
    if path is None or not path.is_file():
        return Decisions()
    data = Decisions.model_validate_json(path.read_text(encoding="utf-8"))
    if data.version != DECISIONS_VERSION:
        raise ValueError(f"unsupported decisions file version {data.version}")
    return data
