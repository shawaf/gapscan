"""Triage memories: short notes a team's reviewers wrote about *their* project, retrieved when a
similar finding is triaged ("this folder is not deployed", "sanitizeId() really validates it").

Properties that keep them safe and honest:
* Visible, editable, deletable: a plain JSON file the team owns (`gapscan memory ...`), never a
  hidden model state. Nothing is learned silently.
* Scoped: a memory applies by rule, path and/or weakness, so a note about one folder never leaks
  into another.
* Advisory only: they reach the model as context. The deterministic guardrails (installed
  vulnerable dependencies, KEV, prompt-injection detection, secrets, rule-decided findings) are
  applied afterwards and cannot be overridden by any memory.
* Auditable: every verdict lists the memories that were shown for it.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from .models import Finding

MEMORY_VERSION = 1
MIN_NOTE_CHARS = 12  # a decision without a real explanation teaches nothing
MAX_TEXT = 400
Kind = Literal["false_positive", "confirmed", "accepted_risk", "context"]
_KIND_WORDS = {
    "false_positive": "reviewers judged a similar finding NOT a real weakness",
    "confirmed": "reviewers confirmed a similar finding IS a real weakness",
    "accepted_risk": "reviewers accepted the risk of a similar finding",
    "context": "note about this project",
}


class Memory(BaseModel):
    id: str = ""
    text: str = Field(max_length=MAX_TEXT)
    kind: Kind = "context"
    rule: str = ""  # a rule id or just its last segment; "" matches any rule
    path: str = ""  # a directory prefix or glob relative to the scan root; "" matches any file
    cwe: str = ""  # e.g. "CWE-22"; "" matches any weakness
    source: str = "manual"  # manual | decision:<finding id>
    created: str = ""
    enabled: bool = True

    def model_post_init(self, _ctx: object) -> None:
        if not self.id:
            key = "|".join([self.text, self.rule, self.path, self.cwe])
            self.id = hashlib.sha256(key.encode()).hexdigest()[:10]
        if not self.created:
            self.created = datetime.now(UTC).strftime("%Y-%m-%d")


class MemoryFile(BaseModel):
    version: int = MEMORY_VERSION
    memories: list[Memory] = Field(default_factory=list)


def load_memories(path: Path | None) -> list[Memory]:
    if path is None or not path.is_file():
        return []
    data = MemoryFile.model_validate_json(path.read_text(encoding="utf-8"))
    if data.version != MEMORY_VERSION:
        raise ValueError(f"unsupported memories file version {data.version}")
    return data.memories


def save_memories(path: Path, memories: list[Memory]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = MemoryFile(memories=memories).model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def add_memory(memories: list[Memory], new: Memory) -> list[Memory]:
    """Add `new`, replacing an existing memory with the same id (so re-adding is idempotent)."""
    return [m for m in memories if m.id != new.id] + [new]


def remove_memory(memories: list[Memory], memory_id: str) -> list[Memory]:
    return [m for m in memories if m.id != memory_id]


def _rule_matches(memory_rule: str, finding: Finding) -> bool:
    if not memory_rule:
        return True
    tail = finding.rule_id.rsplit(".", 1)[-1]
    if memory_rule in (finding.rule_id, tail) or finding.rule_id.endswith("." + memory_rule):
        return True
    return len(memory_rule) >= 5 and memory_rule in finding.rule_id  # a distinctive fragment


def _path_matches(pattern: str, file: str | None) -> bool:
    if not pattern:
        return True
    if not file:
        return False
    if any(ch in pattern for ch in "*?["):
        return fnmatch(file, pattern)
    prefix = pattern.rstrip("/")
    return file == prefix or file.startswith(prefix + "/")


def relevance(memory: Memory, finding: Finding) -> float:
    """0 when the memory does not apply; higher the more specific the match."""
    if not memory.enabled:
        return 0.0
    if memory.cwe and memory.cwe not in finding.cwe:
        return 0.0
    if not _rule_matches(memory.rule, finding) or not _path_matches(memory.path, finding.file):
        return 0.0
    score = 0.0
    if memory.rule:
        score += 4.0 if memory.rule in (finding.rule_id,) else 3.0
    if memory.path:
        score += 2.0 + min(len(memory.path), 60) / 60  # a deeper path is more specific
    if memory.cwe:
        score += 1.0
    return score or 0.5  # a note with no scope applies everywhere, weakly


def retrieve(memories: list[Memory], finding: Finding, limit: int = 3) -> list[Memory]:
    scored = [(relevance(m, finding), m) for m in memories]
    ranked = sorted((x for x in scored if x[0] > 0), key=lambda x: (-x[0], x[1].created, x[1].id))
    return [m for _s, m in ranked[:limit]]


def render_memory(memory: Memory) -> str:
    scope = ", ".join(
        part
        for part in (
            f"rule {memory.rule}" if memory.rule else "",
            f"under {memory.path}" if memory.path else "",
            memory.cwe,
        )
        if part
    )
    where = f" ({scope})" if scope else ""
    return f"[{memory.id}] {_KIND_WORDS[memory.kind]}{where}: {memory.text.strip()}"


def from_decision(finding: Finding, decision: str, note: str, by: str = "") -> Memory | None:
    """A memory from one reviewer decision that carries a real explanation, else None."""
    note = " ".join(note.split())
    if len(note) < MIN_NOTE_CHARS:
        return None
    kind: Kind = {
        "false_positive": "false_positive",
        "accepted_risk": "accepted_risk",
        "fixed": "confirmed",
    }.get(decision, "context")  # type: ignore[assignment]
    directory = posixpath.dirname(finding.file) if finding.file else ""
    return Memory(
        text=note[:MAX_TEXT],
        kind=kind,
        rule=finding.rule_id.rsplit(".", 1)[-1],
        path=directory,
        source=f"decision:{finding.id}" + (f" by {by}" if by else ""),
    )
