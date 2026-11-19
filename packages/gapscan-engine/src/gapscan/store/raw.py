"""Raw data store: files are saved byte-for-byte as received, with a manifest that records
where each came from. Nothing here modifies a downloaded file, so the original value can
always be shown and its integrity re-verified.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field


class RawEntry(BaseModel):
    path: str  # relative to the store root, POSIX style
    url: str
    sha256: str
    bytes: int
    retrieved_at: str
    source: str  # e.g. "owasp-top10"
    version: str  # release tag, commit SHA or edition
    license: str = ""


class Manifest(BaseModel):
    entries: list[RawEntry] = Field(default_factory=list)


class RawStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.manifest_path = root / "manifest.json"

    def manifest(self) -> Manifest:
        if not self.manifest_path.is_file():
            return Manifest()
        return Manifest.model_validate_json(self.manifest_path.read_text(encoding="utf-8"))

    def save(self, rel_path: str, content: bytes, *, url: str, source: str, version: str,
             license: str = "") -> RawEntry:  # fmt: skip
        dest = self.resolve(rel_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
        entry = RawEntry(
            path=rel_path,
            url=url,
            sha256=hashlib.sha256(content).hexdigest(),
            bytes=len(content),
            retrieved_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            source=source,
            version=version,
            license=license,
        )
        m = self.manifest()
        m.entries = [e for e in m.entries if e.path != rel_path] + [entry]
        m.entries.sort(key=lambda e: e.path)
        self.root.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(m.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return entry

    def resolve(self, rel_path: str) -> Path:
        """Map a manifest path to a file, refusing anything outside the store."""
        p = (self.root / rel_path).resolve()
        if not p.is_relative_to(self.root.resolve()):
            raise ValueError(f"path escapes the store: {rel_path}")
        return p

    def read_raw(self, rel_path: str) -> bytes:
        return self.resolve(rel_path).read_bytes()

    def verify(self) -> list[str]:
        """Return a problem description per missing or modified file (empty = all intact)."""
        problems = []
        for e in self.manifest().entries:
            p = self.resolve(e.path)
            if not p.is_file():
                problems.append(f"missing: {e.path}")
            elif hashlib.sha256(p.read_bytes()).hexdigest() != e.sha256:
                problems.append(f"modified: {e.path}")
        return problems
