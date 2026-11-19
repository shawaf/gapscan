"""Local knowledge base: CWE, OWASP documents, ASVS/MASVS and the owner's own policies,
searchable offline with keyword + semantic retrieval, every hit carrying a citation."""

from __future__ import annotations

import logging
from pathlib import Path

from ..config import Config
from ..llm.client import LLMError
from ..store.raw import RawStore
from .embed import Embedder, OllamaEmbedder
from .index import DB_NAME, KBIndex
from .ingest import Chunk, ingest_all
from .references import cheatsheets_for

__all__ = ["KnowledgeBase", "build_kb", "load_kb"]

log = logging.getLogger(__name__)
SNIPPET_CHARS = 1300


def format_hit(c: Chunk) -> str:
    where = f" ({c.url})" if c.url else ""
    return f"[{c.citation}]{where}\n{c.text[:SNIPPET_CHARS]}"


class KnowledgeBase:
    def __init__(self, index: KBIndex, embedder: Embedder | None = None) -> None:
        self.index = index
        self.embedder = embedder

    def search_chunks(
        self, query: str, limit: int = 3, sources: set[str] | None = None
    ) -> list[Chunk]:
        """Hybrid search. A query that is exactly a document id (CWE-89, A05:2025, LLM01:2026,
        MASVS-STORAGE, ...) returns that document's chunks first, in reading order."""
        exact = [
            c for c in self.index.get_by_doc_id(query.strip()) if not sources or c.source in sources
        ]
        found = self.index.search(query, limit, embedder=self.embedder, sources=sources)
        merged = exact[:limit] + [c for c in found if c.id not in {e.id for e in exact[:limit]}]
        return merged[:limit]

    def search(self, query: str, limit: int = 3) -> list[str]:
        """Formatted hits with citations (what the agent's `search_kb` tool returns)."""
        return [format_hit(c) for c in self.search_chunks(query, limit)]

    def lookup(self, doc_id: str) -> str | None:
        """Full CWE entry (description, consequences, mitigations) for e.g. 'CWE-89'."""
        chunks = self.index.get_doc("cwe", doc_id)
        if not chunks:
            return None
        return "\n\n".join(format_hit(c) for c in chunks[:3])

    def references_for(
        self, cwes: list[str], limit: int = 2, *, dependency: bool = False
    ) -> list[str]:
        """Cheat Sheets to read, from the curated CWE map (never chosen by the model and never by
        fuzzy search); only sheets present in the built index are cited."""
        refs: list[str] = []
        for sheet in cheatsheets_for(cwes, dependency=dependency):
            chunks = self.index.get_doc("cheatsheet", sheet)
            if chunks:
                c = chunks[0]
                refs.append(f"OWASP Cheat Sheet: {c.title} ({c.url}, {c.version})")
            if len(refs) >= limit:
                break
        return refs


def kb_dir(config: Config) -> Path:
    return config.data.kb_dir


def load_kb(config: Config, *, use_embeddings: bool = True) -> KnowledgeBase | None:
    """The built knowledge base, or None when `gapscan kb build` has not been run."""
    if not (kb_dir(config) / DB_NAME).is_file():
        return None
    embedder: Embedder | None = None
    if use_embeddings:
        try:
            embedder = OllamaEmbedder(config.llm)
        except LLMError:
            embedder = None
    return KnowledgeBase(KBIndex(kb_dir(config)), embedder)


def build_kb(config: Config, *, embed: bool = True) -> KBIndex:
    """Ingest the stored sources and build the index (and embeddings, when asked)."""
    owasp = RawStore(config.data.dir / "owasp")
    mitre = RawStore(config.data.dir / "mitre")
    chunks = ingest_all(owasp, mitre, config.kb.policies_dir)
    if not chunks:
        raise RuntimeError("no sources found; run `gapscan data fetch` and `gapscan data fetch-kb`")
    sources = {e.source: e.version for s in (owasp, mitre) for e in s.manifest().entries}
    return KBIndex.build(chunks, kb_dir(config), OllamaEmbedder(config.llm) if embed else None,
                         manifest={"sources": sources})  # fmt: skip
