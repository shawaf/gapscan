"""Local hybrid index in `data/kb/`: SQLite (chunks + FTS5 keyword search) and a NumPy matrix of
normalized embeddings (cosine similarity by matrix product; a few thousand chunks need no
vector database). Search fuses both rankings with reciprocal rank fusion, so exact terms
("CWE-89") and meaning ("preventing queries built from user input") both work, and the index
still answers by keywords alone if embeddings are missing or the model server is down."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from pathlib import Path

import numpy as np
from numpy.typing import NDArray

from ..llm.client import LLMError
from .embed import Embedder
from .ingest import Chunk

log = logging.getLogger(__name__)

DB_NAME = "kb.sqlite"
VEC_NAME = "embeddings.npy"
META_NAME = "meta.json"
RRF_K = 60
CANDIDATES = 40
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_STOP = {"the", "a", "an", "of", "to", "in", "and", "or", "for", "is", "are", "how", "what", "do", "i",
         "with", "on", "by", "be", "it", "this", "that", "from", "as", "at", "can", "my"}  # fmt: skip


def fts_query(text: str) -> str:
    """A safe FTS5 query: quoted alphanumeric terms joined with OR (never raw user syntax)."""
    terms = [w.strip(".-_").lower() for w in _WORD.findall(text)]
    terms = [t for t in dict.fromkeys(terms) if t and t not in _STOP]
    return " OR ".join(f'"{t}"' for t in terms[:24])


class KBIndex:
    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self._db = sqlite3.connect(directory / DB_NAME)
        self._db.row_factory = sqlite3.Row
        self._vectors: NDArray[np.float32] | None = None
        self.meta: dict[str, object] = {}
        if (directory / META_NAME).is_file():
            self.meta = json.loads((directory / META_NAME).read_text(encoding="utf-8"))
        if (directory / VEC_NAME).is_file():
            self._vectors = np.load(directory / VEC_NAME)

    # --- build ----------------------------------------------------------------------

    @staticmethod
    def build(chunks: list[Chunk], directory: Path, embedder: Embedder | None = None,
              manifest: dict[str, object] | None = None) -> KBIndex:  # fmt: skip
        directory.mkdir(parents=True, exist_ok=True)
        for name in (DB_NAME, VEC_NAME, META_NAME):
            (directory / name).unlink(missing_ok=True)
        db = sqlite3.connect(directory / DB_NAME)
        db.executescript(
            """
            CREATE TABLE chunks (n INTEGER PRIMARY KEY, id TEXT UNIQUE, source TEXT, doc_id TEXT,
                title TEXT, heading TEXT, text TEXT, url TEXT, version TEXT, license TEXT);
            CREATE INDEX chunks_doc ON chunks(source, doc_id);
            CREATE VIRTUAL TABLE chunks_fts USING fts5(text, title, heading, doc_id,
                content='chunks', content_rowid='n', tokenize='unicode61 remove_diacritics 2');
            """
        )
        for i, c in enumerate(chunks):
            db.execute("INSERT INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (i, c.id, c.source, c.doc_id, c.title, c.heading, c.text, c.url, c.version, c.license))  # fmt: skip
        db.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')")
        db.commit()
        db.close()
        meta: dict[str, object] = {
            "chunks": len(chunks),
            "embedding_model": None,
            **(manifest or {}),
        }
        if embedder is not None:
            texts = [f"{c.title}\n{c.heading}\n{c.text}" for c in chunks]
            vectors = embedder.embed(texts, "document")
            np.save(directory / VEC_NAME, vectors)
            meta.update(embedding_model=embedder.model, embedding_dim=int(vectors.shape[1]))
        (directory / META_NAME).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return KBIndex(directory)

    # --- query ----------------------------------------------------------------------

    def _row_to_chunk(self, r: sqlite3.Row) -> Chunk:
        return Chunk(id=r["id"], source=r["source"], doc_id=r["doc_id"], title=r["title"],
                     heading=r["heading"], text=r["text"], url=r["url"], version=r["version"],
                     license=r["license"])  # fmt: skip

    def _keyword(self, query: str, sources: set[str] | None) -> list[int]:
        q = fts_query(query)
        if not q:
            return []
        rows = self._db.execute(
            "SELECT c.n, c.source FROM chunks_fts f JOIN chunks c ON c.n = f.rowid "
            "WHERE chunks_fts MATCH ? ORDER BY bm25(chunks_fts, 1.0, 6.0, 2.0, 8.0) LIMIT ?",
            (q, CANDIDATES * 3),
        ).fetchall()
        return [r["n"] for r in rows if not sources or r["source"] in sources][:CANDIDATES]

    def _semantic(
        self, query: str, embedder: Embedder | None, sources: set[str] | None
    ) -> list[int]:
        if self._vectors is None or embedder is None:
            return []
        if self.meta.get("embedding_model") != embedder.model:
            log.warning("KB was built with %s but %s is configured; using keyword search only",
                        self.meta.get("embedding_model"), embedder.model)  # fmt: skip
            return []
        try:
            qv = embedder.embed([query], "query")[0]
        except LLMError as exc:
            log.warning("embedding unavailable (%s); using keyword search only", exc)
            return []
        scores = self._vectors @ qv
        order = np.argsort(-scores)
        if sources:
            allowed = {r["n"] for r in self._db.execute(
                f"SELECT n FROM chunks WHERE source IN ({','.join('?' * len(sources))})", tuple(sources))}  # fmt: skip
            return [int(i) for i in order if int(i) in allowed][:CANDIDATES]
        return [int(i) for i in order[:CANDIDATES]]

    def search(self, query: str, limit: int = 3, *, embedder: Embedder | None = None,
               sources: set[str] | None = None) -> list[Chunk]:  # fmt: skip
        """Top chunks by reciprocal rank fusion of keyword and semantic rankings."""
        fused: dict[int, float] = {}
        for ranking in (self._keyword(query, sources), self._semantic(query, embedder, sources)):
            for rank, n in enumerate(ranking):
                fused[n] = fused.get(n, 0.0) + 1.0 / (RRF_K + rank + 1)
        best = sorted(fused, key=lambda n: -fused[n])[:limit]
        if not best:
            return []
        marks = ",".join("?" * len(best))
        rows = {
            r["n"]: r for r in self._db.execute(f"SELECT * FROM chunks WHERE n IN ({marks})", best)
        }
        return [self._row_to_chunk(rows[n]) for n in best]

    def get_doc(self, source: str, doc_id: str) -> list[Chunk]:
        rows = self._db.execute("SELECT * FROM chunks WHERE source = ? AND doc_id = ? ORDER BY n",
                                (source, doc_id)).fetchall()  # fmt: skip
        return [self._row_to_chunk(r) for r in rows]

    def get_by_doc_id(self, doc_id: str) -> list[Chunk]:
        """Chunks of any source whose document id equals `doc_id` (case-insensitive)."""
        rows = self._db.execute("SELECT * FROM chunks WHERE doc_id = ? COLLATE NOCASE ORDER BY n",
                                (doc_id,)).fetchall()  # fmt: skip
        return [self._row_to_chunk(r) for r in rows]

    def stats(self) -> dict[str, object]:
        by_source = {r["source"]: r["c"] for r in self._db.execute(
            "SELECT source, COUNT(*) c FROM chunks GROUP BY source")}  # fmt: skip
        return {"chunks": sum(by_source.values()), "by_source": by_source, **self.meta}

    def close(self) -> None:
        self._db.close()
