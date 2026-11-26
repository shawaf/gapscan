"""Embeddings from the local model server (Ollama or llama-server; localhost/internal only, like the chat client)."""

from __future__ import annotations

import logging
from typing import Literal, Protocol

import httpx
import numpy as np
from numpy.typing import NDArray

from ..config import LLMConfig
from ..llm.client import LLMError, assert_local_endpoint, openai_url

log = logging.getLogger(__name__)

# nomic-embed-text was trained with task prefixes; other models use none.
_PREFIXES = {"nomic-embed-text": {"document": "search_document: ", "query": "search_query: "}}
BATCH = 32
MAX_CHARS = 4000


class Embedder(Protocol):
    model: str

    def embed(
        self, texts: list[str], kind: Literal["document", "query"]
    ) -> NDArray[np.float32]: ...


class OllamaEmbedder:
    def __init__(self, cfg: LLMConfig, http: httpx.Client | None = None) -> None:
        endpoint = cfg.embedding_endpoint or cfg.endpoint
        assert_local_endpoint(endpoint, cfg.internal_hosts)
        self.model = cfg.embedding_model
        self.openai = cfg.backend != "ollama"  # llama-server speaks the OpenAI-style API
        self.endpoint = endpoint.rstrip("/")
        self._http = http or httpx.Client(timeout=cfg.timeout_s)
        self._prefix = _PREFIXES.get(self.model.split(":")[0], {})

    def embed(self, texts: list[str], kind: Literal["document", "query"]) -> NDArray[np.float32]:
        prefix = self._prefix.get(kind, "")
        vectors: list[list[float]] = []
        for i in range(0, len(texts), BATCH):
            batch = [prefix + t[:MAX_CHARS] for t in texts[i : i + BATCH]]
            try:
                url = (
                    openai_url(self.endpoint, "embeddings")
                    if self.openai
                    else f"{self.endpoint}/api/embed"
                )
                r = self._http.post(url, json={"model": self.model, "input": batch})
                if r.status_code >= 400:
                    raise httpx.HTTPError(f"{r.status_code}: {r.text[:200]}")
                body = r.json()
                got = (
                    [d["embedding"] for d in sorted(body["data"], key=lambda d: d["index"])]
                    if self.openai
                    else body["embeddings"]
                )
            except (httpx.HTTPError, KeyError, ValueError) as exc:
                raise LLMError(f"embedding request failed for {self.model!r}: {exc}") from exc
            if len(got) != len(batch):
                raise LLMError("embedding server returned the wrong number of vectors")
            vectors += got
        arr = np.asarray(vectors, dtype=np.float32)
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        return np.asarray(arr / np.maximum(norms, 1e-12), dtype=np.float32)
