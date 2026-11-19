"""Find a model Ollama already stored, so the setup wizard can reuse it instead of downloading it again.

Ollama keeps each model as a plain GGUF file (a "blob" named after its sha256) plus a small manifest. The
engine can load that file directly. This module only reads: it never writes to, moves or deletes anything in
Ollama's folder, and it does not start or contact Ollama."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MODEL_LAYER = "application/vnd.ollama.image.model"
MIN_BYTES = 50_000_000  # anything smaller is not a language model


def models_dir() -> Path:
    env = os.environ.get("OLLAMA_MODELS")
    return Path(env).expanduser() if env else Path.home() / ".ollama" / "models"


def find_model(alias: str, root: Path | None = None) -> Path | None:
    """The GGUF file of an Ollama model named like `qwen3-coder:30b`, or None when it is not there or
    does not look like a model file (wrong size, not GGUF)."""
    root = root or models_dir()
    name, _, tag = alias.partition(":")
    parts = name.split("/") if "/" in name else ["library", name]
    if not tag or any(p in ("", ".", "..") for p in [*parts, tag]):
        return None
    manifest = root.joinpath("manifests", "registry.ollama.ai", *parts, tag)
    try:
        layers = json.loads(manifest.read_text(encoding="utf-8")).get("layers", [])
    except (OSError, ValueError, AttributeError):
        return None
    for layer in layers:
        if not isinstance(layer, dict) or layer.get("mediaType") != MODEL_LAYER:
            continue
        digest = str(layer.get("digest", ""))
        if not DIGEST.match(digest):
            return None
        blob = root / "blobs" / digest.replace(":", "-")
        try:
            if blob.stat().st_size != layer.get("size") or blob.stat().st_size < MIN_BYTES:
                return None
            with blob.open("rb") as fh:
                return blob if fh.read(4) == b"GGUF" else None
        except OSError:
            return None
    return None
