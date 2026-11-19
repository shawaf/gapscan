"""Response cache so reruns are fast. Keyed by prompt version, model, sampling options and
the exact messages (which embed the finding and its code context), hashed together.

Only validated results are stored, and only the answer JSON: neither prompts nor scanned code
are written to the cache (hard rule: never persist secrets or full prompts)."""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def cache_key(prompt_version: str, model: str, options: dict[str, Any],
              messages: list[dict[str, str]]) -> str:  # fmt: skip
    blob = json.dumps(
        [prompt_version, model, options, messages], sort_keys=True, ensure_ascii=False
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ResponseCache:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS responses (key TEXT PRIMARY KEY, model TEXT NOT NULL,"
            " prompt_version TEXT NOT NULL, value TEXT NOT NULL,"
            " created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        self._db.commit()

    # The cache only saves time: a locked, read-only or replaced database file must never cost a
    # finished model answer, so read and write failures are logged and the run goes on.
    def get(self, key: str) -> str | None:
        try:
            row = self._db.execute("SELECT value FROM responses WHERE key = ?", (key,)).fetchone()
        except sqlite3.Error as exc:
            log.warning("LLM cache read failed (%s); asking the model", exc)
            return None
        return str(row[0]) if row else None

    def put(self, key: str, model: str, prompt_version: str, value: str) -> None:
        try:
            self._db.execute(
                "INSERT OR REPLACE INTO responses (key, model, prompt_version, value)"
                " VALUES (?,?,?,?)",
                (key, model, prompt_version, value),
            )
            self._db.commit()
        except sqlite3.Error as exc:
            log.warning("LLM cache write failed (%s); the answer is kept, only not cached", exc)

    def clear(self, model: str | None = None) -> int:
        cur = self._db.execute("DELETE FROM responses WHERE ? IS NULL OR model = ?", (model, model))
        self._db.commit()
        return cur.rowcount

    def __len__(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM responses").fetchone()[0])

    def close(self) -> None:
        self._db.close()
