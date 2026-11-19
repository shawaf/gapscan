"""One small database layer for SQLite (default, single node) and PostgreSQL (teams), shared by the
local app (`server/db.py`).

SQL is written once with `?` placeholders and plain types, which both engines accept; the layer
only swaps the placeholder style and the row factory. PostgreSQL needs the optional `psycopg`
package (`pip install 'gapscan[server]'`); it is imported only when a PostgreSQL URL is used.

    sqlite:///path/to/gapscan.db
    postgresql://user:password@host:5432/gapscan

Each schema brings its own ordered migrations. A step is an SQL statement or a function of the
connection (for changes plain SQL cannot express on SQLite, such as adding a column only when an
older database lacks it). The `schema_version` row says how far a database has got.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

VERSION_TABLE = "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
PG_POOL = 20  # at most this many connections to PostgreSQL at once


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id() -> str:
    return uuid.uuid4().hex


def event_id() -> str:
    """Sorts in creation order even within one second, so a history reads correctly."""
    return f"{time.time_ns():019d}{uuid.uuid4().hex[:8]}"


class Conn:
    """A connection plus the verbs the rest of the code uses."""

    def __init__(self, raw: Any, postgres: bool) -> None:
        self.raw, self.pg = raw, postgres

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.pg else sql

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        cur = self.raw.execute(self._sql(sql), params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def run(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        """Execute; the number of rows changed."""
        cur = self.raw.execute(self._sql(sql), params)
        return int(cur.rowcount)

    def insert(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        """Execute an INSERT into a table with an integer `id`; the new row's id."""
        if self.pg:
            row = self.raw.execute(self._sql(sql) + " RETURNING id", params).fetchone()
            return int(row["id"])
        return int(self.raw.execute(sql, params).lastrowid or 0)


class _ForeignKeysOff:
    """Migration step marker: run this migration with SQLite foreign keys off (SQLite's documented
    way to rebuild a table others reference), then refuse to commit if `foreign_key_check` finds
    any broken reference. No effect on PostgreSQL, whose constraints can be changed in place."""


FOREIGN_KEYS_OFF = _ForeignKeysOff()
Step = str | Callable[[Conn], None] | _ForeignKeysOff
Migrations = Sequence[tuple[int, Sequence[Step]]]


class Database:
    """Opens a connection per transaction: `with db.conn() as c:` commits on success and rolls
    back on any error. SQLite writes are serialized by a lock; PostgreSQL uses a bounded pool."""

    def __init__(self, url: str, migrations: Migrations) -> None:
        self.url = url
        self.migrations = migrations
        self.pg = url.startswith(("postgresql://", "postgres://"))
        self._lock = threading.Lock()  # SQLite allows one writer at a time
        self._tenant = threading.local()  # the workspace this thread works for, if any
        self._pg_slots = threading.BoundedSemaphore(PG_POOL)
        if self.pg:
            try:
                import psycopg  # noqa: F401
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL needs the psycopg package: pip install 'gapscan[server]'"
                ) from exc
        elif url.startswith("sqlite:///"):
            self.path = Path(url.removeprefix("sqlite:///"))
            self.path.parent.mkdir(parents=True, exist_ok=True)
        else:
            raise ValueError("database URL must start with sqlite:/// or postgresql://")
        self.migrate()

    @contextmanager
    def tenant(self, workspace: str) -> Iterator[None]:
        """Work for one workspace in this thread: on PostgreSQL every connection opened inside
        sets `gapscan.workspace`, which row-level security policies confine rows to (the second
        wall behind the application's own filters). SQLite has no row-level security."""
        previous = getattr(self._tenant, "ws", None)
        self._tenant.ws = workspace
        try:
            yield
        finally:
            self._tenant.ws = previous

    @contextmanager
    def conn(self, *, foreign_keys: bool = True) -> Iterator[Conn]:
        if self.pg:
            import psycopg
            from psycopg.rows import dict_row

            if not self._pg_slots.acquire(timeout=30):
                raise RuntimeError("database busy: no free connection slot")
            try:
                raw = psycopg.connect(self.url, row_factory=dict_row, connect_timeout=10)
                try:
                    ws = getattr(self._tenant, "ws", None)
                    if ws is not None:  # transaction-local: it ends with this connection's work
                        raw.execute("SELECT set_config('gapscan.workspace', %s, true)", (ws,))
                    yield Conn(raw, True)
                    raw.commit()
                except BaseException:
                    raw.rollback()
                    raise
                finally:
                    raw.close()
            finally:
                self._pg_slots.release()
            return
        with self._lock:
            # Explicit transactions: Python's sqlite3 otherwise commits DDL (CREATE, ALTER) at
            # once, so a migration that fails halfway would leave a half-changed schema behind.
            lite = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            lite.row_factory = sqlite3.Row
            # A no-op inside a transaction: set it first.
            lite.execute(f"PRAGMA foreign_keys = {'ON' if foreign_keys else 'OFF'}")
            lite.execute("BEGIN")
            try:
                yield Conn(lite, False)
                lite.execute("COMMIT")
            except BaseException:
                lite.execute("ROLLBACK")
                raise
            finally:
                lite.close()

    def version(self) -> int:
        with self.conn() as c:
            c.run(VERSION_TABLE)
            row = c.one("SELECT MAX(version) AS v FROM schema_version")
        return int(row["v"]) if row and row["v"] is not None else 0

    def migrate(self) -> None:
        """Run each migration newer than the database, in order, each in its own transaction."""
        current = self.version()
        for version, steps in self.migrations:
            if version <= current:
                continue
            fk_off = any(isinstance(step, _ForeignKeysOff) for step in steps)
            with self.conn(foreign_keys=not fk_off) as c:
                for step in steps:
                    if isinstance(step, str):
                        c.run(step)
                    elif not isinstance(step, _ForeignKeysOff):
                        step(c)
                if fk_off and not c.pg and c.query("PRAGMA foreign_key_check"):
                    raise RuntimeError(f"migration {version} broke a foreign key reference")
                c.run("DELETE FROM schema_version")
                c.run("INSERT INTO schema_version (version) VALUES (?)", (version,))

    def bypasses_row_security(self) -> bool:
        """True when the connected PostgreSQL role ignores row-level security (a superuser or a
        role with BYPASSRLS, such as a hosted service-role key). Always False on SQLite."""
        if not self.pg:
            return False
        with self.conn() as c:
            row = c.one("SELECT rolsuper OR rolbypassrls AS bypass FROM pg_roles "
                        "WHERE rolname = current_user")  # fmt: skip
        return bool(row and row["bypass"])

    def ping(self) -> bool:
        try:
            with self.conn() as c:
                c.one("SELECT 1 AS ok")
            return True
        except Exception:  # noqa: BLE001 - health check: any failure means not ready
            return False
