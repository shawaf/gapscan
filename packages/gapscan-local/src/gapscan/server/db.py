"""SQLite storage for the management UI: projects, scan runs, reviewer decisions and settings.

Scan artifacts (findings, verdicts, the report) live as files under data/runs/<scan id>/; the database
holds the index and the history. It runs on the shared SQL layer (`gapscan/store/sql.py`) with its
own versioned migrations. Ids are integers, so this schema is SQLite-only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..registry import (
    capability_catalogue,
    resolve_capabilities,
    scanners_for_capabilities,
    selectable_scanners,
)
from ..store.sql import Conn, Migrations, Step, now
from ..store.sql import Database as SqlDatabase

__all__ = ["ACTIVE", "MAX_LOG", "MIGRATIONS", "TABLES", "Database", "now"]

# A project enables a service per domain (ARCHITECTURE.md: Project -> Service (domain) ->
# Capability). Security is the first and, for now, only domain in local mode too.
DEFAULT_DOMAIN = "security"

TABLES: list[Step] = [
    """CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
    archived INTEGER NOT NULL DEFAULT 0
)""",
    """CREATE TABLE IF NOT EXISTS benchmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, model TEXT NOT NULL, status TEXT NOT NULL, phase TEXT NOT NULL DEFAULT 'queued',
    progress_done INTEGER NOT NULL DEFAULT 0, progress_total INTEGER NOT NULL DEFAULT 0, summary TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT
)""",
    """CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT 'scan',
    status TEXT NOT NULL, phase TEXT NOT NULL DEFAULT 'queued', options TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, error TEXT NOT NULL DEFAULT '',
    progress_done INTEGER NOT NULL DEFAULT 0, progress_total INTEGER NOT NULL DEFAULT 0, stats TEXT NOT NULL DEFAULT '{}',
    findings INTEGER, open_findings INTEGER, score REAL, grade TEXT, model TEXT, log TEXT NOT NULL DEFAULT ''
)""",
    """CREATE TABLE IF NOT EXISTS decisions (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL, decision TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', date TEXT NOT NULL,
    PRIMARY KEY (project_id, finding_id)
)""",
    """CREATE TABLE IF NOT EXISTS memories (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (project_id, id)
)""",
    "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
]
ACTIVE = ("queued", "running")
MAX_LOG = 20_000


def _columns(c: Conn, table: str) -> set[str]:
    return {r["name"] for r in c.query(f"PRAGMA table_info({table})")}


def _legacy_columns(c: Conn) -> None:
    """Databases from before versioned migrations may lack columns added since."""
    scans, projects = _columns(c, "scans"), _columns(c, "projects")
    if "stats" not in scans:  # created before live run statistics existed
        c.run("ALTER TABLE scans ADD COLUMN stats TEXT NOT NULL DEFAULT '{}'")
    if "archived" not in projects:  # created before projects could be archived
        c.run("ALTER TABLE projects ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
    if "started_by" not in scans:  # created before runs recorded who started them
        c.run("ALTER TABLE scans ADD COLUMN started_by TEXT NOT NULL DEFAULT ''")


def _scan_git_columns(c: Conn) -> None:
    """The branch and commit the working tree was on when the scan ran (read from git, never
    changed by GapScan). Empty for folders that are not git repositories."""
    scans = _columns(c, "scans")
    if "branch" not in scans:
        c.run("ALTER TABLE scans ADD COLUMN branch TEXT NOT NULL DEFAULT ''")
    if "commit_sha" not in scans:
        c.run("ALTER TABLE scans ADD COLUMN commit_sha TEXT NOT NULL DEFAULT ''")


def _services(c: Conn) -> None:
    """Services (domains) enabled per project, with capability toggles in `config`
    (ARCHITECTURE.md: Project -> Service (domain) -> Capability). Existing projects get the
    Security service, every capability on (empty config)."""
    c.run("""CREATE TABLE IF NOT EXISTS services (
        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        domain TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        config TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
        PRIMARY KEY (project_id, domain))""")
    c.run(
        "INSERT INTO services (project_id, domain, enabled, config, created_at) "
        "SELECT id, ?, 1, '{}', ? FROM projects",
        (DEFAULT_DOMAIN, now()),
    )


# Each migration runs once, in order; never edit a released one, add a new one. Migration 1 is the
# schema as it was before versioning, so existing databases (version 0) upgrade in place.
MIGRATIONS: Migrations = [
    (1, [*TABLES, _legacy_columns]),
    (2, [_scan_git_columns]),
    (3, [_services]),
]


class Database:
    def __init__(self, path: Path) -> None:
        self._sql = SqlDatabase(f"sqlite:///{path}", MIGRATIONS)
        # A restart interrupts whatever was running: say so instead of showing a job that never ends.
        self.execute(
            "UPDATE scans SET status='interrupted', finished_at=? WHERE status IN ('queued','running')",
            (now(),),
        )
        self.execute(
            "UPDATE benchmarks SET status='interrupted', finished_at=? WHERE status IN ('queued','running')",
            (now(),),
        )

    def execute(self, sql: str, args: tuple[Any, ...] = ()) -> int:
        """Run one statement in its own transaction; the number of rows changed."""
        with self._sql.conn() as c:
            return c.run(sql, args)

    def insert(self, sql: str, args: tuple[Any, ...] = ()) -> int:
        with self._sql.conn() as c:
            return c.insert(sql, args)

    def query(self, sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._sql.conn() as c:
            return c.query(sql, args)

    def one(self, sql: str, args: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, args)
        return rows[0] if rows else None

    # --- projects -------------------------------------------------------------------------

    def add_project(self, name: str, path: str) -> dict[str, Any]:
        new = self.insert(
            "INSERT INTO projects (name, path, created_at) VALUES (?,?,?)", (name, path, now())
        )
        # Every new project gets the Security service, all capabilities on (empty config).
        self.execute(
            "INSERT INTO services (project_id, domain, enabled, config, created_at) VALUES (?,?,1,'{}',?)",
            (new, DEFAULT_DOMAIN, now()),
        )
        return self.project(new) or {}

    def project(self, project_id: int) -> dict[str, Any] | None:
        row = self.one("SELECT * FROM projects WHERE id = ?", (project_id,))
        if row:
            row["archived"] = bool(row["archived"])
        return row

    def projects(self) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM projects ORDER BY name COLLATE NOCASE")
        for r in rows:
            r["archived"] = bool(r["archived"])
        return rows

    def project_summary(self, p: dict[str, Any]) -> dict[str, Any]:
        """A project with its latest run, latest finished run and score history (last 12)."""
        scans = self.query(
            "SELECT id, status, score, grade, open_findings, findings, finished_at FROM scans "
            "WHERE project_id = ? AND kind = 'scan' ORDER BY id DESC LIMIT 30",
            (p["id"],),
        )
        done = [s for s in scans if s["status"] == "done"]
        return {**p, "latest": scans[0] if scans else None, "latest_done": done[0] if done else None,
                "history": [{"id": s["id"], "score": s["score"], "at": s["finished_at"]}
                            for s in reversed(done)][-12:],
                "active": any(s["status"] in ACTIVE for s in scans)}  # fmt: skip

    def set_archived(self, project_id: int, archived: bool) -> None:
        self.execute("UPDATE projects SET archived = ? WHERE id = ?", (int(archived), project_id))

    def delete_project(self, project_id: int) -> None:
        self.execute("DELETE FROM projects WHERE id = ?", (project_id,))

    # --- scans ----------------------------------------------------------------------------

    def create_scan(
        self, project_id: int, options: dict[str, Any], kind: str = "scan", started_by: str = ""
    ) -> int:
        return self.insert(
            "INSERT INTO scans (project_id, kind, status, options, created_at, started_by) VALUES (?,?,?,?,?,?)",
            (project_id, kind, "queued", json.dumps(options), now(), started_by),
        )

    def scan(self, scan_id: int) -> dict[str, Any] | None:
        row = self.one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        if row:
            row["options"] = json.loads(row["options"] or "{}")
            row["stats"] = json.loads(row.get("stats") or "{}")
        return row

    def scans(self, project_id: int, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT * FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT ?", (project_id, limit)
        )
        for r in rows:
            r["options"] = json.loads(r["options"] or "{}")
            r["stats"] = json.loads(r.get("stats") or "{}")
            r.pop("log", None)  # logs are fetched per scan
        return rows

    def update_scan(self, scan_id: int, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.execute(f"UPDATE scans SET {cols} WHERE id = ?", (*fields.values(), scan_id))  # noqa: S608 - column names are ours

    def append_log(self, scan_id: int, line: str) -> None:
        row = self.one("SELECT log FROM scans WHERE id = ?", (scan_id,))
        if row is None:
            return
        text = (row["log"] + line.rstrip("\n") + "\n")[-MAX_LOG:]
        self.execute("UPDATE scans SET log = ? WHERE id = ?", (text, scan_id))

    def latest_done(self, project_id: int, before: int | None = None) -> dict[str, Any] | None:
        sql = "SELECT * FROM scans WHERE project_id = ? AND status = 'done' AND kind = 'scan'"
        args: tuple[Any, ...] = (project_id,)
        if before is not None:
            sql += " AND id < ?"
            args = (project_id, before)
        return self.one(sql + " ORDER BY id DESC LIMIT 1", args)

    def queue(self) -> list[dict[str, Any]]:
        """Running and waiting runs of every project, oldest first (the run list of the top bar)."""
        rows = self.query(
            "SELECT s.id, s.project_id, s.kind, s.status, s.phase, s.options, s.progress_done, s.progress_total, "
            "s.created_at, s.started_at, s.stats, p.name AS project FROM scans s "
            "JOIN projects p ON p.id = s.project_id WHERE s.status IN ('queued','running') ORDER BY s.id"
        )
        for r in rows:
            r["options"] = json.loads(r["options"] or "{}")
            r["stats"] = json.loads(r.get("stats") or "{}")
        return rows

    def benchmark_queue(self) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT * FROM benchmarks WHERE status IN ('queued','running') ORDER BY id"
        )
        for r in rows:
            r["summary"] = json.loads(r["summary"] or "{}")
        return rows

    def delete_scan(self, scan_id: int) -> None:
        self.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    # --- model benchmarks -----------------------------------------------------------------

    def create_benchmark(self, model: str) -> int:
        return self.insert(
            "INSERT INTO benchmarks (model, status, created_at) VALUES (?,?,?)",
            (model, "queued", now()),
        )

    def benchmark(self, bench_id: int) -> dict[str, Any] | None:
        row = self.one("SELECT * FROM benchmarks WHERE id = ?", (bench_id,))
        if row:
            row["summary"] = json.loads(row["summary"] or "{}")
        return row

    def update_benchmark(self, bench_id: int, **fields: Any) -> None:
        if fields:
            cols = ", ".join(f"{k} = ?" for k in fields)
            self.execute(f"UPDATE benchmarks SET {cols} WHERE id = ?", (*fields.values(), bench_id))  # noqa: S608 - column names are ours

    def latest_benchmarks(self) -> dict[str, dict[str, Any]]:
        """Per model: the benchmark waiting or running now, else the newest finished one, else the newest."""
        active: dict[str, dict[str, Any]] = {}
        finished: dict[str, dict[str, Any]] = {}
        newest: dict[str, dict[str, Any]] = {}
        for r in self.query("SELECT id FROM benchmarks ORDER BY id"):
            row = self.benchmark(r["id"])
            if row is None:
                continue
            newest[row["model"]] = row
            if row["status"] in ("queued", "running"):
                active[row["model"]] = row
            elif row["status"] == "done":
                finished[row["model"]] = row
        return {m: active.get(m) or finished.get(m) or newest[m] for m in newest}

    # --- team memories --------------------------------------------------------------------

    def memories(self, project_id: int) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT data FROM memories WHERE project_id = ? ORDER BY rowid", (project_id,)
        )
        return [json.loads(r["data"]) for r in rows]

    def save_memory(self, project_id: int, memory: dict[str, Any]) -> None:
        self.execute(
            "INSERT INTO memories (project_id, id, data) VALUES (?,?,?) "
            "ON CONFLICT(project_id, id) DO UPDATE SET data = excluded.data",
            (project_id, memory["id"], json.dumps(memory)),
        )

    def delete_memory(self, project_id: int, memory_id: str) -> bool:
        changed = self.execute(
            "DELETE FROM memories WHERE project_id = ? AND id = ?", (project_id, memory_id)
        )
        return changed > 0

    # --- decisions ------------------------------------------------------------------------

    def decisions(self, project_id: int) -> list[dict[str, Any]]:
        return self.query(
            "SELECT finding_id, decision, note, date FROM decisions WHERE project_id = ? ORDER BY finding_id",
            (project_id,),
        )

    def set_decision(self, project_id: int, finding_id: str, decision: str, note: str) -> None:
        self.execute(
            "INSERT INTO decisions (project_id, finding_id, decision, note, date) VALUES (?,?,?,?,?) "
            "ON CONFLICT(project_id, finding_id) DO UPDATE SET decision=excluded.decision, note=excluded.note, date=excluded.date",
            (project_id, finding_id, decision, note, now()[:10]),
        )

    def clear_decision(self, project_id: int, finding_id: str) -> None:
        self.execute(
            "DELETE FROM decisions WHERE project_id = ? AND finding_id = ?",
            (project_id, finding_id),
        )

    # --- settings -------------------------------------------------------------------------

    def settings(self) -> dict[str, Any]:
        return {
            r["key"]: json.loads(r["value"]) for r in self.query("SELECT key, value FROM settings")
        }

    def set_setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )

    # --- services (domains and their capabilities) ----------------------------------------

    def services(self, project_id: int) -> list[dict[str, Any]]:
        """The project's services (one per domain), each with its enabled capabilities and the
        full capability catalogue of that domain, so the UI can draw the toggles."""
        rows = self.query(
            "SELECT domain, enabled, config FROM services WHERE project_id = ? ORDER BY domain",
            (project_id,),
        )
        catalogue = capability_catalogue()
        out = []
        for r in rows:
            config = json.loads(r["config"] or "{}")
            out.append({
                "domain": r["domain"],
                "label": r["domain"].title(),
                "enabled": bool(r["enabled"]),
                "capabilities": {
                    "enabled": resolve_capabilities(r["domain"], config),
                    "available": [c for c in catalogue if c["domain"] == r["domain"]],
                },
            })  # fmt: skip
        return out

    def set_service(
        self, project_id: int, domain: str, *,
        enabled: bool | None = None, capabilities: list[str] | None = None,
    ) -> dict[str, Any] | None:  # fmt: skip
        """Enable/disable a service or set which capabilities run. Unknown/reserved capability ids
        are refused by the caller (the API validates against the catalogue)."""
        row = self.one(
            "SELECT config FROM services WHERE project_id = ? AND domain = ?", (project_id, domain)
        )
        if row is None:
            return None
        config = json.loads(row["config"] or "{}")
        sets: list[str] = []
        params: list[Any] = []
        if enabled is not None:
            sets.append("enabled = ?")
            params.append(int(enabled))
        if capabilities is not None:
            config["capabilities"] = sorted(set(capabilities))
            sets.append("config = ?")
            params.append(json.dumps(config))
        if sets:
            self.execute(
                f"UPDATE services SET {', '.join(sets)} WHERE project_id = ? AND domain = ?",  # noqa: S608 - column names are ours
                (*params, project_id, domain),
            )
        return next((s for s in self.services(project_id) if s["domain"] == domain), None)

    def project_scanners(self, project_id: int) -> list[str] | None:
        """The selectable scanners a project's enabled, non-reserved capabilities turn on (its
        Security service), to use as the picker default for its scans. None when the service is
        disabled or absent, so the caller falls back to the global default. Background scanners
        (taint, malware) are not in the picker and follow the base config via `effective_config`."""
        row = self.one(
            "SELECT enabled, config FROM services WHERE project_id = ? AND domain = ?",
            (project_id, DEFAULT_DOMAIN),
        )
        if row is None or not row["enabled"]:
            return None
        caps = resolve_capabilities(DEFAULT_DOMAIN, json.loads(row["config"] or "{}"))
        picked = set(scanners_for_capabilities(caps))
        return [s for s in selectable_scanners() if s in picked]
