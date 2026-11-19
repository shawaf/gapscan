"""The management server: a small JSON API plus the single-file manager UI, on loopback only.

Built on the standard library (no web framework) to keep the attack surface and the dependencies
small. Every request passes `security` (Host, session token, same-origin JSON for writes) before a
route runs. The server only ever scans folders that were registered as projects, and never executes
anything from them."""

from __future__ import annotations

import contextlib
import getpass
import json
import logging
import re
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..compliance.catalog import catalog_payload
from ..config import Config
from ..core.version import __version__
from ..diffscan import branches as git_branches
from ..diffscan import head_info as git_head
from ..doctor import run_all_checks
from ..llm.client import LLMClient, LLMError
from ..memory import MIN_NOTE_CHARS, Memory, from_decision
from ..models import ScanResult
from ..offline.bundle import STATE_FILE
from ..paths import app_dir
from ..registry import capability_catalogue, scanner_status, selectable_scanners
from ..runtime.manager import RuntimeManager, first_run_plan
from ..services import (
    InvalidInput,
    Missing,
    NotReady,
    check_finding_id,
    check_project_folder,
    compare_runs,
    finding_history,
    list_directory,
    run_options,
    run_settings,
    settings_update,
)
from . import health, security, tasks
from . import setup as setup_steps
from .db import ACTIVE, Database
from .jobs import JobRunner
from .sample import NAME as SAMPLE_NAME
from .sample import ensure_sample
from .tasks import Task
from .workspace import Workspace, check_url

log = logging.getLogger(__name__)
TEMPLATE = Path(__file__).parent / "templates" / "manager.html"
EXPORT_NAMES = {
    "report.sarif",
    "report-findings.csv",
    "report-asvs.csv",
    "report-summary.md",
    "report.json",
    "report.cdx.json",
}
DECISIONS = {"accepted_risk", "false_positive", "fixed"}


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status, self.message = status, message


class GapScanServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config: Config, db: Database, jobs: JobRunner, token: str, *, host: str = "127.0.0.1", port: int = 8765,
                 manager_html: str | None = None, runtime: RuntimeManager | None = None,
                 data_dir: Path | None = None) -> None:  # fmt: skip
        security.require_loopback(host)
        self.config, self.db, self.jobs, self.token = config, db, jobs, token
        self.data_dir = data_dir or config.data.dir
        self.runtime = runtime or RuntimeManager(config.data.dir)
        self.native: dict[
            str, Callable[[], str | None]
        ] = {}  # set by the desktop window (a folder picker)
        self.tasks: dict[str, Task] = {}
        self._manager_html = manager_html
        self.scanner_cache: tuple[float, list[dict[str, Any]] | None] = (0.0, None)
        super().__init__((host, port), _make_handler(self))

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def server_close(self) -> None:
        self.runtime.stop()  # the AI engine is a child of the manager and ends with it
        super().server_close()

    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?token={self.token}"

    def manager_html(self) -> str | None:
        if self._manager_html is not None:
            return self._manager_html
        return TEMPLATE.read_text(encoding="utf-8") if TEMPLATE.is_file() else None


# --- helpers -----------------------------------------------------------------------------


def _os_user() -> str:
    """Who started a run: the account that runs this manager (it only listens on this machine)."""
    try:
        return getpass.getuser()[:60]
    except Exception:  # noqa: BLE001 - no account name available (containers); leave it blank
        return ""


def _head_dict(path: Path) -> dict[str, Any]:
    """The branch/commit checked out in `path`, as plain JSON. Read-only; all-empty for a non-repo
    or a path that is not a folder (git is only asked; nothing is fetched or changed)."""
    if not path.is_dir():
        return {"git": False, "branch": "", "commit": "", "dirty": False}
    head = git_head(path)
    return {"git": head.is_repo, "branch": head.branch, "commit": head.commit, "dirty": head.dirty}


def _cases_available(jobs: Any) -> bool:
    return bool(jobs.pipeline.benchmark_cases())


# --- request handler ---------------------------------------------------------------------


def _make_handler(srv: GapScanServer) -> type[BaseHTTPRequestHandler]:
    db, jobs, cfg = srv.db, srv.jobs, srv.config
    known_scanners = selectable_scanners(tuple(cfg.scanners.packs))  # the picker's choices

    class Handler(BaseHTTPRequestHandler):
        server_version = "GapScan"
        _body_read = False
        protocol_version = "HTTP/1.1"

        def log_message(
            self, fmt: str, *args: Any
        ) -> None:  # never log URLs: they may carry the launch token
            log.debug("request handled")

        # -- plumbing --
        def _send(
            self,
            status: int,
            body: bytes,
            ctype: str,
            extra: dict[str, str] | None = None,
            csp: str = security.CSP_APP,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", csp)
            for k, v in {**security.BASE_HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            if int(self.headers.get("Content-Length") or 0) > 0 and not self._body_read:
                self.send_header("Connection", "close")  # unread body would corrupt keep-alive
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, obj: Any, extra: dict[str, str] | None = None) -> None:
            self._send(status, json.dumps(obj).encode(), "application/json", extra)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > security.MAX_BODY:
                # Left unread, so the answer closes the connection: the next request on it
                # would otherwise be parsed from the middle of this body.
                raise ApiError(413, "request too large")
            self._body_read = True
            if length == 0:
                return {}
            try:
                data = json.loads(self.rfile.read(length))
            except ValueError as exc:
                raise ApiError(400, "invalid JSON") from exc
            if not isinstance(data, dict):
                raise ApiError(400, "expected a JSON object")
            return data

        def _handle(self, method: str) -> None:
            self._body_read = False  # one handler serves a whole keep-alive connection
            try:
                security.check_host(self.headers.get("Host"), srv.port)
                url = urlparse(self.path)
                if method == "GET" and url.path == "/health":
                    return self._json(200, {"ok": True})
                if method == "GET" and url.path == "/":
                    return self._index(parse_qs(url.query))
                security.check_token(
                    self.headers.get("Cookie"), self.headers.get("Authorization"), srv.token
                )
                security.check_csrf(
                    method, self.headers.get("Origin"), self.headers.get("Content-Type"), srv.port
                )
                for pattern, verbs, fn in ROUTES:
                    m = pattern.fullmatch(url.path)
                    if m:
                        if method not in verbs:
                            raise ApiError(405, "method not allowed")
                        return fn(self, *m.groups())
                raise ApiError(404, "not found")
            except security.Forbidden as exc:
                self._json(exc.status, {"error": str(exc)})
            except ApiError as exc:
                self._json(exc.status, {"error": exc.message})
            except InvalidInput as exc:
                self._json(400, {"error": str(exc)})
            except NotReady as exc:
                self._json(409, {"error": str(exc)})
            except Missing as exc:
                self._json(404, {"error": str(exc)})
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:  # noqa: BLE001 - never leak a traceback to the browser
                log.exception("unhandled error")
                self._json(500, {"error": "internal error"})

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._handle("PUT")

        def do_DELETE(self) -> None:  # noqa: N802
            self._handle("DELETE")

        # -- index and session --
        def _index(self, query: dict[str, list[str]]) -> None:
            supplied = (query.get("token") or [""])[0]
            if supplied:
                try:
                    security.check_token(None, f"Bearer {supplied}", srv.token)
                except security.Forbidden:
                    return self._send(
                        401,
                        b"Invalid token. Open the URL printed by `gapscan serve`.",
                        "text/plain; charset=utf-8",
                    )
                self.send_response(
                    302
                )  # set the session cookie, then drop the token from the address bar
                self.send_header("Set-Cookie", security.session_cookie(srv.token))
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                for k, v in security.BASE_HEADERS.items():
                    self.send_header(k, v)
                self.end_headers()
                return
            try:
                security.check_token(self.headers.get("Cookie"), None, srv.token)
            except security.Forbidden:
                return self._send(
                    401,
                    b"Open the URL printed by `gapscan serve` (it contains the session token).",
                    "text/plain; charset=utf-8",
                )
            html = srv.manager_html()
            if html is None:
                return self._send(
                    503,
                    b"The manager UI is not built. Run `make manager`.",
                    "text/plain; charset=utf-8",
                )
            self._send(200, html.encode(), "text/html; charset=utf-8")

        # -- projects --
        def projects(self) -> None:
            self._json(200, [db.project_summary(p) for p in db.projects()])

        def add_project(self) -> None:
            b = self._body()
            path = check_project_folder(str(b.get("path", "")), cfg.data.dir)
            name = str(b.get("name") or path.name).strip()[:80] or path.name
            if db.one("SELECT id FROM projects WHERE path = ?", (str(path),)):
                raise ApiError(409, "that folder is already a project")
            self._json(201, db.project_summary(db.add_project(name, str(path))))

        def project(self, pid: str) -> None:
            p = db.project(int(pid))
            if not p:
                raise ApiError(404, "no such project")
            self._json(200, {**db.project_summary(p), "scans": db.scans(p["id"])})

        def delete_project(self, pid: str) -> None:
            p = db.project(int(pid))
            if not p:
                raise ApiError(404, "no such project")
            if any(s["status"] in ACTIVE for s in db.scans(p["id"])):
                raise ApiError(409, "a scan is still running for this project")
            ids = [s["id"] for s in db.scans(p["id"], 10_000)]
            db.delete_project(p["id"])
            import shutil

            for i in ids:
                shutil.rmtree(jobs.run_dir(i), ignore_errors=True)
            self._json(
                200, {"deleted": True}
            )  # only GapScan's own records: the project's files are never touched

        # -- scans --
        def start_scan(self, pid: str) -> None:
            p = db.project(int(pid))
            if not p:
                raise ApiError(404, "no such project")
            if p["archived"]:
                raise ApiError(409, "this project is archived: restore it to start a run")
            b = self._body()
            opts = run_options(b, db.settings(), cfg, known_scanners)
            # Unless the run names scanners, the project's enabled Security capabilities decide
            # them (its service config); a disabled/absent service falls back to the global default.
            if "scanners" not in opts:
                chosen = db.project_scanners(p["id"])
                if chosen is not None:
                    opts["scanners"] = chosen
            if "baseline" in opts:
                base = db.scan(opts["baseline"])
                if not base or base["project_id"] != p["id"] or base["status"] != "done":
                    raise ApiError(400, "the baseline must be a finished run of this project")
            scan_id = db.create_scan(
                p["id"],
                opts,
                kind="dryrun" if b.get("dry_run") is True else "scan",
                started_by=_os_user(),
            )
            jobs.submit(scan_id)
            self._json(202, {"id": scan_id})

        def project_refs(self, pid: str) -> None:
            """The branch and commit checked out in the project folder, and the branches/refs a
            diff-aware run can use as its base. Read from git only; nothing is fetched or changed."""
            p = db.project(int(pid))
            if not p:
                raise ApiError(404, "no such project")
            target = Path(p["path"])
            refs = git_branches(target) if target.is_dir() else []
            self._json(200, {**_head_dict(target), "refs": refs})

        def finding_history(self, pid: str, fid: str) -> None:
            """How one finding looked in each earlier finished run (stable IDs make this possible)."""
            if not db.project(int(pid)):
                raise ApiError(404, "no such project")
            done = [
                x for x in db.scans(int(pid), 40) if x["status"] == "done" and x["kind"] == "scan"
            ]
            runs = [(x, jobs.run_dir(x["id"]) / "report.json") for x in done[:12]]
            self._json(200, finding_history(check_finding_id(fid), runs))

        def compare(self, pid: str, query: dict[str, list[str]]) -> None:
            """New, fixed and unchanged findings between two finished runs, plus the score series."""
            if not db.project(int(pid)):
                raise ApiError(404, "no such project")
            done = [
                x for x in db.scans(int(pid), 60) if x["status"] == "done" and x["kind"] == "scan"
            ]
            a, b = (query.get("a") or [""])[0], (query.get("b") or [""])[0]
            self._json(200, compare_runs(done, a, b, lambda i: jobs.run_dir(i) / "report.json"))

        def queue(self) -> None:
            rows = db.queue()
            for r in db.benchmark_queue():  # a model benchmark waits in the same queue as the scans
                rows.append({"id": r["id"], "project_id": 0, "kind": "benchmark", "project": "Model benchmark", "status": r["status"],
                             "phase": r["phase"], "options": {"model": r["model"]}, "progress_done": r["progress_done"],
                             "progress_total": r["progress_total"], "created_at": r["created_at"], "started_at": r["started_at"], "stats": {}})  # fmt: skip
            rows.sort(key=lambda r: (r["status"] != "running", r["created_at"], r["id"]))
            waiting = 0
            for r in rows:
                waiting = waiting + 1 if r["status"] == "queued" else waiting
                r["position"] = waiting if r["status"] == "queued" else 0
            self._json(200, rows)

        def start_benchmark(self) -> None:
            b = self._body()
            model = str(b.get("model", "")).strip()
            if model not in {p.model for p in cfg.llm.all_profiles.values()}:
                raise ApiError(400, "pick the model of one of the profiles")
            if not _cases_available(jobs):
                raise ApiError(409, "the benchmark cases (eval/triage_cases.json) were not found")
            bid = db.create_benchmark(model)
            jobs.submit_benchmark(bid)
            self._json(202, {"id": bid})

        def benchmarks(self) -> None:
            self._json(200, db.latest_benchmarks())

        def cancel_benchmark(self, bid: str) -> None:
            if not jobs.cancel_benchmark(int(bid)):
                raise ApiError(409, "that benchmark is not waiting or running")
            self._json(200, {"cancelling": True})

        def update_project(self, pid: str) -> None:
            p = db.project(int(pid))
            if not p:
                raise ApiError(404, "no such project")
            b = self._body()
            if "archived" in b:
                if not isinstance(b["archived"], bool):
                    raise ApiError(400, "archived must be true or false")
                if b["archived"] and any(s["status"] in ACTIVE for s in db.scans(p["id"])):
                    raise ApiError(409, "a run is still working for this project")
                db.set_archived(p["id"], b["archived"])
            self._json(200, db.project_summary(db.project(p["id"]) or p))

        def project_services(self, pid: str) -> None:
            if not db.project(int(pid)):
                raise ApiError(404, "no such project")
            self._json(200, db.services(int(pid)))

        def update_service(self, pid: str, domain: str) -> None:
            if not db.project(int(pid)):
                raise ApiError(404, "no such project")
            b = self._body()
            enabled = b.get("enabled")
            if enabled is not None and not isinstance(enabled, bool):
                raise ApiError(400, "enabled must be true or false")
            caps = b.get("capabilities")
            if caps is not None:
                if not (isinstance(caps, list) and all(isinstance(x, str) for x in caps)):
                    raise ApiError(400, "capabilities must be a list of capability ids")
                available = {
                    c["id"]
                    for c in capability_catalogue()
                    if c["domain"] == domain and not c["reserved"]
                }
                bad = [c for c in caps if c not in available]
                if bad:
                    raise ApiError(400, f"unknown or reserved capabilities: {', '.join(bad)}")
            out = db.set_service(int(pid), domain, enabled=enabled, capabilities=caps)
            if out is None:
                raise ApiError(404, f"service {domain!r} is not set up for this project")
            self._json(200, out)

        def scanners(self) -> None:

            if time.monotonic() - srv.scanner_cache[0] >= 60 or srv.scanner_cache[1] is None:
                # Versions need a program run each: cache a minute.
                found = [
                    {"name": st.name, "description": st.description, "available": st.available,
                     "version": st.version}
                    for st in scanner_status(cfg, known_scanners)
                ]  # fmt: skip
                srv.scanner_cache = (time.monotonic(), found)
            defaults = db.settings().get("scanners") or list(cfg.scanners.enabled)
            self._json(
                200,
                [
                    {**row, "default": row["name"] in defaults}
                    for row in (srv.scanner_cache[1] or [])
                ],
            )

        def report_json(self, sid: str) -> None:
            path = jobs.run_dir(int(sid)) / "report.json"
            if not path.is_file():
                raise ApiError(404, "no report data for this scan")
            self._send(200, path.read_bytes(), "application/json")

        def scan(self, sid: str) -> None:
            row = db.scan(int(sid))
            if not row:
                raise ApiError(404, "no such scan")
            run = jobs.run_dir(row["id"])
            row["has_report"] = (run / "report.html").is_file()
            row["exports"] = sorted(n for n in EXPORT_NAMES if (run / "exports" / n).is_file())
            self._json(200, row)

        def cancel_scan(self, sid: str) -> None:
            if not jobs.cancel(int(sid)):
                raise ApiError(409, "that scan is not running")
            self._json(200, {"cancelling": True})

        def rebuild_scan(self, sid: str) -> None:
            row = db.scan(int(sid))
            if not row:
                raise ApiError(404, "no such scan")
            if row["status"] != "done" or not (jobs.run_dir(row["id"]) / "scan.json").is_file():
                raise ApiError(409, "only a finished scan can be rebuilt")
            if db.query("SELECT id FROM scans WHERE status IN ('queued','running')"):
                raise ApiError(409, "wait for the running scan to finish")
            db.update_scan(
                row["id"],
                status="queued",
                phase="queued",
                options=json.dumps({**row["options"], "rebuild": True}),
            )
            jobs.submit(row["id"])
            self._json(202, {"id": row["id"]})

        def delete_scan(self, sid: str) -> None:
            row = db.scan(int(sid))
            if not row:
                raise ApiError(404, "no such scan")
            if row["status"] in ACTIVE:
                raise ApiError(409, "cancel the scan first")
            import shutil

            db.delete_scan(row["id"])
            shutil.rmtree(jobs.run_dir(row["id"]), ignore_errors=True)
            self._json(200, {"deleted": True})

        def report(self, sid: str) -> None:
            path = jobs.run_dir(int(sid)) / "report.html"
            if not path.is_file():
                raise ApiError(404, "no report for this scan")
            self._send(200, path.read_bytes(), "text/html; charset=utf-8", csp=security.CSP_REPORT)

        def export(self, sid: str, name: str) -> None:
            if name not in EXPORT_NAMES:
                raise ApiError(404, "unknown export")
            path = jobs.run_dir(int(sid)) / "exports" / name
            if not path.is_file():
                raise ApiError(404, "export not available")
            ctype = (
                "application/json"
                if name.endswith(".json") or name.endswith(".sarif")
                else "text/plain; charset=utf-8"
            )
            self._send(
                200,
                path.read_bytes(),
                ctype,
                {"Content-Disposition": f'attachment; filename="{name}"'},
            )

        # -- decisions --
        def decisions(self, pid: str) -> None:
            if not db.project(int(pid)):
                raise ApiError(404, "no such project")
            self._json(200, db.decisions(int(pid)))

        def set_decision(self, pid: str, fid: str) -> None:
            if not db.project(int(pid)):
                raise ApiError(404, "no such project")
            check_finding_id(fid)
            b = self._body()
            if b.get("decision") not in DECISIONS:
                raise ApiError(400, f"decision must be one of {sorted(DECISIONS)}")
            note = str(b.get("note", ""))[:500]
            db.set_decision(int(pid), fid, str(b["decision"]), note)
            self._json(
                200,
                {
                    "ok": True,
                    "memory": self._memory_from_decision(int(pid), fid, str(b["decision"]), note),
                },
            )

        def _memory_from_decision(self, pid: int, fid: str, decision: str, note: str) -> str | None:
            """A decision that carries a real explanation becomes a visible, deletable memory."""
            latest = db.latest_done(pid)
            path = jobs.run_dir(latest["id"]) / "scan.json" if latest else None
            if path is None or not path.is_file():
                return None
            finding = next(
                (
                    f
                    for f in ScanResult.model_validate_json(
                        path.read_text(encoding="utf-8")
                    ).findings
                    if f.id == fid
                ),
                None,
            )
            made = from_decision(finding, decision, note) if finding else None
            if made is None:
                return None
            db.save_memory(pid, made.model_dump(mode="json"))
            return made.id

        def memories(self, pid: str) -> None:
            if not db.project(int(pid)):
                raise ApiError(404, "no such project")
            self._json(200, db.memories(int(pid)))

        def add_memory(self, pid: str) -> None:
            if not db.project(int(pid)):
                raise ApiError(404, "no such project")
            b = self._body()
            try:
                memory = Memory(text=str(b.get("text", "")).strip(), kind=b.get("kind", "context"),
                                rule=str(b.get("rule", ""))[:120], path=str(b.get("path", ""))[:200],
                                cwe=str(b.get("cwe", ""))[:20])  # fmt: skip
            except ValueError as exc:
                raise ApiError(
                    400, "invalid memory: text up to 400 characters and a known kind"
                ) from exc
            if len(memory.text) < MIN_NOTE_CHARS:
                raise ApiError(
                    400, f"write at least {MIN_NOTE_CHARS} characters so it teaches something"
                )
            db.save_memory(int(pid), memory.model_dump(mode="json"))
            self._json(201, memory.model_dump(mode="json"))

        def update_memory(self, pid: str, mid: str) -> None:
            current = next((m for m in db.memories(int(pid)) if m["id"] == mid), None)
            if current is None:
                raise ApiError(404, "no such memory")
            b = self._body()
            if not isinstance(b.get("enabled"), bool):
                raise ApiError(400, "enabled must be true or false")
            db.save_memory(int(pid), {**current, "enabled": b["enabled"]})
            self._json(200, {"ok": True})

        def delete_memory(self, pid: str, mid: str) -> None:
            if not db.delete_memory(int(pid), mid):
                raise ApiError(404, "no such memory")
            self._json(200, {"ok": True})

        def clear_decision(self, pid: str, fid: str) -> None:
            db.clear_decision(int(pid), check_finding_id(fid))
            self._json(200, {"ok": True})

        # -- settings, models, doctor, data --
        def get_settings(self) -> None:
            self._json(200, run_settings(db.settings(), cfg))

        def put_settings(self) -> None:
            for key, value in settings_update(self._body(), cfg, known_scanners).items():
                db.set_setting(key, value)
            self.get_settings()

        def models(self) -> None:
            installed: dict[str, Any] = {}
            error = ""
            try:
                installed = {m["name"]: m for m in LLMClient(cfg.llm).list_models()}
            except LLMError as exc:
                error = str(exc)
            chosen = db.settings().get("profile") or cfg.llm.profile

            def found(model: str) -> dict[str, Any] | None:
                return installed.get(model) or installed.get(f"{model}:latest")

            profiles = [{"name": n, "model": p.model, "note": p.note, "installed": found(p.model) is not None,
                         "size_gb": (found(p.model) or {}).get("size_gb") or None, "selected": n == chosen}
                        for n, p in cfg.llm.all_profiles.items()]  # fmt: skip
            self._json(
                200,
                {
                    "profiles": profiles,
                    "installed": list(installed.values()),
                    "error": error,
                    "endpoint": cfg.llm.endpoint,
                },
            )

        def compliance(self) -> None:
            self._json(200, catalog_payload())

        def doctor(self) -> None:
            items = health.rows(cfg, run_all_checks(cfg))
            self._json(
                200,
                {
                    "checked_at": datetime.now(UTC).isoformat(timespec="seconds"),
                    "summary": health.summary(items),
                    "items": items,
                },
            )

        def data(self) -> None:
            state: dict[str, Any] = {}
            with contextlib.suppress(OSError, ValueError):
                state = json.loads((cfg.data.dir / STATE_FILE).read_text(encoding="utf-8"))
            snaps = state.get("snapshots", {}) if isinstance(state, dict) else {}
            self._json(200, {"version": __version__, "data_dir": str(cfg.data.dir), "bundle": state or None,
                             "max_age_days": cfg.general.vuln_data_max_age_days,
                             "freshness": health.freshness(snaps, cfg.general.vuln_data_max_age_days)})  # fmt: skip

        def start_task(self) -> None:
            b = self._body()
            raw = str(b.get("path", ""))
            path = Path(raw).expanduser()
            if not path.is_file() or not (raw.endswith((".tar", ".tar.gz", ".tgz"))):
                raise ApiError(400, "give the path of a bundle file (.tar.gz) on this machine")
            if db.query("SELECT id FROM scans WHERE status IN ('queued','running')"):
                raise ApiError(409, "wait for the running scan to finish before changing the data")
            verify_only, force = bool(b.get("verify_only")), bool(b.get("force"))
            task = Task("verify" if verify_only else "update")
            srv.tasks[task.id] = task
            tasks.run(
                task, tasks.install_bundle(cfg.data.dir, path, verify_only=verify_only, force=force)
            )
            self._json(202, {"id": task.id})

        def build_task(self) -> None:
            """Package the data already on this machine into a bundle. Never downloads anything."""
            b = self._body()
            raw = str(b.get("path", "")).strip()
            path = Path(raw).expanduser() if raw else Path.home() / tasks.bundle_name()
            if path.is_dir():
                path = path / tasks.bundle_name()
            if not path.name.endswith((".tar.gz", ".tgz", ".tar")):
                raise ApiError(400, "the bundle file name must end in .tar.gz")
            if not path.parent.is_dir():
                raise ApiError(400, f"the folder {path.parent} does not exist")
            if path.exists():
                raise ApiError(409, f"{path} already exists; choose another name")
            if db.query("SELECT id FROM scans WHERE status IN ('queued','running')"):
                raise ApiError(409, "wait for the running scan to finish before packaging data")
            task = Task("build")
            srv.tasks[task.id] = task
            tasks.run(task, tasks.package_data(cfg.data.dir, path))
            self._json(202, {"id": task.id})

        def task(self, tid: str) -> None:
            t = srv.tasks.get(tid)
            if not t:
                raise ApiError(404, "no such task")
            self._json(200, t.view())

        def desktop(self) -> None:
            self._json(200, {"folder_picker": "choose_folder" in srv.native})

        def choose_folder(self) -> None:
            pick = srv.native.get("choose_folder")
            if pick is None:
                raise ApiError(404, "there is no desktop window to open a folder dialog")
            self._json(200, {"path": pick()})

        def browse(self, query: dict[str, list[str]]) -> None:
            """List the sub-folders of a directory so the browser can offer a folder picker
            (no native dialog outside the desktop window). Directories only; defaults to home.
            Carries the folder's own branch/commit so the picker can show what you would add."""
            listing = list_directory((query.get("path") or [""])[0], Path.home())
            self._json(200, {**listing, "head": _head_dict(Path(listing["path"]))})

        def git_head(self, query: dict[str, list[str]]) -> None:
            """The branch/commit checked out in one folder, so the Add-a-project form can show
            what will be registered. Read-only; all-empty for a non-repo or a path that is not a
            folder. Never errors on a bad path (the form may send a half-typed one)."""
            raw = (query.get("path") or [""])[0].strip()
            empty = {"git": False, "branch": "", "commit": "", "dirty": False}
            self._json(200, _head_dict(Path(raw).expanduser()) if raw else empty)

        def cancel_task(self, tid: str) -> None:
            t = srv.tasks.get(tid)
            if not t:
                raise ApiError(404, "no such task")
            t.cancel.set()
            self._json(200, {"id": t.id})

        def setup_status(self) -> None:
            running = next(
                (
                    t.id
                    for t in srv.tasks.values()
                    if t.kind in setup_steps.STEPS and t.status == "running"
                ),
                None,
            )
            status = srv.runtime.status()
            self._json(200, {**status, "plan": first_run_plan(status), "task": running})

        def setup_welcome(self) -> None:
            value = str(self._body().get("value", ""))
            if value not in ("done", "skipped"):
                raise ApiError(400, 'value must be "done" or "skipped"')
            srv.runtime.set_welcome(value)
            self._json(200, {"welcome": value})

        def add_sample(self) -> None:
            folder = ensure_sample(app_dir() / "sample-project")
            existing = db.one("SELECT id FROM projects WHERE path = ?", (str(folder.resolve()),))
            if existing:
                project = db.project(int(existing["id"]))
                assert project is not None
            else:
                project = db.add_project(SAMPLE_NAME, str(folder.resolve()))
            self._json(200, db.project_summary(project))

        # -- the team workspace (signed "local run" reports) --
        def _workspace(self) -> Workspace:
            return Workspace(srv.data_dir, str(db.settings().get("workspace_url") or ""))

        def workspace(self) -> None:
            ws = self._workspace()
            self._json(200, {"url": ws.url, "connected": bool(ws.url and ws.token()),
                             "identity": db.settings().get("workspace_identity"), "key": ws.key(),
                             "projects": db.settings().get("workspace_projects") or {}})  # fmt: skip

        def workspace_save(self) -> None:
            b = self._body()
            url = check_url(str(b.get("url", "")))
            current = self._workspace()
            token = str(b.get("token") or "").strip() or (
                current.token() if current.url == url else ""
            )
            if not token:
                raise ApiError(400, "paste a token from the team workspace (ask its admin)")
            ws = Workspace(srv.data_dir, url)
            identity = ws.check(token)  # refuses an address or token that does not work
            ws.save_token(token)
            db.set_setting("workspace_url", url)
            db.set_setting("workspace_identity", identity)
            self.workspace()

        def workspace_forget(self) -> None:
            self._workspace().forget()
            for key in ("workspace_url", "workspace_identity"):
                db.set_setting(key, "")
            self.workspace()

        def workspace_key(self) -> None:
            self._json(200, self._workspace().create_key())

        def workspace_projects(self) -> None:
            self._json(200, self._workspace().projects())

        def send_scan(self, sid: str) -> None:
            row = db.scan(int(sid))
            if not row:
                raise ApiError(404, "no such scan")
            path = jobs.run_dir(row["id"]) / "scan.json"
            if row["status"] != "done" or row["kind"] != "scan" or not path.is_file():
                raise ApiError(409, "only a finished scan can be sent")
            target = str(self._body().get("project_id", ""))
            scan_result = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
            result = self._workspace().send(scan_result, target)
            chosen = dict(db.settings().get("workspace_projects") or {})
            chosen[str(row["project_id"])] = target  # offered first next time for this project
            db.set_setting("workspace_projects", chosen)
            self._json(200, result)

        def setup_run(self) -> None:
            b = self._body()
            step, pack = str(b.get("step", "")), str(b.get("pack", ""))
            if step not in setup_steps.STEPS:
                raise ApiError(400, "unknown setup step")
            if any(
                t.kind in setup_steps.STEPS and t.status == "running" for t in srv.tasks.values()
            ):
                raise ApiError(409, "another setup step is still running")
            if step in ("model", "remove", "link") and not pack:
                raise ApiError(400, "choose a model")
            if step in ("data", "start", "stop", "remove") and db.query(
                "SELECT id FROM scans WHERE status IN ('queued','running')"
            ):
                raise ApiError(409, "wait for the running scan to finish first")
            task = Task(step)
            srv.tasks[task.id] = task
            threading.Thread(
                target=setup_steps.work, args=(srv, task, step, pack), daemon=True
            ).start()
            self._json(202, {"id": task.id})

    Route = tuple[re.Pattern[str], set[str], Callable[..., None]]
    ROUTES: list[Route] = [
        (re.compile(r"/api/queue"), {"GET"}, lambda h: h.queue()),
        (
            re.compile(r"/api/benchmarks"),
            {"GET", "POST"},
            lambda h: h.benchmarks() if h.command == "GET" else h.start_benchmark(),
        ),
        (re.compile(r"/api/benchmarks/(\d+)/cancel"), {"POST"}, lambda h, i: h.cancel_benchmark(i)),
        (
            re.compile(r"/api/projects/(\d+)/compare"),
            {"GET"},
            lambda h, i: h.compare(i, parse_qs(urlparse(h.path).query)),
        ),
        (
            re.compile(r"/api/projects/(\d+)/findings/([^/]+)/history"),
            {"GET"},
            lambda h, i, f: h.finding_history(i, f),
        ),
        (re.compile(r"/api/scanners"), {"GET"}, lambda h: h.scanners()),
        (re.compile(r"/api/scans/(\d+)/report\.json"), {"GET"}, lambda h, i: h.report_json(i)),
        (
            re.compile(r"/api/projects"),
            {"GET", "POST"},
            lambda h: h.projects() if h.command == "GET" else h.add_project(),
        ),
        (
            re.compile(r"/api/projects/(\d+)"),
            {"GET", "DELETE", "PUT"},
            lambda h, i: (
                h.project(i)
                if h.command == "GET"
                else h.update_project(i)
                if h.command == "PUT"
                else h.delete_project(i)
            ),
        ),
        (re.compile(r"/api/projects/(\d+)/scans"), {"POST"}, lambda h, i: h.start_scan(i)),
        (re.compile(r"/api/projects/(\d+)/refs"), {"GET"}, lambda h, i: h.project_refs(i)),
        (re.compile(r"/api/projects/(\d+)/decisions"), {"GET"}, lambda h, i: h.decisions(i)),
        (
            re.compile(r"/api/projects/(\d+)/decisions/([^/]+)"),
            {"PUT", "DELETE"},
            lambda h, i, f: h.set_decision(i, f) if h.command == "PUT" else h.clear_decision(i, f),
        ),
        (
            re.compile(r"/api/projects/(\d+)/memories"),
            {"GET", "POST"},
            lambda h, i: h.memories(i) if h.command == "GET" else h.add_memory(i),
        ),
        (
            re.compile(r"/api/projects/(\d+)/memories/([0-9a-f]{10})"),
            {"PUT", "DELETE"},
            lambda h, i, m: h.update_memory(i, m) if h.command == "PUT" else h.delete_memory(i, m),
        ),
        (re.compile(r"/api/projects/(\d+)/services"), {"GET"}, lambda h, i: h.project_services(i)),
        (
            re.compile(r"/api/projects/(\d+)/services/([a-z0-9_]+)"),
            {"PUT"},
            lambda h, i, d: h.update_service(i, d),
        ),
        (
            re.compile(r"/api/scans/(\d+)"),
            {"GET", "DELETE"},
            lambda h, i: h.scan(i) if h.command == "GET" else h.delete_scan(i),
        ),
        (re.compile(r"/api/scans/(\d+)/cancel"), {"POST"}, lambda h, i: h.cancel_scan(i)),
        (re.compile(r"/api/scans/(\d+)/rebuild"), {"POST"}, lambda h, i: h.rebuild_scan(i)),
        (re.compile(r"/api/scans/(\d+)/report\.html"), {"GET"}, lambda h, i: h.report(i)),
        (
            re.compile(r"/api/scans/(\d+)/exports/([\w.\-]+)"),
            {"GET"},
            lambda h, i, n: h.export(i, n),
        ),
        (
            re.compile(r"/api/settings"),
            {"GET", "PUT"},
            lambda h: h.get_settings() if h.command == "GET" else h.put_settings(),
        ),
        (re.compile(r"/api/models"), {"GET"}, lambda h: h.models()),
        (re.compile(r"/api/doctor"), {"GET"}, lambda h: h.doctor()),
        (re.compile(r"/api/compliance"), {"GET"}, lambda h: h.compliance()),
        (re.compile(r"/api/data"), {"GET"}, lambda h: h.data()),
        (re.compile(r"/api/data/bundle"), {"POST"}, lambda h: h.start_task()),
        (re.compile(r"/api/data/build"), {"POST"}, lambda h: h.build_task()),
        (re.compile(r"/api/tasks/([0-9a-f]+)"), {"GET"}, lambda h, i: h.task(i)),
        (re.compile(r"/api/tasks/([0-9a-f]+)/cancel"), {"POST"}, lambda h, i: h.cancel_task(i)),
        (re.compile(r"/api/desktop"), {"GET"}, lambda h: h.desktop()),
        (re.compile(r"/api/desktop/choose-folder"), {"POST"}, lambda h: h.choose_folder()),
        (re.compile(r"/api/fs"), {"GET"}, lambda h: h.browse(parse_qs(urlparse(h.path).query))),
        (
            re.compile(r"/api/git-head"),
            {"GET"},
            lambda h: h.git_head(parse_qs(urlparse(h.path).query)),
        ),
        (re.compile(r"/api/setup/welcome"), {"POST"}, lambda h: h.setup_welcome()),
        (re.compile(r"/api/sample"), {"POST"}, lambda h: h.add_sample()),
        (re.compile(r"/api/setup"), {"GET"}, lambda h: h.setup_status()),
        (re.compile(r"/api/setup/run"), {"POST"}, lambda h: h.setup_run()),
        (
            re.compile(r"/api/workspace"),
            {"GET", "PUT", "DELETE"},
            lambda h: (
                h.workspace()
                if h.command == "GET"
                else h.workspace_save()
                if h.command == "PUT"
                else h.workspace_forget()
            ),
        ),
        (re.compile(r"/api/workspace/key"), {"POST"}, lambda h: h.workspace_key()),
        (re.compile(r"/api/workspace/projects"), {"GET"}, lambda h: h.workspace_projects()),
        (re.compile(r"/api/scans/(\d+)/send"), {"POST"}, lambda h, i: h.send_scan(i)),
    ]
    return Handler
