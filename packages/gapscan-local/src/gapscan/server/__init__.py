"""The local management UI: `gapscan serve`."""

from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..kb import load_kb
from ..runtime.manager import RuntimeManager
from ..runtime.tools import activate as activate_tools
from .app import GapScanServer
from .db import Database
from .jobs import JobRunner, Pipeline
from .security import new_token, require_loopback

__all__ = ["GapScanServer", "build_server"]


def build_server(config: Config, *, host: str = "127.0.0.1", port: int = 8765, pipeline: Pipeline | None = None,
                 token: str | None = None, data_dir: Path | None = None,
                 runtime: RuntimeManager | None = None) -> GapScanServer:  # fmt: skip
    """Wire the database, job runner and HTTP server together (the worker thread is started here)."""
    require_loopback(host)  # before anything is created or started: a refused host leaves no trace
    base = data_dir or config.data.dir
    db = Database(base / "gapscan.db")
    jobs = JobRunner(
        db,
        config,
        base / "runs",
        pipeline or Pipeline(),
        kb_loader=lambda c: load_kb(c, use_embeddings=False),
    )
    runtime = runtime or RuntimeManager(base)
    runtime.attach(config)
    activate_tools(runtime.root)
    jobs.engine = runtime
    jobs.start()
    return GapScanServer(
        config, db, jobs, token or new_token(), host=host, port=port, runtime=runtime, data_dir=base
    )
