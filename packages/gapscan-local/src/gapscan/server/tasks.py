"""Short background tasks for data operations (bundle verify, install and packaging), each with a
log the manager shows. The data work itself is the offline adapter's (`gapscan.offline`); this
only runs it on a thread and records what happened."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..offline.bundle import BundleOptions, build_bundle
from ..offline.update import import_bundle, verify_bundle


class Task:
    """A short background task with a visible log."""

    def __init__(self, kind: str) -> None:
        self.id = uuid.uuid4().hex[:8]
        self.kind, self.status, self.log, self.result = kind, "running", [], {}  # type: str, str, list[str], dict[str, Any]
        self.progress: dict[str, int] = {"done": 0, "total": 0}
        self.cancel = threading.Event()

    def view(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "status": self.status, "log": self.log,
                "result": self.result, "progress": self.progress}  # fmt: skip


def run(task: Task, work: Callable[[Task], None]) -> None:
    """Run `work` on a thread. Any exception is a refusal, written to the task's log."""

    def go() -> None:
        try:
            work(task)
            task.status = "done"
        except Exception as exc:  # noqa: BLE001 - an unreadable bundle or missing data is a refusal
            task.log.append(f"refused: {exc}")
            task.status = "failed"

    threading.Thread(target=go, daemon=True).start()


def bundle_name() -> str:
    return f"gapscan-bundle-{datetime.now(UTC).strftime('%Y-%m-%d')}.tar.gz"


def install_bundle(
    data_dir: Path, path: Path, *, verify_only: bool, force: bool
) -> Callable[[Task], None]:
    """Check every file of a bundle against its manifest, then (unless verify_only) install it."""

    def work(task: Task) -> None:
        task.log.append("checking every file against the manifest ...")
        if verify_only:
            m = verify_bundle(path)
            task.log.append(f"bundle intact: {len(m.files)} files, built {m.created_at}")
            task.result = {"snapshots": m.snapshots}
        else:
            res = import_bundle(data_dir, path, force=force)
            task.log.append("installed: " + ", ".join(res.sections))
            task.result = {"snapshots": res.manifest.snapshots, "warnings": res.warnings}

    return work


def package_data(data_dir: Path, path: Path) -> Callable[[Task], None]:
    """Package the data already on this machine into a bundle. Never downloads anything."""

    def work(task: Task) -> None:
        task.log.append("packaging the data on this machine (nothing is downloaded) ...")
        compress = path.name.endswith("gz") or path.name.endswith(".tgz")
        m = build_bundle(data_dir, path, BundleOptions(compress=compress))
        size = path.stat().st_size / 1e6
        task.log.append(f"wrote {path} ({size:.0f} MB, {len(m.files)} files)")
        task.log.append("sha256 is stored next to it as " + path.name + ".sha256")
        task.result = {"path": str(path), "snapshots": m.snapshots}

    return work
