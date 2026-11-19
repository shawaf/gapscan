"""The setup wizard's steps, run as background tasks with progress. This is the only code in the
manager that goes online, and only to the hosts in the pinned manifest."""

from __future__ import annotations

import threading
from typing import Any

from ..offline.bundle import BundleError
from ..offline.refresh import refresh_all
from ..offline.update import UpdateError, import_bundle
from ..runtime.download import DownloadCancelled, DownloadError
from ..runtime.manager import RuntimeError_

STEPS = {"engine", "model", "embedding", "link", "scanners", "start", "stop", "remove", "data"}
ONLINE = {"engine", "model", "embedding", "scanners", "data"}  # the steps that download


def work(srv: Any, task: Any, step: str, pack: str) -> None:
    rt, say = srv.runtime, task.log.append
    last = [-1]

    def progress(done: int, total: int) -> None:
        task.progress = {"done": done, "total": total}
        pct = int(done * 100 / total) if total else 0
        if (pct // 10 != last[0] // 10 or pct == 100) and pct != last[
            0
        ]:  # a log line every 10 percent
            last[0] = pct
            say(f"{pct}% ({done / 1e6:.0f} of {total / 1e6:.0f} MB)")

    try:
        if step == "engine":
            rt.install_runtime(progress, task.cancel, say)
        elif step == "model":
            rt.install_model(pack, progress, task.cancel, say)
        elif step == "scanners":
            tools = rt.tools
            tools.install(progress, task.cancel, say)
            tools.activate()
            srv.scanner_cache = (0.0, None)  # the scanner list is read again
            left = tools.missing()
            say("every scanner is ready" if not left else "still missing: " + ", ".join(left))
        elif step == "link":
            rt.link_ollama(pack, say)
        elif step == "embedding":
            emb = rt.manifest.embedding()
            if emb is None:
                raise RuntimeError_("this build has no embedding model")
            rt.install_model(emb.id, progress, task.cancel, say)
        elif step == "start":
            say(
                "starting the AI engine and loading the model (a large model can take a minute) ..."
            )
            rt.start_chat(pack or None)
            say("the AI engine is running on this machine")
        elif step == "stop":
            rt.stop_chat()
            say("the AI engine is stopped")
        elif step == "remove":
            rt.remove_model(pack)
            say("removed")
        elif step == "data":
            _data(srv, say, progress, task.cancel)
        task.status = "done"
    except DownloadCancelled as exc:
        say(str(exc))
        task.status = "cancelled"
    except (DownloadError, RuntimeError_, BundleError, UpdateError, OSError) as exc:
        say(f"failed: {exc}")
        task.status = "failed"
    except Exception as exc:  # noqa: BLE001 - a step must always end in a visible state
        say(f"failed: {type(exc).__name__}: {exc}")
        task.status = "failed"


def _data(srv: Any, say: Any, progress: Any, cancel: threading.Event) -> None:
    """Get the security data (vulnerability databases, advisories, knowledge base).

    With a published data pack this is one verified download imported by the same checked importer as `gapscan update`.
    Without one (a source checkout, or a manifest that lists none) it is fetched from the upstream sources."""
    rt = srv.runtime
    pack = rt.manifest.data()
    if pack is not None:
        say(f"downloading the security data ({pack.size / 1e6:.0f} MB)")
        path = rt.fetch_pack(pack, progress, cancel)
        say("checking every file against the bundle's manifest and installing it")
        result = import_bundle(srv.config.data.dir, path, force=True, install_model=False)
        say("installed: " + ", ".join(result.sections))
        for warning in result.warnings:
            say("note: " + warning)
        path.unlink(missing_ok=True)
        path.with_name(path.name + ".ok").unlink(missing_ok=True)
        return
    cfg = srv.config.model_copy(deep=True)
    emb = rt.manifest.embedding()
    started = False
    if rt.binary() is not None and emb is not None and rt.installed(emb):
        say("starting the embedding model for the knowledge base ...")
        rt.start_embedding()
        started = True
        rt.apply(cfg)
    try:
        versions = refresh_all(cfg, rebuild_kb=True, progress=say)
    finally:
        if started:
            rt.stop_embedding()
    say("data ready: " + ", ".join(f"{k} {v}" for k, v in versions.items() if k.endswith("_date")))


def new_cancel() -> threading.Event:
    return threading.Event()
