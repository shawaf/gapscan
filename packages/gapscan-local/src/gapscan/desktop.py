"""The desktop window: GapScan's manager in its own native window instead of a browser tab.

It starts the same local server as `gapscan serve` (loopback only, random port, per-launch token), shows it in
the system's own web view (WKWebView on macOS, WebView2 on Windows) through pywebview, and stops everything when the
window closes. One copy runs at a time per user (a lock file), because two managers would fight over one database.
The window gets no JavaScript bridge (the manager's strict Content-Security-Policy would block one, and it would expose
Python to a page that shows untrusted code). The native folder picker is instead an ordinary authenticated call on the
local server, which opens the dialog itself."""

from __future__ import annotations

import contextlib
import logging
import sys
import threading
import webbrowser
from pathlib import Path
from typing import IO, Any
from urllib.parse import urlparse

from .config import Config
from .paths import app_dir

log = logging.getLogger(__name__)
TITLE = "GapScan"
SIZE = (1280, 860)
MIN_SIZE = (960, 640)


class AlreadyRunning(RuntimeError):
    pass


def acquire_lock(folder: Path) -> IO[str]:
    """Take the per-user lock; raises AlreadyRunning when another copy holds it. Keep the handle open."""
    folder.mkdir(parents=True, exist_ok=True)
    handle = (folder / "app.lock").open("a+")
    try:
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
        else:
            import fcntl

            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise AlreadyRunning("GapScan is already running for this user") from exc
    return handle


class FolderPicker:
    """Opens the system's folder dialog on behalf of the manager's "Browse..." button."""

    def __init__(self, webview: Any) -> None:
        self._webview = webview
        self._window: Any = None

    def attach(self, window: Any) -> None:
        self._window = window

    def __call__(self) -> str | None:
        if self._window is None:
            return None
        kind = getattr(getattr(self._webview, "FileDialog", None), "FOLDER", None) or getattr(
            self._webview, "FOLDER_DIALOG", None
        )
        chosen = self._window.create_file_dialog(kind)
        return str(chosen[0]) if chosen else None


def is_local(url: str) -> bool:
    return (urlparse(url).hostname or "") in {"127.0.0.1", "localhost", "::1"}


def run(cfg: Config, webview: Any | None = None) -> int:
    """Open the window and block until it is closed. `webview` is injectable for tests."""
    if webview is None:
        import webview as real

        webview = real
    from .server import build_server

    lock = acquire_lock(app_dir())
    server = build_server(cfg, port=0)
    thread = threading.Thread(target=server.serve_forever, name="gapscan-http", daemon=True)
    thread.start()
    picker = FolderPicker(webview)
    server.native["choose_folder"] = picker
    window = webview.create_window(
        TITLE, server.url(), width=SIZE[0], height=SIZE[1], min_size=MIN_SIZE, text_select=True
    )
    picker.attach(window)

    def keep_local() -> None:
        """Pages outside this machine never stay in the window (they would get the folder picker): open them in the browser."""
        with contextlib.suppress(Exception):
            current = window.get_current_url() or ""
            if current and not is_local(current):
                webbrowser.open(current)
                window.load_url(server.url())

    with contextlib.suppress(Exception):
        window.events.loaded += keep_local
    try:
        webview.start()
    finally:
        server.shutdown()
        server.jobs.stop()
        server.server_close()
        lock.close()
    return 0
