"""The desktop window logic, with a fake web view standing in for the real one (no display needed)."""

from __future__ import annotations

import httpx
import pytest

from gapscan import desktop
from gapscan.config import Config


class FakeEvents:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, fn):
        self.handlers.append(fn)
        return self


class FakeWindow:
    def __init__(self, url, js_api=None):
        self.url, self.js_api, self.events, self.dialogs, self.loaded = (
            url,
            js_api,
            type("E", (), {"loaded": FakeEvents()})(),
            [],
            [],
        )
        self.current = url

    def create_file_dialog(self, kind):
        self.dialogs.append(kind)
        return ["/Users/me/code/app"]

    def get_current_url(self):
        return self.current

    def load_url(self, url):
        self.loaded.append(url)


class FakeWebview:
    FOLDER_DIALOG = "folder"

    def __init__(self, during=None):
        self.windows, self.during, self.opened = [], during, []

    def create_window(self, title, url, **kw):
        w = FakeWindow(url, kw.get("js_api"))
        w.title, w.options = title, kw
        self.windows.append(w)
        return w

    def start(self):
        if self.during:
            self.during(self.windows[0])


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("GAPSCAN_HOME", str(tmp_path / "home"))
    return Config(
        data={"dir": str(tmp_path / "data")},
        scanners={
            "osv": {"db_dir": str(tmp_path / "o")},
            "trivy": {"cache_dir": str(tmp_path / "t")},
        },
    )


def test_the_window_shows_the_local_server_and_everything_stops_with_it(cfg):
    seen = {}

    def during(window):
        seen["title"], seen["url"], seen["size"] = (
            window.title,
            window.url,
            (window.options["width"], window.options["height"]),
        )
        client = httpx.Client(follow_redirects=True)
        page = client.get(
            window.url
        )  # the token handshake works from a fresh client, like the web view
        seen["status"], seen["login_free"] = page.status_code, "token" not in str(page.url)
        seen["api"] = client.get(window.url.split("/?")[0] + "/api/projects").status_code

    wv = FakeWebview(during)
    assert desktop.run(cfg, wv) == 0
    assert (
        seen["title"] == "GapScan"
        and seen["url"].startswith("http://127.0.0.1:")
        and "token=" in seen["url"]
    )
    assert seen["status"] == 200 and seen["login_free"] and seen["api"] == 200
    with pytest.raises(httpx.HTTPError):
        httpx.get(seen["url"], timeout=2)  # the server is gone after the window closed
    desktop.acquire_lock(desktop.app_dir()).close()  # and the lock was released


def test_only_one_copy_runs_at_a_time(cfg):
    held = desktop.acquire_lock(desktop.app_dir())
    try:
        with pytest.raises(desktop.AlreadyRunning):
            desktop.run(cfg, FakeWebview())
    finally:
        held.close()


def test_the_window_has_no_javascript_bridge_and_the_picker_is_a_server_call(cfg):
    seen = {}

    def during(window):
        seen["options"] = set(window.options)
        client = httpx.Client(follow_redirects=True)
        client.get(window.url)
        base = window.url.split("/?")[0]
        headers = {"Origin": base, "Content-Type": "application/json"}
        seen["desktop"] = client.get(base + "/api/desktop").json()
        seen["pick"] = client.post(
            base + "/api/desktop/choose-folder", content="{}", headers=headers
        ).json()
        seen["anon"] = httpx.post(
            base + "/api/desktop/choose-folder", content="{}", headers=headers
        ).status_code

    desktop.run(cfg, FakeWebview(during))
    assert "js_api" not in seen["options"]  # nothing of Python is exposed to the page
    assert seen["desktop"] == {"folder_picker": True} and seen["pick"] == {
        "path": "/Users/me/code/app"
    }
    assert seen["anon"] == 401  # the picker needs the session like every other call


def test_folder_picker_returns_nothing_when_the_dialog_is_cancelled():
    wv = FakeWebview()
    picker = desktop.FolderPicker(wv)
    assert picker() is None  # no window yet
    window = FakeWindow("http://127.0.0.1:1/", None)
    window.create_file_dialog = lambda kind: None  # the user pressed Cancel
    picker.attach(window)
    assert picker() is None


def test_pages_outside_this_machine_leave_the_window(cfg, monkeypatch):
    opened = []
    monkeypatch.setattr(desktop.webbrowser, "open", lambda u: opened.append(u))

    def during(window):
        window.current = "https://evil.example/phish"
        for fn in window.events.loaded.handlers:
            fn()

    wv = FakeWebview(during)
    desktop.run(cfg, wv)
    assert (
        opened == ["https://evil.example/phish"]
        and wv.windows[0].loaded
        and wv.windows[0].loaded[0].startswith("http://127.0.0.1:")
    )
    assert desktop.is_local("http://localhost:5/x") and not desktop.is_local("https://example.com")
