"""Browser test of the setup wizard against a real server whose downloads come from a local fake host:
the page shows the machine and the recommendation, installs the engine, downloads the model and starts
it, with the progress and the final state read from the page. Skipped without Chromium or templates."""

from __future__ import annotations

import threading

import pytest

from gapscan.config import Config
from gapscan.report.dashboard import TEMPLATE_PATH
from gapscan.runtime.manager import RuntimeManager
from gapscan.server import build_server
from gapscan.server.app import TEMPLATE as MANAGER_TEMPLATE

from .browser import launch_chromium
from .test_runtime import HW, Origin, make_manifest
from .test_server import FakePipeline

playwright_api = pytest.importorskip("playwright.sync_api")
MANAGER = MANAGER_TEMPLATE
pytestmark = pytest.mark.skipif(
    not (TEMPLATE_PATH.is_file() and MANAGER.is_file()),
    reason="templates not built (make dashboard manager)",
)


def test_the_wizard_installs_downloads_and_starts_the_engine(tmp_path, monkeypatch):
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "no-ollama"))
    origin = Origin()
    cfg = Config(data={"dir": str(tmp_path / "data")},
                 scanners={"osv": {"db_dir": str(tmp_path / "o")}, "trivy": {"cache_dir": str(tmp_path / "t")}})  # fmt: skip
    runtime = RuntimeManager(tmp_path / "data", make_manifest(origin), HW)
    server = build_server(cfg, port=0, pipeline=FakePipeline(), runtime=runtime)
    server.runtime.set_welcome(
        "skipped"
    )  # these tests start from the domain picker, not the first-run welcome page
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with playwright_api.sync_playwright() as p:
            try:
                browser = launch_chromium(p)
            except Exception as exc:  # noqa: BLE001
                pytest.skip(f"Chromium unavailable: {exc}")
            page = browser.new_page(viewport={"width": 1280, "height": 1000})
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(server.url())
            page.get_by_role("heading", name="What do you want to close gaps against?").wait_for()
            page.get_by_role("link", name="Setup").click()
            page.get_by_role("heading", name="Setup").wait_for()
            page.get_by_text(
                "The only time GapScan goes online"
            ).wait_for()  # after /api/setup loads
            assert "The only time GapScan goes online" in page.inner_text("main")
            assert "Recommended for this machine: qwen3-coder:30b" in page.inner_text("main")
            page.screenshot(path=str(tmp_path / "setup-start.png"), full_page=True)

            page.get_by_role("button", name="Install AI engine").click()
            page.get_by_role("heading", name="Installing the AI engine").wait_for()
            page.get_by_text("Ready").first.wait_for()
            page.locator("#s2").locator("xpath=..").get_by_text("Ready").wait_for(timeout=20_000)

            page.get_by_role("button", name="Download qwen3-coder:30b").click()
            page.locator("#s3").locator("xpath=..").get_by_text("Ready").wait_for(timeout=30_000)
            page.get_by_role("button", name="Start AI engine").click()
            page.get_by_role("button", name="Stop AI engine").wait_for(timeout=30_000)
            assert "The AI engine is running qwen3-coder:30b" in page.inner_text("main")
            page.screenshot(path=str(tmp_path / "setup-done.png"), full_page=True)
            assert errors == []
            browser.close()
    finally:
        server.shutdown()
        server.jobs.stop()
        server.server_close()
        origin.close()
