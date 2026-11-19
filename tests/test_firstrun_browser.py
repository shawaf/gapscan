"""Browser test of the first-run journey on a clean server: it opens on the Welcome page by itself, runs the plan from a
local fake download host, then tries the built-in sample project. Skipped without Chromium or the built templates."""

from __future__ import annotations

import threading

import httpx
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


@pytest.fixture
def stack(tmp_path, monkeypatch):
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "no-ollama"))
    monkeypatch.setenv("GAPSCAN_HOME", str(tmp_path / "home"))
    origin = Origin()
    cfg = Config(data={"dir": str(tmp_path / "data")}, scanners={"osv": {"db_dir": str(tmp_path / "o")}, "trivy": {"cache_dir": str(tmp_path / "t")}})  # fmt: skip
    runtime = RuntimeManager(tmp_path / "data", make_manifest(origin), HW)
    server = build_server(cfg, port=0, pipeline=FakePipeline(), runtime=runtime)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with playwright_api.sync_playwright() as p:
        try:
            browser = launch_chromium(p)
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"Chromium unavailable: {exc}")
        page = browser.new_page(viewport={"width": 1280, "height": 1000})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        yield server, page, errors, tmp_path
        browser.close()
    server.shutdown()
    server.jobs.stop()
    server.server_close()
    origin.close()


def test_a_new_user_is_guided_from_setup_to_a_first_scan(stack):
    server, page, errors, tmp_path = stack
    page.goto(server.url())
    page.get_by_role(
        "heading", name="Set up this computer"
    ).wait_for()  # no projects and no welcome yet: it opens here
    text = page.inner_text("main")
    assert (
        "enough for the AI model" in text and "AI engine" in text and "Knowledge-base model" in text
    )
    page.screenshot(path=str(tmp_path / "welcome-start.png"), full_page=True)

    page.get_by_label(
        "Include Security data (vulnerability databases, advisories)"
    ).uncheck()  # no real downloads here
    page.get_by_role("button", name="Set up (").click()
    page.get_by_role("status").get_by_text("You are ready").wait_for(timeout=60_000)
    page.screenshot(path=str(tmp_path / "welcome-ready.png"), full_page=True)

    page.get_by_role("button", name="Try the sample project").click()
    page.get_by_role("heading", name="Runs").wait_for()
    page.get_by_role("cell", name="Succeeded").wait_for(
        timeout=30_000
    )  # the sample project was scanned

    cookies = {c["name"]: c["value"] for c in page.context.cookies()}
    base = f"http://127.0.0.1:{server.port}"
    assert httpx.get(base + "/api/setup", cookies=cookies).json()["welcome"] == "done"
    assert [p["name"] for p in httpx.get(base + "/api/projects", cookies=cookies).json()] == [
        "GapScan sample"
    ]
    page.goto(server.url())  # coming back later starts on the domain picker, not the welcome page
    page.get_by_role("heading", name="What do you want to close gaps against?").wait_for()
    page.get_by_role("button", name="Open Application security, 1 project").click()
    page.get_by_role("heading", name="Application security projects").wait_for()
    assert errors == []


def test_skipping_the_welcome_page_is_remembered(stack):
    server, page, errors, tmp_path = stack
    page.goto(server.url())
    page.get_by_role("heading", name="Welcome to GapScan").wait_for()
    page.get_by_role("button", name="Skip for now").click()
    page.get_by_role(
        "heading", name="Welcome to GapScan"
    ).wait_for()  # the empty project list still says welcome
    cookies = {c["name"]: c["value"] for c in page.context.cookies()}
    assert (
        httpx.get(f"http://127.0.0.1:{server.port}/api/setup", cookies=cookies).json()["welcome"]
        == "skipped"
    )
    page.goto(server.url())
    page.get_by_role(
        "button", name="Open Application security, 0 projects"
    ).click()  # the domain picker, not the wizard
    page.get_by_label(
        "Project folder"
    ).wait_for()  # the add-project form, not a redirect to the wizard
    assert "Set up this computer" not in page.inner_text("main")
    assert errors == []
