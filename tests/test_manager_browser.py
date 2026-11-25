"""Browser test of the Control Center against a real server with the recorded fixture scan: add a
project, start a run from the Runs page, watch it finish, read the Overview, make a decision in the
Findings explorer (checked on the server), and manage team memories. Skipped without Chromium or
the built templates (`make dashboard manager`)."""

from __future__ import annotations

import threading
import time

import httpx
import pytest

from gapscan.config import Config
from gapscan.report.dashboard import TEMPLATE_PATH
from gapscan.server import build_server
from gapscan.server.app import TEMPLATE as MANAGER_TEMPLATE

from .browser import launch_chromium
from .test_server import FakePipeline

playwright_api = pytest.importorskip("playwright.sync_api")
MANAGER = MANAGER_TEMPLATE
pytestmark = pytest.mark.skipif(
    not (TEMPLATE_PATH.is_file() and MANAGER.is_file()),
    reason="templates not built (make dashboard manager)",
)
ALL_AVAILABLE = [
    {"name": n, "description": f"{n} scanner", "available": True, "version": "1.0", "default": True}
    for n in ("semgrep", "osv", "trivy", "gitleaks", "checkov", "bandit")
]


@pytest.fixture
def stack(tmp_path):
    cfg = Config(
        data={"dir": str(tmp_path / "data")},
        scanners={
            "osv": {"db_dir": str(tmp_path / "o")},
            "trivy": {"cache_dir": str(tmp_path / "t")},
        },
    )
    pipeline = FakePipeline()
    server = build_server(cfg, port=0, pipeline=pipeline)
    server.runtime.set_welcome(
        "skipped"
    )  # these tests start from the project list, not the first-run welcome page
    server.scanner_cache = (
        time.monotonic() + 1e6,
        ALL_AVAILABLE,
    )  # the tools need not be installed here
    threading.Thread(target=server.serve_forever, daemon=True).start()
    project = tmp_path / "myapp"
    project.mkdir()
    (project / "app.py").write_text("print('hi')\n")
    with playwright_api.sync_playwright() as p:
        try:
            browser = launch_chromium(p)
        except Exception as exc:  # noqa: BLE001 - browser not installed here
            pytest.skip(f"Chromium unavailable: {exc}")
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        yield server, page, project, errors
        browser.close()
    server.shutdown()
    server.jobs.stop()
    server.server_close()


def test_add_project_run_read_results_decide_and_remember(stack):
    server, page, project, errors = stack
    page.goto(server.url())  # the token handshake sets the cookie and drops the token from the URL
    page.get_by_role("heading", name="Welcome to GapScan").wait_for()  # the Projects landing, empty
    assert "token" not in page.url
    page.get_by_role(
        "button", name="Add your first project"
    ).click()  # opens the create-project wizard
    page.get_by_label("Project folder").fill(str(project))
    page.get_by_role("button", name="Add project").click()
    page.get_by_role("heading", name="Runs").wait_for()

    # start a run: the live card, then the history row
    page.get_by_role("button", name="Start run").click()
    page.get_by_role("cell", name="Succeeded").wait_for(timeout=30_000)
    assert page.get_by_role("row").filter(has_text="#1").count() >= 1

    # open the run drawer: pipeline, scanners and the log
    page.get_by_role("link", name="#1").click()
    drawer = page.get_by_role("dialog", name="Details")
    drawer.get_by_text("Scanner", exact=True).wait_for()
    assert "done: risk" in drawer.inner_text()
    page.keyboard.press("Escape")
    drawer.wait_for(state="detached")

    # overview of the finished run
    page.get_by_role("link", name="Overview").click()
    page.get_by_role("heading", name="myapp").wait_for()
    page.get_by_role("region", name="Open gaps").wait_for()
    assert page.get_by_role("region", name="Fix first").count() == 1

    # findings explorer: a decision made in the drawer is saved by the server
    page.locator(".cc-nav").get_by_role("link", name="Gaps").click()
    page.get_by_role("heading", name="Gaps", exact=True).wait_for()
    page.locator("[role=listitem]").first.click()
    dialog = page.locator("[role=dialog]")
    assert dialog.get_by_role(
        "button", name="Accept risk"
    ).is_disabled()  # a note is required first
    dialog.get_by_label("Decision note").fill("internal tool, accepted until the next release")
    dialog.get_by_role("button", name="Accept risk").click()
    page.wait_for_timeout(300)
    cookies = {c["name"]: c["value"] for c in page.context.cookies()}
    rows = httpx.get(
        f"http://127.0.0.1:{server.port}/api/projects/1/decisions", cookies=cookies
    ).json()
    assert (
        len(rows) == 1
        and rows[0]["decision"] == "accepted_risk"
        and "internal tool" in rows[0]["note"]
    )
    assert "Run #1" in dialog.inner_text()  # history across runs
    page.keyboard.press("Escape")

    # settings: team memories
    page.get_by_role("link", name="Settings").click()
    page.get_by_role("heading", name="Settings").wait_for()
    page.get_by_label("Memory note").fill("the logs folder is never deployed to production")
    page.get_by_label("Memory folder").fill("src/logs")
    page.get_by_role("button", name="Add memory").click()
    page.get_by_text("the logs folder is never deployed to production").wait_for()
    # the decision with a note made earlier already became a memory
    page.get_by_text("internal tool, accepted until the next release").wait_for()
    mine = page.get_by_role("row").filter(has_text="the logs folder is never deployed")
    mine.get_by_role("button", name="Disable").click()
    mine.get_by_role("button", name="Enable").wait_for()
    mine.get_by_role("button", name="Delete").click()
    page.get_by_text("the logs folder is never deployed to production").wait_for(state="detached")
    assert errors == []


def test_findings_explorer_views_filters_bulk_decisions_and_saved_views(stack):
    server, page, project, errors = stack
    page.goto(server.url())
    page.get_by_role("heading", name="Welcome to GapScan").wait_for()  # the Projects landing, empty
    page.get_by_role(
        "button", name="Add your first project"
    ).click()  # opens the create-project wizard
    page.get_by_label("Project folder").fill(str(project))
    page.get_by_role("button", name="Add project").click()
    page.get_by_role("button", name="Start run").click()
    page.get_by_role("cell", name="Succeeded").wait_for(timeout=30_000)
    page.locator(".cc-nav").get_by_role("link", name="Gaps").click()
    page.get_by_role("heading", name="Gaps", exact=True).wait_for()
    rows = page.locator("[role=listitem]")
    total = int(page.get_attribute("[role=list]", "aria-rowcount"))
    assert total == 63 and rows.count() > 5

    page.get_by_role("button", name="More filters").click()
    # a saved view narrows the list, and the tab shows the count
    page.get_by_role("tab", name="Critical and High").click()
    n = int(page.get_attribute("[role=list]", "aria-rowcount"))
    assert 0 < n < total
    assert (
        page.get_by_role("tab", name="Critical and High").get_attribute("aria-selected") == "true"
    )

    # a dropdown filter adds a chip that can be removed
    page.get_by_role("tab", name="All open").click()
    page.get_by_role("button", name="Severity", exact=True).click()
    page.get_by_label("Critical").check()
    page.keyboard.press("Escape")
    chip = page.locator(".fx-chip", has_text="Severity: Critical")
    chip.wait_for()
    page.get_by_role("button", name="Remove filter Severity: Critical").click()
    chip.wait_for(state="detached")
    assert int(page.get_attribute("[role=list]", "aria-rowcount")) == total

    # bulk decision: select two rows, the dialog asks for a note
    boxes = page.locator(".fx-item input[type=checkbox]")
    boxes.nth(0).check()
    boxes.nth(1).check()
    page.get_by_text("2 selected").wait_for()
    page.get_by_role("button", name="Mark false positive").click()
    save = page.get_by_role("button", name="Mark false positive").last
    assert save.is_disabled()  # a note is required
    page.get_by_label("Decision note").fill("values here come from our own config, not from users")
    save.click()
    page.wait_for_timeout(500)
    cookies = {c["name"]: c["value"] for c in page.context.cookies()}
    base = f"http://127.0.0.1:{server.port}/api/projects/1"
    decisions = httpx.get(f"{base}/decisions", cookies=cookies).json()
    assert len(decisions) == 2 and {d["decision"] for d in decisions} == {"false_positive"}
    assert all("our own config" in d["note"] for d in decisions)
    memories = httpx.get(f"{base}/memories", cookies=cookies).json()
    assert (
        len(memories) >= 1 and memories[0]["kind"] == "false_positive"
    )  # the note became a memory
    assert (
        int(page.get_attribute("[role=list]", "aria-rowcount")) == total - 2
    )  # dismissed rows leave the open list

    # keyboard: j moves, Enter opens the drawer, Escape closes it
    page.locator("body").click(position={"x": 5, "y": 5})
    page.keyboard.press("j")
    page.keyboard.press("Enter")
    page.locator("[role=dialog]").wait_for()
    page.keyboard.press("Escape")
    page.locator("[role=dialog]").wait_for(state="detached")

    # save the current view and find it again as a tab
    page.get_by_role("button", name="Severity", exact=True).click()
    page.get_by_label("High", exact=True).check()
    page.keyboard.press("Escape")
    page.get_by_role("button", name="Save current view").click()
    page.get_by_label("View name").fill("High only")
    page.get_by_role("button", name="Save view").click()
    page.get_by_role("tab", name="All open").click()
    page.get_by_role("tab", name="High only").click()
    assert page.get_by_role("tab", name="High only").get_attribute("aria-selected") == "true"
    assert errors == []


def test_every_rebuilt_page_opens_and_a_project_is_deleted_with_a_typed_confirmation(stack):
    server, page, project, errors = stack
    page.goto(server.url())
    page.get_by_role("heading", name="Welcome to GapScan").wait_for()  # the Projects landing, empty
    page.get_by_role(
        "button", name="Add your first project"
    ).click()  # opens the create-project wizard
    page.get_by_label("Project folder").fill(str(project))
    page.get_by_role("button", name="Add project").click()
    for n in (1, 2):  # two finished runs, so Compare has something to compare
        page.get_by_role(
            "button", name="Start run" if n == 1 else "Add to queue"
        ).click() if n == 1 else page.get_by_role("button", name="Start run").click()
        page.get_by_role("cell", name="Succeeded").nth(n - 1).wait_for(timeout=40_000)

    # OWASP heat view: a tile opens the findings of that category
    page.get_by_role("link", name="OWASP Top 10").click()
    page.get_by_role("heading", name="OWASP Top 10:2025").wait_for()
    page.get_by_role("button", name="A05:2025 Injection", exact=False).click()
    page.locator(".fx-chip", has_text="OWASP: A05:2025").wait_for()

    page.get_by_role("link", name="ASVS").click()
    page.get_by_role("heading", name="ASVS", exact=False).wait_for()
    page.get_by_role("region", name="Needs a person").wait_for()
    page.locator(".chapter-row").first.click()
    page.locator("tr.req").first.wait_for()
    page.keyboard.press("Escape")
    page.get_by_role("dialog").wait_for(state="detached")

    page.get_by_role("link", name="Dependencies").click()
    page.get_by_role("heading", name="Dependencies").wait_for()
    page.get_by_role("tab", name="Upgrade plan").click()
    page.get_by_role("tab", name="SBOM").click()

    page.get_by_role("link", name="Secrets and Config").click()
    page.get_by_text("Secret values are never stored or shown").wait_for()

    page.get_by_role("link", name="Hotspots").click()
    page.get_by_role("heading", name="Hotspots").wait_for()
    page.locator(".tm").first.click()
    page.locator(".fx-chip", has_text="Path:").wait_for()

    page.get_by_role("link", name="Overview").click()
    page.get_by_role("link", name="Compare").click()
    page.get_by_role("heading", name="Compare").wait_for()
    page.get_by_text("Trend over the last runs").wait_for()
    assert (
        page.get_by_label("Baseline run (older)").count() == 1
        or page.locator("select").count() == 2
    )

    page.get_by_role("link", name="System Health").click()
    page.get_by_role("heading", name="System Health").wait_for()
    page.get_by_role("heading", name="Checklist").wait_for()
    page.get_by_text("Data freshness").wait_for()
    page.get_by_role("heading", name="Model manager").wait_for()

    # the score explanation
    page.get_by_role("link", name="Overview").click()
    page.get_by_role("link", name="How is this calculated?").click()
    page.get_by_role("dialog").get_by_text("How the risk score is calculated").wait_for()
    page.keyboard.press("Escape")

    # deleting a project needs its name typed
    page.goto(server.url().split("?")[0].rstrip("/") + "/#/security")
    page.get_by_role("button", name="Delete project myapp").click()
    confirm = page.get_by_role("alertdialog").get_by_role("button", name="Delete project")
    assert confirm.is_disabled()
    page.get_by_label("Type the project name to confirm").fill("myapp")
    confirm.click()
    page.get_by_role("heading", name="Welcome to GapScan").wait_for()
    assert errors == []


def test_dry_run_archive_and_model_benchmark(stack, monkeypatch):
    server, page, project, errors = stack
    best = Config().llm.all_profiles["best"].model
    monkeypatch.setattr(
        "gapscan.server.app.LLMClient.list_models",
        lambda self: [{"name": best, "size_gb": 18.0, "params": "30B", "quant": "Q4"}],
    )
    page.goto(server.url())
    page.get_by_role("heading", name="Welcome to GapScan").wait_for()  # the Projects landing, empty
    page.get_by_role(
        "button", name="Add your first project"
    ).click()  # opens the create-project wizard
    page.get_by_label("Project folder").fill(str(project))
    page.get_by_role("button", name="Add project").click()
    page.get_by_role("heading", name="Runs").wait_for()

    # dry run: shows a plan and changes nothing
    page.get_by_role("radio", name="Dry run").click()
    page.get_by_text("Dry run lists what would execute and changes nothing.").wait_for()
    page.get_by_role("button", name="Show the plan").click()
    page.get_by_role("cell", name="Succeeded").wait_for(timeout=30_000)
    page.get_by_role("link", name="#1").click()
    drawer = page.get_by_role("dialog", name="Details")
    drawer.get_by_text("This is a plan, not a result").wait_for()
    assert "scanners would run" in drawer.inner_text()
    page.keyboard.press("Escape")
    assert server.jobs.pipeline.scanned == []  # no scanner was started
    assert page.get_by_text("Grade").count() == 0  # a dry run has no score

    # archive and restore from the projects page
    page.goto(server.url().split("?")[0].rstrip("/") + "/#/security")
    page.get_by_role("button", name="Archive project myapp").click()
    page.get_by_role("button", name="Archived projects", exact=False).click()
    page.get_by_role("button", name="Restore project myapp").click()
    page.get_by_role("button", name="Archive project myapp").wait_for()

    # model benchmark from System Health, through the queue
    page.goto(server.url().split("?")[0].rstrip("/") + "/#/p/1/health")
    page.get_by_role("heading", name="Model manager").wait_for()
    page.get_by_role("button", name="Benchmark this model").first.click()
    page.get_by_text("3 of 4 match").wait_for(timeout=30_000)
    assert errors == []


def test_switching_project_replaces_the_data_that_is_shown(stack):
    server, page, project, errors = stack
    second = project.parent / "other"
    second.mkdir()
    (second / "x.py").write_text("print('x')\n")
    page.goto(server.url())
    page.get_by_role("heading", name="Welcome to GapScan").wait_for()  # the Projects landing, empty
    page.get_by_role(
        "button", name="Add your first project"
    ).click()  # opens the create-project wizard
    page.get_by_label("Project folder").fill(str(project))
    page.get_by_role("button", name="Add project").click()
    page.get_by_role("button", name="Start run").click()
    page.get_by_role("cell", name="Succeeded").wait_for(timeout=30_000)
    page.get_by_role("link", name="Overview").click()
    page.get_by_role("region", name="Fix first").wait_for()

    # a second project that was never scanned: its page must not show the first project's results
    page.get_by_role("link", name="All projects").click()
    page.get_by_role("button", name="New project").click()  # opens the create-project wizard
    page.get_by_label("Project folder").fill(str(second))
    page.get_by_role("button", name="Add project").click()
    page.get_by_role("heading", name="Runs").wait_for()
    page.get_by_role("link", name="Overview").click()
    page.get_by_role("heading", name="No scans yet for other").wait_for()
    assert page.get_by_role("region", name="Fix first").count() == 0

    # and back: the first project's results return, not the empty page
    page.get_by_role("link", name="Open myapp").click()
    page.get_by_role("region", name="Fix first").wait_for()
    page.locator(".cc-nav").get_by_role("link", name="Gaps").click()
    page.locator("[role=listitem]").first.wait_for()
    page.get_by_role("link", name="Open other").click()
    page.wait_for_timeout(600)
    assert page.locator("[role=listitem]").count() == 0
    assert not errors


def test_the_look_is_saved_per_project_and_defaults_to_midnight(stack):
    server, page, project, errors = stack
    page.goto(server.url())
    page.get_by_role("button", name="Add your first project").click()
    page.get_by_label("Project folder").fill(str(project))
    page.get_by_role("button", name="Add project").click()
    page.get_by_role("heading", name="Runs").wait_for()
    pid = page.url.split("/p/")[1].split("/")[0]
    looks = "() => Object.fromEntries(Object.entries(localStorage).filter(([k]) => k.startsWith('gapscan.ui')))"
    assert page.evaluate(looks) == {}
    page.locator("main").click()
    page.keyboard.press("u")  # midnight, the default, steps to gapscan for this project only
    page.wait_for_function(
        "() => Object.keys(localStorage).some((k) => k.startsWith('gapscan.ui'))"
    )
    assert page.evaluate(looks) == {f"gapscan.ui.{pid}": "gapscan"}
    assert errors == []
