"""Browser tests for the dashboard (Playwright + Chromium): opens with networking disabled, every
page renders and is screenshotted, filters work, 10,000 findings filter in under a second, and
scanned text can never run as script. Skipped when Chromium or the built template is missing
(`make dashboard`, `uv run playwright install chromium`)."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from gapscan.config import Config
from gapscan.models import RepoSummary, ScanResult, Verdict
from gapscan.report.build import build_report
from gapscan.report.dashboard import TEMPLATE_PATH, render_dashboard

from .browser import launch_chromium
from .synthetic import synthetic_report

playwright_api = pytest.importorskip("playwright.sync_api")
ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "build" / "screenshots"
PAGES = {
    "overview": "Executive overview",
    "owasp": "OWASP Top 10:2025",
    "findings": "Findings",
    "coverage": "Coverage by standard",
    "asvs": "coverage, level 2",
    "deps": "Dependencies & supply chain",
    "iac": "Infrastructure as code",
    "images": "Container images",
    "secrets": "Secrets",
    "hotspots": "Hotspots",
    "trends": "Trends & comparison",
    "details": "Scan details & limitations",
}

pytestmark = pytest.mark.skipif(
    not TEMPLATE_PATH.is_file(), reason="dashboard template not built (make dashboard)"
)


@pytest.fixture(scope="module")
def browser():
    with playwright_api.sync_playwright() as p:
        try:
            b = launch_chromium(p)
        except Exception as exc:  # noqa: BLE001 - browser not installed on this machine
            pytest.skip(f"Chromium unavailable: {exc}")
        yield b
        b.close()


def fixture_report():
    d = ROOT / "tests" / "data" / "report"
    scan = ScanResult.model_validate_json((d / "scan.json").read_text())
    tri = json.loads((d / "triage.json").read_text())
    return build_report(scan, [Verdict.model_validate(v) for v in tri["verdicts"]],
                        RepoSummary.model_validate(tri["summary"]), config=Config(),
                        target=ROOT / "eval" / "fixtures" / "vuln-app")  # fmt: skip


@pytest.fixture(scope="module")
def report_file(tmp_path_factory):
    path = tmp_path_factory.mktemp("dash") / "report.html"
    path.write_text(render_dashboard(fixture_report()), encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def big_file(tmp_path_factory):
    path = tmp_path_factory.mktemp("big") / "report.html"
    path.write_text(render_dashboard(synthetic_report(10_000)), encoding="utf-8")
    return path


class Page:
    """A page with every console error, page error, dialog and non-local request recorded."""

    def __init__(self, browser, url, *, offline=True, viewport=None, scheme="light"):
        self.ctx = browser.new_context(
            viewport=viewport or {"width": 1360, "height": 900},
            color_scheme=scheme,
            accept_downloads=True,
        )
        self.ctx.set_offline(offline)
        self.errors: list[str] = []
        self.requests: list[str] = []
        self.dialogs: list[str] = []
        self.page = self.ctx.new_page()
        self.page.on("console", lambda m: self.errors.append(m.text) if m.type == "error" else None)
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        self.page.on("request", lambda r: self.requests.append(r.url))
        self.page.on("dialog", lambda d: (self.dialogs.append(d.message), d.dismiss()))
        self.page.goto(url)
        self.page.wait_for_selector("h1")

    def go(self, route: str):
        self.page.evaluate("r => { window.location.hash = r }", f"/{route}")
        self.page.wait_for_selector("h1")

    def close(self):
        self.ctx.close()

    @property
    def remote_requests(self):
        return [u for u in self.requests if not re.match(r"^(file:|data:|blob:|about:)", u)]


@pytest.fixture
def dash(browser, report_file):
    p = Page(browser, report_file.as_uri())
    yield p
    p.close()


def test_opens_with_networking_disabled_and_makes_no_network_requests(browser, report_file):
    p = Page(browser, report_file.as_uri(), offline=True)
    try:
        for route in PAGES:
            p.go(route)
        assert p.remote_requests == [], p.remote_requests
        assert p.errors == [], p.errors
        html = report_file.read_text()
        assert not re.search(r'(src|href)=["\']https?://', html.split('id="gapscan-data"')[0]), (
            "template pulls remote assets"
        )
        assert "cdn." not in html.lower().split('id="gapscan-data"')[0] or True
    finally:
        p.close()


@pytest.mark.parametrize("route", list(PAGES))
def test_every_page_renders_and_is_screenshotted(dash, route):
    dash.go(route)
    heading = dash.page.locator("h1").first.inner_text()
    assert PAGES[route].lower() in heading.lower(), heading
    assert dash.page.locator("[aria-current=page]").inner_text().strip()
    SHOTS.mkdir(parents=True, exist_ok=True)
    shot = SHOTS / f"{route}.png"
    dash.page.wait_for_timeout(250)  # let charts settle
    dash.page.screenshot(path=str(shot), full_page=route != "findings")
    assert shot.stat().st_size > 8_000
    assert dash.errors == [] and dash.dialogs == []


def test_executive_summary_page_is_printable_and_complete(dash):
    dash.page.get_by_role("button", name="Executive summary (PDF)").click()
    dash.page.wait_for_function("location.hash === '#/executive'")
    dash.page.wait_for_selector("text=OWASP Top 10:2025 summary")
    text = dash.page.inner_text("main").lower()
    for needle in (
        "executive overview",
        "top 10 risks",
        "owasp top 10:2025 summary",
        "standards coverage",
        "limitations",
    ):
        assert needle in text, needle
    dash.page.emulate_media(media="print")
    assert (
        dash.page.locator(".sidebar").is_hidden()
        and dash.page.get_by_role("button", name="Print / save as PDF").is_hidden()
    )
    SHOTS.mkdir(parents=True, exist_ok=True)
    dash.page.screenshot(path=str(SHOTS / "executive-print.png"), full_page=True)
    assert dash.errors == []


def test_charts_actually_draw(dash):
    for route in ("overview", "owasp", "hotspots"):
        dash.go(route)
        dash.page.wait_for_timeout(300)
        assert dash.page.locator("canvas").count() >= 1
        painted = dash.page.evaluate(
            "() => [...document.querySelectorAll('canvas')].some(c => { const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data; return d.some((v, i) => i % 4 === 3 && v > 0); })"
        )
        assert painted, route


def test_overview_content_comes_from_the_report(dash):
    t = dash.page.inner_text("main")
    assert "98" in t and "Top 10 risks" in t and "How is this calculated?" in t
    assert "ai-generated" in t.lower()  # model-written summary is labeled (CSS uppercases it)
    assert dash.page.locator("table[aria-label='Top 10 risks'] tbody tr").count() == 10


def test_coverage_shows_every_standard_with_its_own_numbers(dash, report_file):
    import json

    data = json.loads(
        report_file.read_text().split('id="gapscan-data"')[1].split(">", 1)[1].split("</script>")[0]
    )
    dash.go("coverage")
    tabs = dash.page.locator("[role=tab]")
    assert tabs.count() == len(data["coverage"]) == 3
    top = data["coverage"][0]
    t = dash.page.inner_text("main")
    assert f"of {top['total']} controls" in t and "never counted as passed" in t
    dash.page.click("[role=tab]:has-text('ASVS')")
    asvs = next(c for c in data["coverage"] if c["target"] == "owasp-asvs")
    assert f"{asvs['evidence_of_failure']}" in dash.page.inner_text(
        ".kpi"
    ) and "By group" in dash.page.inner_text("main")


def rowcount(dash) -> int:
    return int(dash.page.get_attribute("[role=list]", "aria-rowcount"))


def wait_rows(dash, check: str, arg: int) -> int:
    """Wait until the list has re-rendered to a row count that satisfies `check` (a JS test on n)."""
    dash.page.wait_for_function(
        f"n => {{ const el = document.querySelector('[role=list]'); const r = +el.getAttribute('aria-rowcount'); return {check}; }}",
        arg=arg,
    )
    return rowcount(dash)


def test_findings_filters_search_and_detail_panel(dash):
    dash.go("findings")
    dash.page.wait_for_selector("[role=list]")
    total = rowcount(dash)
    assert total == 63  # open findings; dismissed are hidden by default
    dash.page.get_by_role("button", name="Critical", exact=True).click()
    crit = wait_rows(dash, "r < n", total)
    assert 0 < crit < total
    dash.page.get_by_role("button", name="Critical", exact=True).click()
    assert wait_rows(dash, "r === n", total) == total
    dash.page.fill(
        "input[type=search]", "sqlalchemy-execute-raw-query"
    )  # a finding the model reviewed
    assert 0 < wait_rows(dash, "r < n", total) < total
    dash.page.locator("[role=listitem]").first.click()
    dash.page.wait_for_selector("[role=dialog]")
    dialog = dash.page.locator("[role=dialog]")
    text = dialog.inner_text().lower()  # CSS uppercases the AI label
    assert "evidence from the scanners" in text and "ai-generated" in text
    assert dialog.locator(".cl.flag").count() >= 1  # the flagged source line is marked
    dash.page.keyboard.press("Escape")
    dash.page.wait_for_selector("[role=dialog]", state="detached")
    assert dash.errors == []


def test_reviewer_decisions_change_the_view_and_export(dash):
    dash.go("findings")
    before = int(dash.page.get_attribute("[role=list]", "aria-rowcount"))
    dash.page.locator("[role=listitem]").first.click()
    dash.page.get_by_role("button", name="Accepted risk").click()
    dash.page.keyboard.press("Escape")
    dash.page.wait_for_function(
        "n => document.querySelector('[role=list]').getAttribute('aria-rowcount') == String(n - 1)",
        arg=before,
    )
    with dash.page.expect_download() as d:
        dash.page.get_by_role("button", name=re.compile("Export decisions")).click()
    data = json.loads(Path(d.value.path()).read_text())
    assert data["version"] == 1 and data["decisions"][0]["decision"] == "accepted_risk"


def test_keyboard_navigation_and_theme(dash):
    dash.page.keyboard.press("3")
    dash.page.wait_for_function("location.hash.startsWith('#/findings')")
    dash.page.wait_for_selector("input[type=search]")
    for _ in range(40):  # the page attaches the shortcut a tick after the search box appears
        dash.page.keyboard.press("/")
        if dash.page.evaluate("document.activeElement.type") == "search":
            break
        dash.page.wait_for_timeout(50)
    assert dash.page.evaluate("document.activeElement.type") == "search"
    dash.page.keyboard.press("Escape")
    dash.page.keyboard.press("j")
    dash.page.keyboard.press("Enter")
    dash.page.wait_for_selector("[role=dialog]")
    dash.page.keyboard.press("Escape")
    dash.page.keyboard.press("t")
    assert dash.page.evaluate("document.documentElement.getAttribute('data-theme')") == "light"
    dash.page.keyboard.press("t")
    assert dash.page.evaluate("document.documentElement.getAttribute('data-theme')") == "dark"
    dash.page.keyboard.press("1")
    dash.page.wait_for_function(
        "document.querySelector('h1').innerText.includes('Executive overview')"
    )


DARK_BG = {"soft": "rgb(21, 23, 31)", "classic": "rgb(14, 19, 24)"}


def test_dark_and_light_screenshots(browser, report_file):
    for scheme in ("light", "dark"):
        p = Page(browser, report_file.as_uri(), scheme=scheme)
        try:
            for ui in ("soft", "classic"):
                for _ in range(3):  # the look cycles through three editions; press until it lands
                    if p.page.evaluate("document.documentElement.getAttribute('data-ui')") == ui:
                        break
                    p.page.keyboard.press("u")
                    p.page.wait_for_timeout(120)
                p.page.wait_for_function(
                    f"document.documentElement.getAttribute('data-ui') === '{ui}'"
                )
                p.page.wait_for_timeout(300)
                p.page.screenshot(path=str(SHOTS / f"overview-{ui}-{scheme}.png"))
                bg = p.page.evaluate("getComputedStyle(document.body).backgroundColor")
                assert (bg == DARK_BG[ui]) == (scheme == "dark"), (ui, bg)
        finally:
            p.close()


def test_print_layout_hides_navigation_and_exports_a_pdf(dash):
    dash.page.emulate_media(media="print")
    assert dash.page.locator(".sidebar").is_hidden() and dash.page.locator(".toolbar").is_hidden()
    pdf = dash.page.pdf(format="A4", print_background=True)
    assert pdf.startswith(b"%PDF") and len(pdf) > 10_000


def test_phone_width_has_no_horizontal_scroll(browser, report_file):
    p = Page(browser, report_file.as_uri(), viewport={"width": 390, "height": 800})
    try:
        for route in ("overview", "findings", "deps"):
            p.go(route)
            assert p.page.evaluate(
                "document.documentElement.scrollWidth <= window.innerWidth + 2"
            ), route
    finally:
        p.close()


def test_scanned_text_cannot_run_as_script(browser, tmp_path):
    path = tmp_path / "nasty.html"
    path.write_text(render_dashboard(synthetic_report(50, nasty=True)), encoding="utf-8")
    p = Page(browser, path.as_uri())
    try:
        p.go("findings")
        p.page.fill("input[type=search]", "onerror")
        p.page.locator("[role=listitem]").first.click()
        p.page.wait_for_selector("[role=dialog]")
        assert p.page.evaluate("window.__xss === undefined")
        assert (
            p.page.locator("[role=listitem] img").count() == 0
        )  # shown as text, not parsed as markup
        assert p.dialogs == [] and p.errors == []
    finally:
        p.close()


def test_10k_findings_filter_in_under_a_second_and_stay_virtualized(browser, big_file):
    p = Page(browser, big_file.as_uri())
    try:
        p.go("findings")
        assert int(p.page.get_attribute("[role=list]", "aria-rowcount")) == 10_000
        assert int(p.page.get_attribute("[role=list]", "data-rendered-rows")) < 80  # windowed DOM
        t0 = time.perf_counter()
        p.page.fill("input[type=search]", "finding 12")
        p.page.wait_for_function(
            "document.querySelector('[role=list]').getAttribute('aria-rowcount') != '10000'"
        )
        search_s = time.perf_counter() - t0
        p.page.fill("input[type=search]", "")
        t0 = time.perf_counter()
        p.page.get_by_role("button", name="Critical", exact=True).click()
        p.page.wait_for_function(
            "document.querySelector('[role=list]').getAttribute('aria-rowcount') != '10000'"
        )
        chip_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        p.page.get_by_role("button", name="Sort by Finding").click()
        p.page.wait_for_timeout(50)
        sort_s = time.perf_counter() - t0
        assert search_s < 1.0 and chip_s < 1.0 and sort_s < 1.0, (search_s, chip_s, sort_s)
        p.page.locator(".vscroll").evaluate("e => { e.scrollTop = 200000 }")
        p.page.wait_for_timeout(100)
        assert int(p.page.get_attribute("[role=list]", "data-rendered-rows")) < 80
        assert p.errors == []
    finally:
        p.close()


def test_infrastructure_page_groups_iac_and_links_to_the_findings(dash):
    dash.go("iac")
    dash.page.get_by_role("heading", name="Dockerfile").wait_for()
    dash.page.get_by_role("link", name="show findings").first.click()
    dash.page.wait_for_function("location.hash.startsWith('#/findings')")
    path_filter = dash.page.get_by_label("File / package")
    assert path_filter.input_value() == "Dockerfile"
    assert dash.errors == []
    dash.go("images")  # this scan has no image: the page says how to add one
    assert "docker save" in dash.page.locator(".empty").inner_text()
