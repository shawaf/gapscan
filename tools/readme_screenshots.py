"""Regenerate the README screenshots in docs/images/ from recorded data (no scanners, no model).

The report pages are rendered from tests/data/report (a real scan of eval/fixtures/vuln-app with
recorded AI verdicts); the local app runs the demo pipeline from tools/demo_manager.py. Both use the
default GapScan look, in the dark theme, at 2x for sharp images.

    uv run python tools/readme_screenshots.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

from playwright.sync_api import sync_playwright

from gapscan.config import Config
from gapscan.llm.client import LLMClient
from gapscan.models import RepoSummary, ScanResult, Verdict
from gapscan.report.build import build_report
from gapscan.report.dashboard import render_dashboard
from gapscan.server import build_server

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "images"
DATA = ROOT / "tests" / "data" / "report"
VIEW = {"width": 1440, "height": 900}

sys.path.insert(0, str(ROOT / "tools"))
from demo_manager import DemoPipeline  # type: ignore[import-not-found]  # noqa: E402


def report_html(tmp: Path) -> Path:
    scan = ScanResult.model_validate_json((DATA / "scan.json").read_text())
    tri = json.loads((DATA / "triage.json").read_text())
    report = build_report(scan, [Verdict.model_validate(v) for v in tri["verdicts"]],
                          RepoSummary.model_validate(tri["summary"]), config=Config(),
                          target=ROOT / "eval" / "fixtures" / "vuln-app")  # fmt: skip
    path = tmp / "report.html"
    path.write_text(render_dashboard(report), encoding="utf-8")
    return path


def shoot_report(browser: Any, path: Path) -> None:
    ctx = browser.new_context(viewport=VIEW, color_scheme="dark", device_scale_factor=2)
    page = ctx.new_page()
    page.goto(path.as_uri())
    page.wait_for_selector("h1")
    for route, name in (("overview", "report-overview"), ("coverage", "report-coverage"),
                        ("deps", "report-dependencies"), ("owasp", "report-owasp"),
                        ("secrets", "report-secrets"), ("hotspots", "report-hotspots"),
                        ("findings", "report-findings")):  # fmt: skip
        page.evaluate("r => { window.location.hash = r }", f"/{route}")
        page.wait_for_selector("h1")
        page.wait_for_timeout(500)
        page.screenshot(path=str(OUT / f"{name}.png"))
    page.keyboard.press("j")
    page.keyboard.press("Enter")
    page.wait_for_selector("[role=dialog]")
    page.wait_for_timeout(400)
    page.screenshot(path=str(OUT / "report-gap-detail.png"))
    ctx.close()
    light = browser.new_context(viewport=VIEW, color_scheme="light", device_scale_factor=2)
    page = light.new_page()
    page.goto(path.as_uri())
    page.wait_for_selector("h1")
    page.wait_for_timeout(500)
    page.screenshot(path=str(OUT / "report-overview-light.png"))
    light.close()


def shoot_manager(browser: Any, tmp: Path) -> None:
    app = tmp / "code" / "payments-api"
    shutil.copytree(ROOT / "eval" / "fixtures" / "vuln-app", app)
    cfg = Config(data={"dir": str(tmp / "data")},
                 scanners={"osv": {"db_dir": str(tmp / "o")}, "trivy": {"cache_dir": str(tmp / "t")}})  # fmt: skip
    # The demo pipeline stands in for the model, so the app should not warn that Ollama is down.
    model = cfg.llm.all_profiles[cfg.llm.profile].model
    LLMClient.list_models = lambda self: [{"name": model, "size_gb": 18.6}]  # type: ignore[method-assign]
    server = build_server(cfg, port=0, pipeline=DemoPipeline(0.01))
    project = server.db.add_project("payments-api", str(app))
    for _ in range(2):
        server.jobs.submit(server.db.create_scan(project["id"], {"triage": True, "limit": 12}))
        server.jobs.wait_idle(120)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ctx = browser.new_context(viewport=VIEW, color_scheme="dark", device_scale_factor=2)
        page = ctx.new_page()
        page.goto(server.url())
        page.wait_for_selector("h1")
        base = server.url().split("#")[0]
        for route, name in ((f"/p/{project['id']}/overview", "manager-overview"),
                            (f"/p/{project['id']}/findings", "manager-gaps"),
                            (f"/p/{project['id']}/asvs", "manager-asvs")):  # fmt: skip
            page.goto(f"{base}#{route}")
            page.wait_for_selector("h1")
            page.wait_for_timeout(800)
            page.screenshot(path=str(OUT / f"{name}.png"))
        ctx.close()
    finally:
        server.shutdown()
        server.jobs.stop()
        server.server_close()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gapscan-shots-") as t, sync_playwright() as p:
        tmp = Path(t)
        browser = p.chromium.launch()
        shoot_report(browser, report_html(tmp))
        shoot_manager(browser, tmp)
        browser.close()
    for f in sorted(OUT.glob("*.png")):
        print(f.relative_to(ROOT))


if __name__ == "__main__":
    main()
