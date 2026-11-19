"""PDF executive report: the dashboard's print layout (overview, top risks, OWASP summary) rendered
by headless Chromium through Playwright. Playwright is optional (`pip install gapscan[pdf]`)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

SYSTEM_BROWSERS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable")


class PdfUnavailable(RuntimeError):
    pass


def launch_chromium(p: Any, extra: tuple[str, ...] = (), **kw: Any) -> Any:
    """Playwright's own Chromium; if that build is missing (a Playwright upgrade without
    `playwright install`), a browser already on the machine: GAPSCAN_CHROMIUM, a Chromium or Chrome
    on PATH, then the Chrome / Edge channels. Raises the first error when none starts."""
    try:
        return p.chromium.launch(**kw)
    except Exception as first:
        paths = [os.environ.get("GAPSCAN_CHROMIUM", ""), *extra]
        paths += [found for name in SYSTEM_BROWSERS if (found := shutil.which(name))]
        for path in paths:
            if path and Path(path).exists():
                try:
                    return p.chromium.launch(executable_path=path, **kw)
                except Exception:  # noqa: BLE001,S112 - try the next one
                    continue
        for channel in ("chrome", "msedge"):
            try:
                return p.chromium.launch(channel=channel, **kw)
            except Exception:  # noqa: BLE001,S112
                continue
        raise first


def render_pdf(html_path: Path, pdf_path: Path) -> Path:
    try:
        from playwright.sync_api import Error, sync_playwright
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise PdfUnavailable(
            "PDF export needs Playwright: `uv sync --extra pdf` then `playwright install chromium`"
        ) from exc
    with sync_playwright() as p:
        try:
            browser = launch_chromium(p)
        except Error as exc:  # pragma: no cover - browser not installed
            raise PdfUnavailable(
                "no Chromium found: run `playwright install chromium`, or set GAPSCAN_CHROMIUM "
                f"to an installed Chromium or Chrome ({str(exc).splitlines()[0]})"
            ) from exc
        try:
            ctx = browser.new_context()
            ctx.set_offline(True)  # the dashboard never needs the network
            page = ctx.new_page()
            page.goto(html_path.resolve().as_uri() + "#/executive")
            page.wait_for_selector("h1")
            page.wait_for_timeout(400)  # charts
            page.emulate_media(media="print")
            page.pdf(path=str(pdf_path), format="A4", print_background=True,
                     margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"})  # fmt: skip
        finally:
            browser.close()
    return pdf_path
