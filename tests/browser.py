"""Start Chromium for the browser tests with the same fallbacks as the PDF export, plus the
image-provided /opt/pw-browsers/chromium, so a version mismatch between the Playwright package and
the installed browser does not silently skip tests."""

from __future__ import annotations

from typing import Any

from gapscan.report.exports.pdf import launch_chromium as _launch

FALLBACKS = ("/opt/pw-browsers/chromium",)


def launch_chromium(p: Any, **kw: Any) -> Any:
    return _launch(p, FALLBACKS, **kw)
