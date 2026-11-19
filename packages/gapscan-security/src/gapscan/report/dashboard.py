"""Inject the report data into the prebuilt single-file dashboard template.

The template is produced by `make dashboard` (Vite + Preact, everything inlined, no network).
The data goes in as one JSON blob in a <script type="application/json"> element."""

from __future__ import annotations

from pathlib import Path

from .schema import ReportData

TEMPLATE_PATH = Path(__file__).parent / "templates" / "dashboard.html"
PLACEHOLDER = "<!--GAPSCAN_DATA-->"


class TemplateMissing(RuntimeError):
    pass


def embed_json(payload: str) -> str:
    """Make JSON safe inside an HTML <script> element: no `</script>`, no `<!--`, no U+2028."""
    return payload.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def render_dashboard(data: ReportData, template: str | None = None) -> str:
    if template is None:
        if not TEMPLATE_PATH.is_file():
            raise TemplateMissing(
                f"dashboard template not built ({TEMPLATE_PATH}); run `make dashboard`"
            )
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
    if PLACEHOLDER not in template:
        raise TemplateMissing(f"template has no {PLACEHOLDER} placeholder")
    block = f'<script id="gapscan-data" type="application/json">{embed_json(data.model_dump_json())}</script>'
    return template.replace(PLACEHOLDER, block, 1)
