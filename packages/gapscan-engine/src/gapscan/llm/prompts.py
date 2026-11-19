"""Versioned prompt templates. Templates live in llm/prompts/ as `<name>_v<N>.j2`; they are
never inline strings (project rule). The version string is recorded with every result so
cached answers and evaluations can be traced to the exact prompt."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

PROMPT_DIR = Path(__file__).parent / "prompts"
_ENV = Environment(  # noqa: S701 - plain-text prompts, not HTML
    loader=FileSystemLoader(PROMPT_DIR),
    undefined=StrictUndefined,  # a missing variable is a bug, not an empty string
    autoescape=False,
    keep_trailing_newline=True,
)


def render_prompt(version: str, **context: Any) -> str:
    """Render e.g. `triage_bench_v2` (the template file name without .j2)."""
    return _ENV.get_template(f"{version}.j2").render(**context)


def latest_version(name: str) -> str:
    """Highest `<name>_vN` template available, e.g. latest_version('triage_bench')."""
    found = [p.stem for p in PROMPT_DIR.glob(f"{name}_v*.j2")]
    if not found:
        raise FileNotFoundError(f"no prompt template named {name!r}")
    return max(found, key=lambda s: int(s.rsplit("_v", 1)[1]))
