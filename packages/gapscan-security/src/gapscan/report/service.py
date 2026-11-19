"""The report of a run, built the same way by every app: the dashboard data computed from a scan
and its model review, and the self-contained dashboard HTML rendered from it."""

from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..kb import KnowledgeBase
from ..models import ScanResult
from ..stages import TriageOutput
from .build import PreviousRun, build_report
from .dashboard import render_dashboard
from .decisions import Decisions
from .schema import ReportData


def build_dashboard(
    scan: ScanResult,
    review: TriageOutput | None,
    *,
    config: Config,
    target: Path | None = None,
    baseline: PreviousRun | None = None,
    decisions: Decisions | None = None,
    project: str | None = None,
    kb: KnowledgeBase | None = None,
    head: str = "",
) -> tuple[ReportData, str]:
    """The report data and its dashboard HTML. `review` must have been made from `scan` (check it
    with `TriageOutput.check` first); `head` is markup an app adds to the page's <head>."""
    data = build_report(
        scan,
        review.verdicts if review else [],
        review.summary if review else None,
        config=config,
        target=target,
        baseline=baseline,
        decisions=decisions,
        project=project,
        kb=kb,
        investigations=review.investigations if review else [],
    )
    html = render_dashboard(data)
    if head:
        html = html.replace("</head>", head + "</head>", 1)
    return data, html
