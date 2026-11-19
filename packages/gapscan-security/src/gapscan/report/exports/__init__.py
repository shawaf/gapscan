"""Exports of the same report data the dashboard shows: SARIF, CSV, Markdown, CycloneDX, JSON, PDF."""

from __future__ import annotations

from pathlib import Path

from ...models import ScanResult
from ..schema import ReportData
from .csvs import asvs_csv, findings_csv
from .markdown import markdown_summary
from .sarif import to_sarif

__all__ = ["asvs_csv", "findings_csv", "markdown_summary", "to_sarif", "write_exports"]


def write_exports(data: ReportData, scan: ScanResult, directory: Path, stem: str) -> list[Path]:
    """Write every text export next to each other and return the paths."""
    import json

    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    def put(name: str, content: str) -> None:
        path = directory / f"{stem}{name}"
        path.write_text(content, encoding="utf-8")
        written.append(path)

    put(".sarif", json.dumps(to_sarif(data), indent=2))
    put("-findings.csv", findings_csv(data))
    put("-asvs.csv", asvs_csv(data))
    put("-summary.md", markdown_summary(data))
    put(".json", data.model_dump_json(indent=2))
    if scan.sbom:
        put(".cdx.json", json.dumps(scan.sbom, indent=2))
    return written
