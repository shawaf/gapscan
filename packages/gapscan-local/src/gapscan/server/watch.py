"""Zero-day watch over the projects saved in the local manager (`gapscan watch --all`).

For every project that is not archived, the latest finished scan's dependency list is re-checked
against the vulnerability data installed now (`gapscan.watch`). The code is not scanned again; the
project folder is only read to tell whether the vulnerable function is called.
"""

from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..enrich import Enrichment
from ..scanners.osv import OSVScanner
from ..stages import RunFolder
from ..watch import WatchReport, watch_scan
from .db import Database


def watch_saved_projects(
    config: Config,
    scanner: OSVScanner,
    workdir: Path,
    *,
    enrichment: Enrichment | None = None,
    data_dir: Path | None = None,
) -> list[WatchReport]:
    base = data_dir or config.data.dir
    db_path = base / "gapscan.db"
    if not db_path.is_file():
        return []
    db = Database(db_path)
    reports: list[WatchReport] = []
    for project in db.projects():
        if project["archived"]:
            continue
        run = db.latest_done(int(project["id"]))
        if run is None:
            continue
        folder = RunFolder(base / "runs" / str(run["id"]))
        try:
            scan = folder.load_scan()
        except (FileNotFoundError, ValueError):
            continue
        reports.append(
            watch_scan(
                scan,
                str(project["name"]),
                scanner,
                workdir / str(project["id"]),
                enrichment=enrichment,
                target=Path(str(project["path"])),
            )
        )
    return reports
