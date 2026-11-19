"""The connected-machine half of `gapscan bundle`: refresh every dataset, in an order that fails
before downloading when OWASP has published a new edition, and verify that the committed mapping
tables still match the freshly downloaded OWASP data."""

from __future__ import annotations

import contextlib
import json
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from ..config import Config
from ..kb import build_kb
from ..kb.ingest import cwe_catalog_version
from ..owasp.build import MAPPINGS_DIR, build
from ..store.raw import RawStore
from .bundle import STATE_FILE, BundleError
from .fetch import fetch_enrichment, fetch_kb_sources, fetch_osv_db, fetch_owasp, fetch_trivy_db
from .versions import check_editions, diff_versions, resolve_versions

Progress = Callable[[str], None]
TABLES = ("cwe_to_top10.csv", "cwe_to_asvs.csv", "asvs_requirements.csv")


def _text(path: Path) -> bytes:
    """Line endings are not content: OWASP publishes the ASVS CSV with CRLF, and git may store or
    check out any text file with either ending (core.autocrlf), so compare with them normalized."""
    return path.read_bytes().replace(b"\r\n", b"\n")


def check_tables_current(owasp: RawStore, committed: Path = MAPPINGS_DIR) -> None:
    """The CWE -> Top 10 / ASVS tables in the repository must be exactly what the downloaded OWASP data
    produces; otherwise a report would mix the tables' edition with newer source text."""
    with tempfile.TemporaryDirectory() as tmp:
        build(owasp, Path(tmp))
        stale = [t for t in TABLES if _text(Path(tmp) / t) != _text(committed / t)]
    if stale:
        raise BundleError(
            "the OWASP data changed in a way that changes the mapping tables ("
            + ", ".join(stale)
            + "). Regenerate and review them (`gapscan data build-mappings`, then commit) before bundling"
        )


def download_wheels(dest: Path, timeout_s: int = 900) -> Path:
    """Download the runtime dependencies as wheels for this platform (for installs without PyPI)."""
    dest.mkdir(parents=True, exist_ok=True)
    req = dest / "requirements.txt"
    subprocess.run(  # noqa: S603 - fixed arg list
        ["uv", "export", "--frozen", "--no-dev", "--no-hashes", "--no-emit-project", "-o", str(req)],
        check=True, capture_output=True, timeout=timeout_s,
    )  # fmt: skip
    subprocess.run(  # noqa: S603
        ["uv", "run", "--with", "pip", "python", "-m", "pip", "download", "-r", str(req), "-d", str(dest), "--only-binary=:all:", "-q"],
        check=True, capture_output=True, timeout=timeout_s,
    )  # fmt: skip
    return dest


def refresh_all(
    config: Config,
    *,
    java_db: bool = False,
    rebuild_kb: bool = True,
    progress: Progress = lambda _m: None,
) -> dict[str, str]:
    """Refresh every dataset on a connected machine. Returns the versions to record in the bundle."""
    data = config.data.dir
    progress("checking the latest OWASP editions ...")
    resolved = resolve_versions()
    check = check_editions(resolved)
    for w in check.warnings:
        progress(f"warning: {w}")
    if not check.ok:
        raise BundleError("new OWASP edition detected:\n  " + "\n  ".join(check.errors))
    previous = {}
    with contextlib.suppress(OSError, ValueError):
        previous = json.loads((data / STATE_FILE).read_text(encoding="utf-8")).get("versions", {})
    for line in diff_versions(previous, resolved):
        progress(f"changed since the last bundle: {line}")

    owasp, mitre = RawStore(data / "owasp"), RawStore(data / "mitre")
    progress("downloading OWASP documents ...")
    fetch_owasp(owasp)
    fetch_kb_sources(owasp, mitre)
    problems = owasp.verify() + mitre.verify()
    if problems:
        raise BundleError("downloaded data failed verification: " + "; ".join(problems))
    check_tables_current(owasp)
    progress("downloading CISA KEV and EPSS ...")
    dates = fetch_enrichment(RawStore(data / "enrichment"))
    progress("downloading the OSV database (about 260 MB) ...")
    osv_date = fetch_osv_db(config.scanners.osv.db_dir)
    progress("downloading the Trivy database ...")
    trivy_date = fetch_trivy_db(config.scanners.trivy.cache_dir, java_db=java_db)
    if rebuild_kb:
        progress("rebuilding the knowledge base (needs the embedding model) ...")
        build_kb(config, embed=True)
    cwe = cwe_catalog_version(mitre)
    return {**resolved, "cwe": cwe, "kev_date": dates.get("cisa_kev", ""), "epss_date": dates.get("epss", ""),
            "osv_date": osv_date, "trivy_date": trivy_date}  # fmt: skip
