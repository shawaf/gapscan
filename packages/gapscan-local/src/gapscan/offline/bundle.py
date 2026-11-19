"""Build the offline data bundle: one tarball with everything an air-gapped machine needs besides the
scanner binaries (those come with the Docker image or the platform's own install).

A bundle carries a manifest (`bundle.json`) with the sha256 of every file, the versions and snapshot
dates of every dataset, and the license notices that must travel with the data. `gapscan update`
verifies all of it before touching anything. Nothing here runs during `scan`."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from ..core.version import __version__

BUNDLE_SCHEMA = 1
MANIFEST_NAME = "bundle.json"
NOTICES_NAME = "NOTICES.md"
# Reproduced verbatim as the CWE Terms of Use require (https://cwe.mitre.org/about/termsofuse.html).
MITRE_COPYRIGHT = (
    "Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks"
    " of The MITRE Corporation."
)
MITRE_CWE_LICENSE = (
    "CWE™ is free to use by any organization or individual for any research, development, and/or "
    "commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby g"
    "rants you a non-exclusive, royalty-free license to use CWE for research, development, and co"
    "mmercial purposes. Any copy you make for such purposes is authorized on the condition that y"
    "ou reproduce MITRE’s copyright designation and this license in any such copy. CWE is a trade"
    "mark of The MITRE Corporation. Please contact cwe@mitre.org if you require further clarifica"
    "tion on this issue."
)
ALLOWED_TOP = ("data", "models", "wheels")
STATE_FILE = "bundle-state.json"  # written into data/ by `gapscan update`

# What goes in, relative to the data directory. Everything else (eval targets, response cache,
# Trivy's layer cache) stays out on purpose.
SECTIONS: dict[str, str] = {
    "owasp": "OWASP documents (raw, checksummed) and mapping sources",
    "mitre": "MITRE CWE catalog",
    "kb": "Local knowledge base index",
    "enrichment": "CISA KEV and EPSS scores",
    "osv-db": "OSV vulnerability database archives",
    "trivy-cache": "Trivy vulnerability database",
    "semgrep-rules": "Semgrep community rules (opt-in)",
}


class BundleFile(BaseModel):
    path: str  # archive path, e.g. data/osv-db/SNAPSHOT_DATE
    sha256: str
    bytes: int


class Includes(BaseModel):
    semgrep_community_rules: bool = False
    java_db: bool = False
    model: str | None = None
    wheels: bool = False


class BundleManifest(BaseModel):
    schema_version: int = BUNDLE_SCHEMA
    created_at: str
    gapscan_version: str = __version__
    includes: Includes = Field(default_factory=Includes)
    versions: dict[str, str] = Field(default_factory=dict)  # OWASP editions, CWE, rules commit...
    snapshots: dict[str, str] = Field(
        default_factory=dict
    )  # dataset -> date (osv_db, trivy_db, cisa_kev, epss)
    sections: dict[str, int] = Field(default_factory=dict)  # section -> file count
    files: list[BundleFile] = Field(default_factory=list)


class BundleError(RuntimeError):
    pass


@dataclass
class BundleOptions:
    include_semgrep_rules: bool = False
    accept_semgrep_license: bool = False
    include_java_db: bool = False
    model: str | None = None
    ollama_dir: Path | None = None
    wheels_dir: Path | None = None  # a directory of already-downloaded wheels to ship
    compress: bool = True
    versions: dict[str, str] = field(default_factory=dict)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk(root: Path, skip_dirs: set[str]) -> Iterator[Path]:
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in skip_dirs)
        for name in sorted(files):
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue  # never ship links or special files
            yield p


def section_files(data_dir: Path, section: str, *, java_db: bool) -> list[tuple[str, Path]]:
    """(archive path, source file) pairs for one section, sorted for a reproducible archive."""
    root = data_dir / section
    if not root.is_dir():
        return []
    skip = {".git", "__pycache__", ".DS_Store"}
    if section == "trivy-cache":
        skip |= {"fanal", "policy"}  # scan-time caches, not data
        if not java_db:
            skip |= {"java-db"}  # ~2.6 GB, only needed to scan Java archives (jar/war)
    return [(f"data/{section}/{p.relative_to(root).as_posix()}", p) for p in _walk(root, skip)]


def model_files(name: str, ollama_dir: Path) -> list[tuple[str, Path]]:
    """The manifest and every blob of an Ollama model, as archive paths under models/ollama/."""
    repo, _, tag = name.partition(":")
    parts = repo.split("/")
    registry = "registry.ollama.ai"
    if len(parts) == 1:
        rel = Path("manifests") / registry / "library" / parts[0] / (tag or "latest")
    elif len(parts) == 2:
        rel = Path("manifests") / registry / parts[0] / parts[1] / (tag or "latest")
    else:
        rel = Path("manifests") / parts[0] / parts[1] / parts[2] / (tag or "latest")
    manifest = ollama_dir / rel
    if not manifest.is_file():
        raise BundleError(f"model {name!r} is not installed in {ollama_dir} (ollama pull it first)")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    digests = [data["config"]["digest"], *[layer["digest"] for layer in data.get("layers", [])]]
    out = [(f"models/ollama/{rel.as_posix()}", manifest)]
    for d in digests:
        blob = ollama_dir / "blobs" / d.replace(":", "-")
        if not blob.is_file():
            raise BundleError(f"model {name!r} is incomplete: blob {d} is missing")
        out.append((f"models/ollama/blobs/{d.replace(':', '-')}", blob))
    return out


def wheel_files(wheels_dir: Path) -> list[tuple[str, Path]]:
    return [
        (f"wheels/{p.name}", p)
        for p in sorted(wheels_dir.iterdir())
        if p.is_file() and p.suffix in (".whl", ".txt")
    ]


def _read_json(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def collect_snapshots(data_dir: Path) -> dict[str, str]:
    snaps: dict[str, str] = {}
    osv = data_dir / "osv-db" / "SNAPSHOT_DATE"
    if osv.is_file():
        snaps["osv_db"] = osv.read_text(encoding="utf-8").strip()
    trivy = _read_json(data_dir / "trivy-cache" / "db" / "metadata.json")
    if trivy.get("UpdatedAt"):
        snaps["trivy_db"] = str(trivy["UpdatedAt"])[:10]
    kev = _read_json(data_dir / "enrichment" / "kev.json")
    if kev.get("dateReleased"):
        snaps["cisa_kev"] = str(kev["dateReleased"])[:10]
    epss = data_dir / "enrichment" / "epss.csv"
    if epss.is_file():
        first = epss.open(encoding="utf-8").readline()
        for part in first.lstrip("#").strip().split(","):
            if part.startswith("score_date:"):
                snaps["epss"] = part.split(":", 1)[1][:10]
    return snaps


def notices(manifest: BundleManifest, data_dir: Path) -> str:
    """License notices that must travel with the data (also written into the bundle)."""
    lines = [
        "# Notices for this GapScan bundle",
        "",
        f"Built {manifest.created_at} by GapScan {manifest.gapscan_version}.",
        "",
        "## OWASP material (CC BY-SA 4.0)",
        "Top 10, ASVS, API Security Top 10, MASVS, GenAI LLM Top 10, Cheat Sheet Series and the knowledge base",
        "index built from them are adapted from OWASP publications, licensed Creative Commons Attribution-",
        "ShareAlike 4.0 International (https://creativecommons.org/licenses/by-sa/4.0/). Copyright the OWASP",
        "Foundation and contributors. Changes: reformatted, chunked and indexed. Derived material stays under",
        "CC BY-SA 4.0. OpenCRE data: CC0 for the project, embedded ASVS/CWE text keeps its own terms.",
        "",
        "## MITRE CWE",
        "The knowledge base and mapping tables contain CWE content from the MITRE CWE catalog. The CWE",
        "Terms of Use require reproducing MITRE's copyright designation and the license in every copy:",
        "",
        MITRE_COPYRIGHT,
        "",
        MITRE_CWE_LICENSE,
        "",
        "Source: https://cwe.mitre.org/about/termsofuse.html (read 2026-10-09). The content is provided by",
        'MITRE on an "as is" basis without warranty of any kind.',
        "",
        "## Vulnerability data",
        "- CISA Known Exploited Vulnerabilities (https://www.cisa.gov/kev): CC0 / US Government public domain,",
        "  used without CISA or DHS endorsement; the CISA logo and DHS seal are not used.",
        "- EPSS scores: FIRST (https://www.first.org/epss/), published freely; citation to FIRST is requested.",
        "- OSV database (https://osv.dev): only the language ecosystems (PyPI, npm, Maven, Go, Pub, Swift,",
        "  RubyGems, NuGet, Packagist, crates.io), predominantly GitHub Advisory Database data under CC-BY 4.0.",
        "- Trivy vulnerability database: Aqua Security, https://github.com/aquasecurity/trivy-db (aggregates",
        "  NVD public-domain, GitHub Advisory CC-BY 4.0, and distro advisories).",
        "",
    ]
    if manifest.includes.semgrep_community_rules:
        lic = data_dir / "semgrep-rules" / "LICENSE"
        lines += [
            "## Semgrep community rules: Semgrep Rules License v1.0",
            "These rules are included because the builder explicitly accepted their license. They may be used",
            "internally, but the license restricts using them in a competing product or service and restricts",
            "redistribution. Do not publish this bundle. License text: https://semgrep.dev/legal/rules-license",
            f"(first line of the shipped LICENSE file: {lic.read_text(encoding='utf-8').splitlines()[0] if lic.is_file() else 'missing'}).",
            "",
        ]
    if manifest.includes.model:
        lines += [f"## Model: {manifest.includes.model}",
                  "The model's own license applies; see docs/licenses.md in the GapScan repository.", ""]  # fmt: skip
    return "\n".join(lines)


def _write_members(
    tar: tarfile.TarFile, manifest: bytes, notice: bytes, entries: list[tuple[str, Path]]
) -> None:
    for name, payload in ((MANIFEST_NAME, manifest), (NOTICES_NAME, notice)):
        info = tarfile.TarInfo(name)
        info.size, info.mtime, info.mode = len(payload), 0, 0o644
        tar.addfile(info, io.BytesIO(payload))
    for arcname, path in entries:
        info = tar.gettarinfo(str(path), arcname)
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 0  # reproducible: the manifest holds the real dates
        info.mode = 0o755 if info.mode & 0o111 else 0o644
        with path.open("rb") as fh:
            tar.addfile(info, fh)


def build_bundle(data_dir: Path, out: Path, opts: BundleOptions) -> BundleManifest:
    """Package the data directory into `out` (a .tar.gz, or .tar when compression is off)."""
    if opts.include_semgrep_rules and not opts.accept_semgrep_license:
        raise BundleError(
            "The Semgrep community rules are under the Semgrep Rules License v1.0, which forbids use in a "
            "competing product or service and restricts redistribution. Include them only for internal use, "
            "and say so with --accept-semgrep-rules-license."
        )
    entries: list[tuple[str, Path]] = []
    counts: dict[str, int] = {}
    for section in SECTIONS:
        if section == "semgrep-rules" and not opts.include_semgrep_rules:
            continue
        files = section_files(data_dir, section, java_db=opts.include_java_db)
        if not files:
            if section in ("owasp", "kb", "osv-db", "trivy-cache", "enrichment"):
                raise BundleError(
                    f"nothing to bundle for '{section}': {data_dir / section} is missing or empty"
                )
            continue
        entries += files
        counts[section] = len(files)
    if opts.model:
        ollama = opts.ollama_dir or Path(
            os.environ.get("OLLAMA_MODELS", Path.home() / ".ollama" / "models")
        )
        entries += model_files(opts.model, ollama)
        counts["models"] = len(entries) - sum(counts.values())
    if opts.wheels_dir:
        wheels = wheel_files(opts.wheels_dir)
        entries += wheels
        counts["wheels"] = len(wheels)
    versions = dict(opts.versions)
    rules_head = data_dir / "semgrep-rules" / ".git" / "HEAD"
    if opts.include_semgrep_rules and rules_head.is_file():
        versions["semgrep_rules"] = rules_head.read_text(encoding="utf-8").strip()[:40]
    manifest = BundleManifest(
        created_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        includes=Includes(semgrep_community_rules=opts.include_semgrep_rules, java_db=opts.include_java_db,
                          model=opts.model, wheels=bool(opts.wheels_dir)),  # fmt: skip
        versions=versions, snapshots=collect_snapshots(data_dir), sections=counts,
        files=[BundleFile(path=a, sha256=sha256_file(p), bytes=p.stat().st_size) for a, p in entries],
    )  # fmt: skip
    notice_bytes = notices(manifest, data_dir).encode("utf-8")
    manifest_bytes = manifest.model_dump_json(indent=1).encode("utf-8")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".part")
    tar = tarfile.open(tmp, "w:gz", compresslevel=6) if opts.compress else tarfile.open(tmp, "w")  # noqa: SIM115
    with tar:
        _write_members(tar, manifest_bytes, notice_bytes, entries)
    tmp.replace(out)
    out.with_suffix(out.suffix + ".sha256").write_text(
        f"{sha256_file(out)}  {out.name}\n", encoding="utf-8"
    )
    return manifest
