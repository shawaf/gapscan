"""`gapscan update --from <bundle>`: import a bundle on the air-gapped machine.

The bundle is untrusted input until proven otherwise, so the importer:
  1. reads the manifest first and refuses unknown schema versions;
  2. accepts only regular files whose paths the manifest lists (no links, devices, absolute paths,
     `..`, unlisted extras, duplicates) and only under data/, models/ and wheels/;
  3. extracts to a staging directory and verifies the sha256 and size of every file BEFORE any
     installed data is touched; a single mismatch aborts with the existing data intact;
  4. refuses to replace newer data with older snapshots unless forced;
  5. swaps each section directory in with a rename and rolls everything back if a step fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import IO

from .bundle import (
    ALLOWED_TOP,
    BUNDLE_SCHEMA,
    MANIFEST_NAME,
    NOTICES_NAME,
    STATE_FILE,
    BundleManifest,
)

MAX_MANIFEST_BYTES = 64 * 1024 * 1024


class UpdateError(RuntimeError):
    pass


@dataclass
class UpdateResult:
    manifest: BundleManifest
    sections: list[str] = field(default_factory=list)
    model: str | None = None
    warnings: list[str] = field(default_factory=list)


def _safe_member_name(name: str) -> PurePosixPath:
    p = PurePosixPath(name)
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or ".." in p.parts
        or p.parts[0].endswith(":")
    ):
        raise UpdateError(f"unsafe path in bundle: {name!r}")
    return p


def read_manifest(bundle: Path) -> BundleManifest:
    with tarfile.open(bundle, "r:*") as tar:
        first = tar.next()
        if first is None or first.name != MANIFEST_NAME or not first.isreg():
            raise UpdateError("not a GapScan bundle: bundle.json must be the first entry")
        if first.size > MAX_MANIFEST_BYTES:
            raise UpdateError("bundle.json is implausibly large")
        fh = tar.extractfile(first)
        assert fh is not None
        try:
            manifest = BundleManifest.model_validate_json(fh.read())
        except ValueError as exc:
            raise UpdateError(f"bundle.json is invalid: {exc}") from exc
    if manifest.schema_version != BUNDLE_SCHEMA:
        raise UpdateError(
            f"bundle schema {manifest.schema_version} is not supported by this GapScan (expects {BUNDLE_SCHEMA})"
        )
    return manifest


def _chunks(fh: IO[bytes]) -> Iterator[bytes]:
    while chunk := fh.read(1 << 20):
        yield chunk


def _extract_verified(bundle: Path, manifest: BundleManifest, staging: Path | None) -> None:
    """Stream every member, check it against the manifest, and (when `staging` is given) write it."""
    expected = {f.path: f for f in manifest.files}
    for path in expected:
        parts = _safe_member_name(path).parts
        if parts[0] not in ALLOWED_TOP:
            raise UpdateError(f"manifest lists a path outside {ALLOWED_TOP}: {path}")
    seen: set[str] = set()
    with tarfile.open(bundle, "r:*") as tar:
        for member in tar:
            name = member.name
            if name in (MANIFEST_NAME, NOTICES_NAME):
                continue
            if not member.isreg():
                raise UpdateError(
                    f"bundle contains a non-regular entry (link, directory or device): {name!r}"
                )
            _safe_member_name(name)
            entry = expected.get(name)
            if entry is None:
                raise UpdateError(f"bundle contains a file the manifest does not list: {name!r}")
            if name in seen:
                raise UpdateError(f"duplicate entry in bundle: {name!r}")
            seen.add(name)
            if member.size != entry.bytes:
                raise UpdateError(f"size mismatch for {name}")
            src = tar.extractfile(member)
            assert src is not None
            h = hashlib.sha256()
            out = None
            dest = None
            if staging is not None:
                dest = (staging / name).resolve()
                if not dest.is_relative_to(staging.resolve()):
                    raise UpdateError(f"unsafe path in bundle: {name!r}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                out = dest.open("wb")
            try:
                for chunk in _chunks(src):
                    h.update(chunk)
                    if out:
                        out.write(chunk)
            finally:
                if out:
                    out.close()
            if h.hexdigest() != entry.sha256:
                raise UpdateError(
                    f"checksum mismatch for {name}: the bundle is corrupt or has been tampered with"
                )
    missing = sorted(set(expected) - seen)
    if missing:
        raise UpdateError(
            f"bundle is incomplete: {len(missing)} listed files are missing (first: {missing[0]})"
        )


def verify_bundle(bundle: Path) -> BundleManifest:
    """Check a bundle end to end without installing anything."""
    manifest = read_manifest(bundle)
    _extract_verified(bundle, manifest, None)
    return manifest


def read_state(data_dir: Path) -> dict[str, object]:
    try:
        raw = json.loads((data_dir / STATE_FILE).read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def _downgrades(current: dict[str, object], manifest: BundleManifest) -> list[str]:
    old = current.get("snapshots")
    if not isinstance(old, dict):
        return []
    out = []
    for key, new_date in manifest.snapshots.items():
        prev = old.get(key)
        if isinstance(prev, str) and prev and new_date and new_date < prev:
            out.append(f"{key}: installed {prev}, bundle has {new_date}")
    return out


def _install_models(staging: Path, ollama_dir: Path) -> None:
    src = staging / "models" / "ollama"
    if not src.is_dir():
        return
    for path in sorted(p for p in src.rglob("*") if p.is_file()):
        dest = ollama_dir / path.relative_to(src)
        if dest.exists() and "blobs" in dest.parts:
            continue  # blobs are content-addressed: an existing one is identical
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)


def import_bundle(
    data_dir: Path,
    bundle: Path,
    *,
    force: bool = False,
    ollama_dir: Path | None = None,
    install_model: bool = True,
) -> UpdateResult:
    manifest = read_manifest(bundle)
    result = UpdateResult(manifest)
    problems = _downgrades(read_state(data_dir), manifest)
    if problems and not force:
        raise UpdateError(
            "refusing to replace newer data with older snapshots (use --force): "
            + "; ".join(problems)
        )
    result.warnings += [f"forced downgrade: {p}" for p in problems]
    total = sum(f.bytes for f in manifest.files)
    data_dir.parent.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(data_dir.parent).free
    if free < total * 1.1:
        raise UpdateError(
            f"not enough disk space: need about {total * 1.1 / 1e9:.1f} GB, {free / 1e9:.1f} GB free"
        )

    staging = data_dir.parent / f".gapscan-staging-{uuid.uuid4().hex[:8]}"
    staging.mkdir()
    swapped: list[tuple[Path, Path | None]] = []  # (installed, previous) for rollback
    try:
        _extract_verified(bundle, manifest, staging)  # nothing installed has been touched so far
        data_src = staging / "data"
        for section in (
            sorted(p for p in data_src.iterdir() if p.is_dir()) if data_src.is_dir() else []
        ):
            target = data_dir / section.name
            previous = None
            if target.exists():
                previous = data_dir / f".old-{section.name}-{uuid.uuid4().hex[:6]}"
                target.rename(previous)
            data_dir.mkdir(parents=True, exist_ok=True)
            try:
                section.rename(target)
            except OSError:
                if previous is not None:
                    previous.rename(target)
                raise
            swapped.append((target, previous))
            result.sections.append(section.name)
        if install_model and manifest.includes.model:
            ollama = ollama_dir or Path(
                os.environ.get("OLLAMA_MODELS", Path.home() / ".ollama" / "models")
            )
            _install_models(staging, ollama)
            result.model = manifest.includes.model
        (data_dir / STATE_FILE).write_text(
            json.dumps(
                {
                    "bundle_created_at": manifest.created_at,
                    "imported_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "snapshots": manifest.snapshots,
                    "versions": manifest.versions,
                    "includes": manifest.includes.model_dump(),
                },
                indent=1,
            ),  # fmt: skip
            encoding="utf-8",
        )
    except BaseException:
        for installed, previous in reversed(swapped):  # roll back to what was there before
            shutil.rmtree(installed, ignore_errors=True)
            if previous is not None:
                previous.rename(installed)
        raise
    else:
        for _, previous in swapped:
            if previous is not None:
                shutil.rmtree(previous, ignore_errors=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return result
