"""Resumable, verified downloads for the setup wizard.

Hard limits, all enforced here and not in the caller: only hosts from the manifest's allow-list (every
redirect hop is checked again), HTTPS only (plain HTTP only to this machine, for tests), enough free
disk before starting, a `.part` file that a later call resumes with a Range request, and the final
file is kept only when its size and sha256 match the pinned values."""

from __future__ import annotations

import fnmatch
import hashlib
import shutil
import tarfile
import threading
import zipfile
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

Progress = Callable[[int, int], None]
CHUNK = 1 << 20
MAX_HOPS = 6
LOCAL = {"127.0.0.1", "localhost", "::1"}


class DownloadError(RuntimeError):
    pass


class DownloadCancelled(DownloadError):
    pass


def host_allowed(url: str, allowed: list[str]) -> bool:
    u = urlparse(url)
    host = (u.hostname or "").lower()
    if host in LOCAL and u.scheme in ("http", "https"):
        return True
    return u.scheme == "https" and any(fnmatch.fnmatch(host, pat.lower()) for pat in allowed)


def sha256_file(path: Path, progress: Progress | None = None) -> str:
    h, done, total = hashlib.sha256(), 0, path.stat().st_size
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)
    return h.hexdigest()


def _marker(dest: Path) -> Path:
    return dest.with_name(dest.name + ".ok")


def is_installed(dest: Path, sha256: str, size: int) -> bool:
    """True when `dest` was fully verified earlier (a marker records the hash that was checked)."""
    try:
        return (
            dest.stat().st_size == size and _marker(dest).read_text().strip() == f"{sha256} {size}"
        )
    except OSError:
        return False


def download(
    url: str, dest: Path, *, sha256: str, size: int, allowed_hosts: list[str],
    progress: Progress | None = None, cancel: threading.Event | None = None,
    client: httpx.Client | None = None, min_free_gb: float = 1.0,
) -> Path:  # fmt: skip
    """Fetch `url` to `dest`. Safe to call again after an interruption: it resumes."""
    if is_installed(dest, sha256, size):
        return dest
    if not host_allowed(url, allowed_hosts):
        raise DownloadError(f"{urlparse(url).hostname} is not on the allowed download list")
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    have = part.stat().st_size if part.exists() else 0
    if have > size:
        part.unlink()
        have = 0
    free = shutil.disk_usage(dest.parent).free
    if free < (size - have) + int(min_free_gb * 1e9):
        raise DownloadError(
            f"not enough disk space: {(size - have) / 1e9:.1f} GB needed, {free / 1e9:.1f} GB free"
        )
    own = client is None
    http = client or httpx.Client(timeout=httpx.Timeout(30.0, read=60.0), follow_redirects=False)
    try:
        if have < size:
            _fetch(http, url, part, have, size, allowed_hosts, progress, cancel)
    finally:
        if own:
            http.close()
    if part.stat().st_size != size:
        raise DownloadError(f"{dest.name}: received {part.stat().st_size} bytes, expected {size}")
    if progress:
        progress(size, size)
    if sha256_file(part) != sha256:
        part.unlink(missing_ok=True)
        raise DownloadError(f"{dest.name}: the checksum does not match, the file was discarded")
    part.replace(dest)
    _marker(dest).write_text(f"{sha256} {size}\n")
    return dest


def _fetch(http: httpx.Client, url: str, part: Path, have: int, size: int, allowed: list[str],
           progress: Progress | None, cancel: threading.Event | None) -> None:  # fmt: skip
    current = url
    for _ in range(MAX_HOPS):
        headers = {"Range": f"bytes={have}-"} if have else {}
        with http.stream("GET", current, headers=headers) as r:
            if r.status_code in (301, 302, 303, 307, 308):
                current = urljoin(current, r.headers.get("location", ""))
                if not host_allowed(current, allowed):
                    raise DownloadError(
                        f"redirected to {urlparse(current).hostname}, which is not on the allowed list"
                    )
                continue
            if r.status_code == 416 and have:  # the part file is already complete
                return
            if r.status_code not in (200, 206):
                raise DownloadError(f"the server answered {r.status_code}")
            if have and r.status_code == 200:  # no range support: start over
                have = 0
            mode = "ab" if have else "wb"
            with part.open(mode) as out:
                for chunk in r.iter_bytes(CHUNK):
                    if cancel is not None and cancel.is_set():
                        raise DownloadCancelled(
                            "stopped; a later start continues where it left off"
                        )
                    out.write(chunk)
                    have += len(chunk)
                    if progress:
                        progress(min(have, size), size)
            return
    raise DownloadError("too many redirects")


def extract_archive(archive: Path, dest: Path, kind: str) -> None:
    """Unpack a runtime archive. Paths that would leave `dest` are refused."""
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    if kind == "zip":
        with zipfile.ZipFile(archive) as z:
            for name in z.namelist():
                if not (root / name).resolve().is_relative_to(root):
                    raise DownloadError(f"unsafe path in the archive: {name}")
            z.extractall(dest)
        return
    with tarfile.open(archive) as t:
        t.extractall(dest, filter="data")  # rejects absolute paths, '..' and links that escape


def find_binary(
    root: Path, names: tuple[str, ...] = ("llama-server", "llama-server.exe")
) -> Path | None:
    for path in sorted(root.rglob("*")):
        if path.name in names and path.is_file():
            path.chmod(path.stat().st_mode | 0o111)
            return path
    return None
