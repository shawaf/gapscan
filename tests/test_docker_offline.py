"""Phase 9 acceptance: a full scan inside `docker run --network none`.

Skipped unless Docker is running and the image exists (build it first: `make docker-build
BUNDLE=...`). The script proves the container has no network before it scans."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "gapscan-offline"


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(
            ["docker", "image", "inspect", IMAGE], check=True, capture_output=True, timeout=30
        )  # noqa: S603, S607
        return True
    except (subprocess.SubprocessError, OSError):
        return False


@pytest.mark.skipif(
    not _docker_ready(), reason=f"Docker is not running or the {IMAGE} image is not built"
)
def test_full_scan_succeeds_with_networking_disabled():
    proc = subprocess.run(
        ["sh", str(ROOT / "docker" / "test-offline.sh")],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )  # noqa: S603, S607
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    assert "blocked as expected" in proc.stdout and "OFFLINE SCAN OK" in proc.stdout
