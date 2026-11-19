"""The built-in sample project: a small app with planted mistakes, copied into the user's data folder so a first scan
shows real findings in seconds. The files are never executed, only read by the scanners."""

from __future__ import annotations

import shutil
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / "sample_project"
NAME = "GapScan sample"


def ensure_sample(dest: Path) -> Path:
    """Copy the sample into `dest` (a `.sample` suffix is dropped so the files are ordinary source) and return it."""
    for src in sorted(SOURCE.rglob("*")):
        if not src.is_file():
            continue
        target = dest / src.relative_to(SOURCE)
        if target.suffix == ".sample":
            target = target.with_suffix("")
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(src, target)
    return dest
