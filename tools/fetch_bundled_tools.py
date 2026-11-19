"""Download the scanners that ship inside the installer (the packs marked `bundled` in the manifest) for
this machine's platform into packaging/bundled/, using the same verified downloader as the setup wizard.
`make freeze` runs it; PyInstaller then copies the programs into the app's `tools/` folder.

    uv run python tools/fetch_bundled_tools.py
"""

from __future__ import annotations

from pathlib import Path

from gapscan.runtime.hardware import detect
from gapscan.runtime.manifest import load_manifest
from gapscan.runtime.tools import ToolManager

DEST = Path(__file__).resolve().parents[1] / "packaging" / "bundled"


def main() -> None:
    tm = ToolManager(DEST, load_manifest(), detect())
    packs = [p for p in tm.packs() if p.bundled]
    if not packs:
        raise SystemExit(f"the manifest has no bundled scanners for {tm.platform}")
    for pack in packs:
        if tm._marker(pack.id).is_file():
            print(f"{pack.id}: already fetched")
            continue
        print(f"{pack.id}: downloading {pack.size / 1e6:.0f} MB from {pack.url.split('/')[2]}")
        tm._install_scanner(pack, lambda _d, _t: None, None)
    print(
        "bundled programs:",
        ", ".join(sorted(str(p.relative_to(DEST)) for p in DEST.glob("tools/*/bin/*"))),
    )


if __name__ == "__main__":
    main()
