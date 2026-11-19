"""Draw the app icon (a shield with scan lines on a blue tile) and build GapScan.icns. Needs macOS (sips, iconutil) and
Playwright's Chromium to render the SVG.  uv run python packaging/icon/make_icon.py"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).parent
SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3b5bdb"/><stop offset="1" stop-color="#1b2a7a"/></linearGradient></defs>
<rect x="100" y="100" width="824" height="824" rx="184" fill="url(#g)"/>
<path d="M512 232 L742 322 V508 C742 650 640 744 512 798 C384 744 282 650 282 508 V322 Z" fill="#fff" fill-opacity=".96"/>
<g stroke="#2347c9" stroke-width="30" stroke-linecap="round"><path d="M392 430 H632"/><path d="M392 512 H632"/><path d="M392 594 H552"/></g>
<circle cx="632" cy="594" r="22" fill="#2347c9"/>
</svg>"""


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        png = Path(tmp) / "icon.png"
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1024, "height": 1024})
            page.set_content(f"<body style='margin:0;background:transparent'>{SVG}</body>")
            page.screenshot(path=str(png), omit_background=True)
            browser.close()
        iconset = Path(tmp) / "GapScan.iconset"
        iconset.mkdir()
        for size in (16, 32, 64, 128, 256, 512, 1024):
            for scale, name in ((1, f"icon_{size}x{size}.png"), (2, f"icon_{size // 2}x{size // 2}@2x.png")):
                if scale == 2 and size == 16:
                    continue
                if scale == 1 and size in (64, 1024):
                    continue
                subprocess.run(["sips", "-z", str(size), str(size), str(png), "--out", str(iconset / name)], check=True, capture_output=True)  # noqa: S603, S607
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(HERE / "GapScan.icns")], check=True)  # noqa: S603, S607
    (HERE / "GapScan.svg").write_text(SVG)
    print("wrote", HERE / "GapScan.icns")


if __name__ == "__main__":
    main()
