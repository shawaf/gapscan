# PyInstaller spec: builds dist/gapscan/ (a folder with the `gapscan` program and everything it needs).
# Build with `make freeze`. One-folder, not one-file: it starts fast because nothing is unpacked at launch.
import glob
import os
import sys

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules, copy_metadata

hidden = collect_submodules("gapscan")
# Language grammars are loaded by name at run time, so the analyzer cannot see them.
for mod in ("python", "javascript", "typescript", "java", "kotlin", "go", "swift", "dart"):
    hidden.append(f"tree_sitter_{mod}")
hidden += ["tree_sitter"]

# The desktop window (pywebview) picks its platform backend at run time.
web_datas, web_binaries, web_hidden = collect_all("webview")
hidden += web_hidden
if sys.platform == "darwin":
    hidden += ["objc", "AppKit", "Foundation", "WebKit", "Quartz", "Security", "UniformTypeIdentifiers", "PyObjCTools"]

datas = collect_data_files("gapscan") + web_datas  # prompts, OWASP tables, report and manager pages, own rules, manifest
# Entry points: the packs register their scanners through them (the security pack's is in
# gapscan-security). `gapscan` is a namespace package over the workspace packages (packages/).
for dist in ("gapscan", "gapscan-core", "gapscan-engine", "gapscan-security", "gapscan-local"):
    datas += copy_metadata(dist)
# Programs shipped inside the installer (fetched by tools/fetch_bundled_tools.py); the app finds them in tools/
datas += [(f, "tools") for f in glob.glob("bundled/tools/*/bin/*") if os.path.isfile(f)]

a = Analysis(
    ["entry.py"],
    pathex=sorted(glob.glob("../packages/*/src")),
    datas=datas,
    binaries=web_binaries,
    hiddenimports=hidden,
    excludes=["playwright", "pytest", "ruff", "mypy", "pre_commit", "tkinter"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="gapscan", console=True)
coll = COLLECT(exe, a.binaries, a.datas, name="gapscan")

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="GapScan.app",
        icon="icon/GapScan.icns",
        bundle_identifier="dev.gapscan.app",
        info_plist={
            "CFBundleName": "GapScan",
            "CFBundleDisplayName": "GapScan",
            "CFBundleShortVersionString": "0.0.1",
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "12.0",
            "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},  # the window talks to its own loopback server
            "NSHumanReadableCopyright": "Apache-2.0",
        },
    )
