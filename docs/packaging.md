# Packaging the desktop app

`make freeze` builds `dist/gapscan/`: a folder with the `gapscan` program and everything it needs (Python, the
dashboards, prompts, OWASP tables, own Semgrep rules, the download manifest and the tree-sitter grammars). It needs
the built dashboards first (`make dashboard manager`) and PyInstaller (the `build` dependency group). It is a
one-folder build, so it starts fast; nothing is unpacked at launch.

- **Same program:** `dist/gapscan/gapscan serve --no-open --port N` is the Control Center, exactly as in a source
  install. The desktop shell (next step) starts this and shows its page in a window.
- **Where data lives:** a packaged app has no project folder, so everything (scan history, models, security data,
  the AI engine) is under one per-user folder: `~/Library/Application Support/GapScan` on macOS,
  `%LOCALAPPDATA%\GapScan` on Windows, `~/.local/share/gapscan` on Linux. Set `GAPSCAN_HOME` to move it, or any
  `GAPSCAN_DATA__*` variable to move a single part. A source checkout still uses `data/` in the project.
- **Tested:** `tests/test_frozen.py` starts the built program, adds a project, runs a scan and reads the report
  with its OWASP mapping, quoted code and SARIF export. It is skipped when `dist/` has not been built.

## The desktop app

`make dmg` builds `dist/GapScan.app` (a normal macOS app with an icon, about 136 MB) and `dist/GapScan.dmg` (about 61 MB). Double-clicking the app opens the Control Center in its own window; there is no browser, no terminal and no Python to install.

- **How it works:** `gapscan app` (what the app runs when started without arguments) starts the same local server as `gapscan serve` on a random loopback port with a fresh token, shows it in the system's own web view through pywebview (WKWebView on macOS), and stops everything when the window closes. Run it from source with `uv sync --group desktop && uv run gapscan app`.
- **One copy per user:** a lock file in the data folder. A second launch exits quietly; after closing, it starts again.
- **No JavaScript bridge:** pywebview's bridge needs script evaluation that the manager's strict Content-Security-Policy blocks, and it would expose Python to a page that shows untrusted scanned code. The native "Browse..." folder dialog on the Add project form is therefore an ordinary authenticated server call (`/api/desktop`, `/api/desktop/choose-folder`) that only exists when a desktop window is attached. Pages outside this machine never stay in the window: they open in the default browser.
- **Icon:** `packaging/icon/make_icon.py` redraws `GapScan.icns` (needs macOS tools and Playwright).
- **Not done:** signing and notarization (without them macOS shows a warning on first open: right-click the app and choose Open), a Windows build (the window would use WebView2) and auto-update.

## Scanners: the hybrid

The scanners reach the user two ways, both from the pinned manifest (`packages/gapscan-local/src/gapscan/runtime/manifest.json`):

| Scanner | How | Size |
|---|---|---|
| Gitleaks, OSV-Scanner | **Inside the installer** (`tools/fetch_bundled_tools.py` fetches them during `make freeze`) | 8 MB, 55 MB |
| Trivy | Downloaded by the setup wizard | 49 MB |
| Semgrep, Checkov, Bandit | Downloaded by the setup wizard: a private relocatable Python plus the pinned wheels | see below |

- **Everything is found through the PATH.** At start, GapScan puts the bundled folder and the folders of scanners the wizard installed in front of the PATH, so the pinned versions win over any copy on the machine. A scanner the machine already has is left alone and never downloaded.
- **Python scanners:** the wizard downloads a relocatable CPython (python-build-standalone), then every pinned wheel from `files.pythonhosted.org`, each checked against its sha256, and installs them offline with `pip --no-index --target` into the scanner's own folder. Launcher scripts (`bin/semgrep`, ...) start the private Python with `-m`; the folder can be moved because nothing holds an absolute path. Nothing is installed into any other Python.
- **Regenerating the manifest:** `uv run python tools/make_pack_manifest.py` rebuilds it (GitHub release metadata, Hugging Face file hashes, and for the Python scanners `uv pip compile --generate-hashes` on `packages/gapscan-local/src/gapscan/runtime/python-tools.in` plus the PyPI file list). Run with `--skip-python` to leave the Python scanners out. Wheels are resolved for the platform you list in `SCANNER_PLATFORMS`; a source-only package stops the run, because it would need a build.

## Not in the package yet

- Signing and notarization (macOS), signing (Windows), Windows and Linux installers, auto-update.
- Only macOS arm64 has been built so far.
