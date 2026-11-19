"""Entry point of the packaged app.

The desktop shell starts it as `gapscan serve --no-open ...`, the same command line as a source install."""

from __future__ import annotations

import multiprocessing
import sys

from gapscan.cli import app
from gapscan.paths import use_app_dir

if __name__ == "__main__":
    multiprocessing.freeze_support()
    use_app_dir()
    if len(sys.argv) == 1:  # double-clicked: open the window
        sys.argv.append("app")
    app()
