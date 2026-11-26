"""Shared test fixtures."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _restore_gapscan_environment() -> Iterator[None]:
    """Every CLI call runs `use_app_dir`, which may set GAPSCAN_DATA__* variables in this process
    (for example when a test sets GAPSCAN_HOME). Put the GAPSCAN_ variables back after each test so
    one test's data folder never leaks into the next."""
    before = {k: v for k, v in os.environ.items() if k.startswith("GAPSCAN_")}
    yield
    for key in [k for k in os.environ if k.startswith("GAPSCAN_")]:
        if key not in before:
            del os.environ[key]
    os.environ.update(before)
