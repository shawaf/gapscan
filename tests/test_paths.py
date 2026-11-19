from __future__ import annotations

import sys

import pytest

from gapscan import paths
from gapscan.config import Config


@pytest.fixture(autouse=True)
def restore_environment(tmp_path, monkeypatch):
    """`use_app_dir` writes environment variables; register each so the test run leaves none behind."""
    for key in paths.data_env(tmp_path):
        monkeypatch.setenv(key, "placeholder")
        monkeypatch.delenv(key)
    monkeypatch.delenv(paths.HOME_ENV, raising=False)


def test_every_data_folder_moves_under_the_app_folder(tmp_path, monkeypatch):
    monkeypatch.setenv(paths.HOME_ENV, str(tmp_path / "home"))
    assert paths.use_app_dir() == tmp_path / "home"
    cfg = Config()
    base = tmp_path / "home" / "data"
    assert cfg.data.dir == base and cfg.data.kb_dir == base / "kb"
    assert cfg.data.enrichment_dir == base / "enrichment"
    assert (
        cfg.scanners.osv.db_dir == base / "osv-db"
        and cfg.scanners.trivy.cache_dir == base / "trivy-cache"
    )
    assert cfg.scanners.semgrep.rules_path == base / "semgrep-rules"


def test_choices_made_through_the_environment_win(tmp_path, monkeypatch):
    monkeypatch.setenv(paths.HOME_ENV, str(tmp_path / "home"))
    monkeypatch.setenv("GAPSCAN_DATA__DIR", str(tmp_path / "mine"))
    paths.use_app_dir()
    assert Config().data.dir == tmp_path / "mine"


def test_a_source_checkout_is_left_alone(monkeypatch):
    monkeypatch.delenv(paths.HOME_ENV, raising=False)
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    assert paths.use_app_dir() is None


def test_default_folder_is_per_user(monkeypatch):
    monkeypatch.delenv(paths.HOME_ENV, raising=False)
    assert "GapScan" in str(paths.app_dir()) or "gapscan" in str(paths.app_dir())
