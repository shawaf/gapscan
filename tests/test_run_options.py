"""Run options and settings (gapscan.services): the one validation of what a person asks a run to
do, shared by every app. The local server's routes only map `InvalidInput` to a 400."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gapscan.config import Config
from gapscan.services import (
    InvalidInput,
    check_finding_id,
    check_project_folder,
    finding_history,
    list_directory,
    run_options,
    run_settings,
    settings_update,
)

KNOWN = ("semgrep", "gitleaks")


def test_run_options_fill_saved_defaults_and_validate_every_field() -> None:
    cfg = Config()
    opts = run_options({"triage": True}, {"triage_limit": 7, "deep_dive_limit": 3}, cfg, KNOWN)
    assert opts == {"triage": True, "limit": 7, "deep_dive": True, "deep_dive_limit": 3}
    assert "deep_dive" not in run_options({}, {}, cfg, KNOWN)  # only after an AI review
    assert run_options({"scanners": ["gitleaks", "semgrep", "gitleaks"]}, {}, cfg, KNOWN)[
        "scanners"] == ["gitleaks", "semgrep"]  # fmt: skip
    assert run_options({"base": "origin/main"}, {}, cfg, KNOWN)["base"] == "origin/main"
    assert "base" not in run_options({"base": ""}, {}, cfg, KNOWN)  # empty means whole project
    for bad in ({"limit": True}, {"limit": -1}, {"scanners": []}, {"scanners": ["nmap"]},
                {"profile": "nope"}, {"triage": True, "deep_dive": "yes"}, {"asvs_level": 4},
                {"baseline": 0}, {"base": "--upload-pack"}, {"base": "a b"}, {"base": "-x"}):  # fmt: skip
        with pytest.raises(InvalidInput):
            run_options(bad, {}, cfg, KNOWN)


def test_settings_update_names_only_what_changed_and_reads_back_with_defaults() -> None:
    cfg = Config()
    assert settings_update({"deep_dive": False, "asvs_level": 3}, cfg, KNOWN) == {
        "deep_dive": False, "asvs_level": 3}  # fmt: skip
    with pytest.raises(InvalidInput, match="default_preset"):
        settings_update({"default_preset": "quick"}, cfg, KNOWN)
    shown = run_settings({"asvs_level": 3}, cfg)
    assert shown["asvs_level"] == 3 and shown["profile"] == cfg.llm.profile
    assert shown["scanners"] == list(cfg.scanners.enabled)


def test_project_folders_refuse_roots_home_and_gapscan_data(tmp_path: Path) -> None:
    data = tmp_path / "data"
    (data / "runs").mkdir(parents=True)
    assert check_project_folder(str(tmp_path), data) == tmp_path.resolve()
    for raw in ("", "relative/path", "/", str(Path.home()), str(data), str(data / "runs"),
                str(tmp_path / "missing")):  # fmt: skip
        with pytest.raises(InvalidInput):
            check_project_folder(raw, data)


def test_list_directory_returns_subfolders_and_marks_git_repos(tmp_path: Path) -> None:
    (tmp_path / "code").mkdir()
    (tmp_path / "code" / "app").mkdir()
    (tmp_path / "code" / "app" / ".git").mkdir()
    (tmp_path / "code" / "notes.txt").write_text("x")  # files are left out
    out = list_directory(str(tmp_path / "code"), tmp_path)
    assert out["path"] == str((tmp_path / "code").resolve())
    assert out["parent"] == str(tmp_path.resolve())
    assert [e["name"] for e in out["entries"]] == ["app"]  # the file is not listed
    assert out["entries"][0]["git"] is True


def test_list_directory_defaults_to_home_and_stops_at_the_root(tmp_path: Path) -> None:
    assert list_directory("", tmp_path)["path"] == str(tmp_path.resolve())
    root = list_directory("/", tmp_path)
    assert root["parent"] is None  # a filesystem root has no parent to go up to


def test_list_directory_refuses_a_non_folder(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("x")
    with pytest.raises(InvalidInput):
        list_directory(str(tmp_path / "f.txt"), tmp_path)


def test_finding_history_reads_each_saved_report_and_skips_unreadable_ones(tmp_path: Path) -> None:
    good = tmp_path / "1.json"
    good.write_text(json.dumps({"findings": [{"id": "f1", "status": "open", "severity": "high"}]}))
    broken = tmp_path / "2.json"
    broken.write_text("{not json")
    runs = [({"id": 2, "finished_at": "b"}, broken), ({"id": 1, "finished_at": "a"}, good)]
    rows = finding_history("f1", runs)
    assert len(rows) == 1 and rows[0]["run"] == 1 and rows[0]["severity"] == "high"
    assert check_finding_id("abc:1") == "abc:1"
    with pytest.raises(InvalidInput):
        check_finding_id("../etc")
