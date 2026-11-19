# ruff: noqa: F811
"""First run: the plan a new machine gets, the welcome state, and the built-in sample project."""

from __future__ import annotations

from pathlib import Path

import pytest

from .test_runtime import fake_ollama, no_host_ollama, origin, setup_env, wait_task  # noqa: F401


@pytest.fixture(autouse=True)
def sample_home(tmp_path, monkeypatch):
    monkeypatch.setenv("GAPSCAN_HOME", str(tmp_path / "home"))


def test_a_fresh_machine_gets_a_plan_in_order_with_sizes(setup_env):
    st = setup_env.get("/api/setup").json()
    assert st["welcome"] is None
    steps = {s["step"]: s for s in st["plan"]}
    assert list(steps) == ["engine", "model", "embedding", "scanners", "data"]
    assert steps["engine"]["size"] > 0 and not steps["engine"]["done"]
    assert (
        steps["model"]["pack"] == "big"
        and steps["model"]["size"] > 0
        and not steps["model"]["done"]
    )
    assert steps["data"]["optional"] is True and steps["data"]["size"] is None
    assert all(not steps[k]["optional"] for k in ("engine", "model", "embedding", "scanners"))


def test_a_model_found_in_ollama_costs_nothing_in_the_plan(setup_env, tmp_path, monkeypatch):
    store = tmp_path / "ollama"
    fake_ollama(store)
    monkeypatch.setenv("OLLAMA_MODELS", str(store))
    model = {s["step"]: s for s in setup_env.get("/api/setup").json()["plan"]}["model"]
    assert model["size"] == 0 and "Ollama" in model["note"]


def test_finished_steps_are_marked_done_after_running_them(setup_env):
    for step, pack in [("engine", ""), ("model", "big"), ("embedding", "")]:
        t = wait_task(
            setup_env,
            setup_env.req("POST", "/api/setup/run", {"step": step, "pack": pack}).json()["id"],
        )
        assert t["status"] == "done", t["log"]
    steps = {s["step"]: s for s in setup_env.get("/api/setup").json()["plan"]}
    assert steps["engine"]["done"] and steps["model"]["done"] and steps["embedding"]["done"]


def test_the_welcome_page_is_remembered(setup_env):
    assert setup_env.req("POST", "/api/setup/welcome", {"value": "later"}).status_code == 400
    assert setup_env.req("POST", "/api/setup/welcome", {"value": "skipped"}).json() == {
        "welcome": "skipped"
    }
    assert setup_env.get("/api/setup").json()["welcome"] == "skipped"
    setup_env.req("POST", "/api/setup/welcome", {"value": "done"})
    assert setup_env.get("/api/setup").json()["welcome"] == "done"


def test_the_sample_project_is_created_once_and_never_inside_the_data_folder(setup_env, tmp_path):
    first = setup_env.req("POST", "/api/sample", {}).json()
    again = setup_env.req("POST", "/api/sample", {}).json()
    assert first["id"] == again["id"] and first["name"] == "GapScan sample"
    folder = Path(first["path"])
    assert folder == (tmp_path / "home" / "sample-project").resolve()
    assert (
        tmp_path / "data"
    ) not in folder.parents  # the manager would refuse a folder inside its own data
    names = {p.name for p in folder.rglob("*") if p.is_file()}
    assert {
        "app.py",
        "requirements.txt",
        "Dockerfile",
        "app.js",
        "README.md",
    } <= names and "app.py.sample" not in names
    assert "SELECT * FROM users" in (folder / "app.py").read_text()
    assert len(setup_env.get("/api/projects").json()) == 1
