"""tools/build_dist.py: the single `gapscan` distribution published to PyPI."""

from __future__ import annotations

import importlib.util
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("build_dist", ROOT / "tools" / "build_dist.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_dist"] = module
    spec.loader.exec_module(module)
    return module


bd = _load()


def test_metadata_merges_every_layer_without_internal_packages():
    meta = bd.merged_metadata()
    names = [bd._name(d) for d in meta["deps"]]
    assert not any(n.startswith("gapscan-") for n in names)
    for needed in ("pydantic", "typer", "httpx", "numpy", "tree-sitter"):
        assert needed in names
    assert len(names) == len(set(names))
    assert meta["scripts"] == {"gapscan": "gapscan.cli:app"}
    assert meta["entry_points"]["gapscan.packs"]["security"] == "gapscan.security_pack:register"
    assert "pdf" in meta["extras"] and "postgres" in meta["extras"]


def test_generated_pyproject_is_valid_toml_with_the_shared_version():
    text = bd.pyproject(bd.version(), bd.merged_metadata())
    project = tomllib.loads(text)["project"]
    assert project["name"] == "gapscan" and project["version"] == bd.version()
    assert project["scripts"]["gapscan"] == "gapscan.cli:app"
    assert "Topic :: Security" in project["classifiers"]


def test_pypi_readme_links_are_absolute():
    text = bd.pypi_readme("9.9.9")
    assert "](docs/" not in text and 'src="docs/' not in text
    assert "https://raw.githubusercontent.com/shawaf/gapscan/v9.9.9/docs/images/" in text
    assert "https://github.com/shawaf/gapscan/blob/v9.9.9/docs/" in text
    assert "](#quick-start)" in text  # in-page anchors stay


def test_stage_merges_the_layers_and_adds_the_marker(tmp_path):
    stage = bd.stage(tmp_path, bd.version())
    pkg = stage / "src" / "gapscan"
    for module in ("core/version.py", "pipeline.py", "security_pack.py", "cli.py", "_dist.py"):
        assert (pkg / module).is_file(), module
    assert not list(pkg.rglob("__pycache__"))
    assert (pkg / "rules" / "semgrep").is_dir()
    assert (pkg / "report" / "templates" / "dashboard.html").is_file()
