"""The workspace packages (ARCHITECTURE.md section 6): `gapscan` is one namespace package spread
over packages/*/src/gapscan, so a module's package is its folder. These checks keep that true; the
import contracts in pyproject.toml check the imports between the packages."""

from __future__ import annotations

import tomllib
from collections import Counter
from pathlib import Path

import gapscan

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = ROOT / "packages"
NAMES = ("core", "engine", "security", "local")
# What each package may depend on inside the workspace (the import contracts mirror this).
ALLOWED = {
    "core": set(),
    "engine": {"core"},
    "security": {"engine"},
    "local": {"engine", "security"},
}


def project(name: str) -> dict:
    return tomllib.loads((PACKAGES / f"gapscan-{name}" / "pyproject.toml").read_text())["project"]


def test_the_workspace_has_exactly_the_four_packages() -> None:
    assert sorted(p.name for p in PACKAGES.iterdir() if p.is_dir()) == sorted(
        f"gapscan-{n}" for n in NAMES
    )
    root = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert root["tool"]["uv"]["workspace"]["members"] == ["packages/*"]


def test_gapscan_stays_a_namespace_package_over_every_package() -> None:
    for name in NAMES:
        assert not (PACKAGES / f"gapscan-{name}" / "src" / "gapscan" / "__init__.py").exists()
    assert sorted(Path(p).parent.parent.name for p in gapscan.__path__) == sorted(
        f"gapscan-{n}" for n in NAMES
    )


def test_no_module_is_in_two_packages() -> None:
    """Two packages with the same file would shadow each other depending on install order."""
    seen = Counter(
        str(p.relative_to(base))
        for name in NAMES
        for base in [PACKAGES / f"gapscan-{name}" / "src"]
        for p in base.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    )
    assert [path for path, n in seen.items() if n > 1] == []


def test_workspace_dependencies_point_down_only() -> None:
    for name in NAMES:
        deps = {d.split("[")[0].split(">")[0].split("=")[0].strip()
                for d in project(name).get("dependencies", [])}  # fmt: skip
        inside = {d.removeprefix("gapscan-") for d in deps if d.startswith("gapscan-")}
        assert inside == ALLOWED[name], name


def test_the_pack_entry_point_and_the_cli_come_from_their_packages() -> None:
    assert project("security")["entry-points"]["gapscan.packs"] == {
        "security": "gapscan.security_pack:register"
    }
    assert project("local")["scripts"] == {"gapscan": "gapscan.cli:app"}
    assert (PACKAGES / "gapscan-security/src/gapscan/security_pack.py").is_file()
    assert (PACKAGES / "gapscan-local/src/gapscan/cli.py").is_file()
