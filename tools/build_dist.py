"""Build the one `gapscan` distribution that is published to PyPI.

The source tree is a uv workspace of four packages (core, engine, security, local) that all add to the
one `gapscan` import package (ARCHITECTURE.md section 6). Publishing four tightly versioned projects
would make `pip install gapscan` fragile, so this script assembles a single project instead: the four
`src/gapscan` trees merged into one, their dependencies, scripts and entry points combined, and a
marker module (`gapscan/_dist.py`) that tells the program it runs from an installed package, so it
keeps its data in the per-user folder rather than in the current directory.

    uv run python tools/build_dist.py            # -> dist/gapscan-<version>-py3-none-any.whl + sdist
    uv run python tools/build_dist.py --check    # also install the wheel in a fresh venv and smoke it

The workspace itself is unchanged: `make setup` and every test keep working on the source tree.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAYERS = ["gapscan-core", "gapscan-engine", "gapscan-security", "gapscan-local"]
REPO = "https://github.com/shawaf/gapscan"
RAW = "https://raw.githubusercontent.com/shawaf/gapscan"
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".mypy_cache", ".pytest_cache")


def version() -> str:
    text = (ROOT / "packages/gapscan-core/src/gapscan/core/version.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([^"]+)"', text)
    if not match:
        raise SystemExit("no __version__ in gapscan/core/version.py")
    return match.group(1)


def _name(requirement: str) -> str:
    return re.split(r"[<>=!~\[ ;]", requirement, maxsplit=1)[0].strip().lower().replace("_", "-")


def merged_metadata() -> dict[str, object]:
    """Dependencies, extras, scripts and entry points of the four layers, without the internal ones."""
    deps: dict[str, str] = {}
    extras: dict[str, list[str]] = {}
    scripts: dict[str, str] = {}
    entry_points: dict[str, dict[str, str]] = {}
    for layer in LAYERS:
        project = tomllib.loads((ROOT / "packages" / layer / "pyproject.toml").read_text())[
            "project"
        ]
        for req in project.get("dependencies", []):
            if not _name(req).startswith("gapscan-"):
                deps.setdefault(_name(req), req)
        for extra, reqs in project.get("optional-dependencies", {}).items():
            extras.setdefault(extra, []).extend(r for r in reqs if r not in extras.get(extra, []))
        scripts.update(project.get("scripts", {}))
        for group, items in project.get("entry-points", {}).items():
            entry_points.setdefault(group, {}).update(items)
    return {"deps": sorted(deps.values(), key=str.lower), "extras": extras, "scripts": scripts,
            "entry_points": entry_points}  # fmt: skip


def pypi_readme(ver: str) -> str:
    """The README with repository-relative links made absolute, so they work on pypi.org."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    tag = f"v{ver}"
    text = re.sub(r'(src=")(?!https?://)([^"]+)"', rf'\1{RAW}/{tag}/\2"', text)
    text = re.sub(r"(!\[[^\]]*\]\()(?!https?://|#)([^)]+)\)", rf"\1{RAW}/{tag}/\2)", text)
    text = re.sub(r"(\]\()(?!https?://|#|mailto:)([^)]+)\)", rf"\1{REPO}/blob/{tag}/\2)", text)
    text = re.sub(r'(href=")(?!https?://|#)([^"]+)"', rf'\1{REPO}/blob/{tag}/\2"', text)
    return text


def _toml_list(items: list[str]) -> str:
    return "[\n" + "".join(f'    "{i}",\n' for i in items) + "]"


def pyproject(ver: str, meta: dict[str, object]) -> str:
    root = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    deps = meta["deps"]
    extras = meta["extras"]
    scripts = meta["scripts"]
    entry_points = meta["entry_points"]
    assert isinstance(deps, list) and isinstance(extras, dict)
    assert isinstance(scripts, dict) and isinstance(entry_points, dict)
    lines = [
        "[project]",
        'name = "gapscan"',
        f'version = "{ver}"',
        f'description = "{root["description"]}"',
        'readme = "README.md"',
        f'requires-python = "{root["requires-python"]}"',
        'license = { text = "Apache-2.0" }',
        'authors = [{ name = "GapScan contributors" }]',
        'keywords = ["security", "sast", "owasp", "asvs", "devsecops", "sbom", "offline", "semgrep", "llm", "mcp"]',
        "classifiers = "
        + _toml_list(
            [
                "Development Status :: 4 - Beta",
                "Environment :: Console",
                "Intended Audience :: Developers",
                "Intended Audience :: Information Technology",
                "License :: OSI Approved :: Apache Software License",
                "Operating System :: MacOS",
                "Operating System :: POSIX :: Linux",
                "Programming Language :: Python :: 3",
                "Programming Language :: Python :: 3.11",
                "Programming Language :: Python :: 3.12",
                "Programming Language :: Python :: 3.13",
                "Topic :: Security",
                "Topic :: Software Development :: Quality Assurance",
            ]
        ),  # fmt: skip
        "dependencies = " + _toml_list(deps),
        "",
        "[project.urls]",
        'Homepage = "https://gapscan.dev"',
        f'Source = "{REPO}"',
        f'Documentation = "{REPO}#docs"',
        f'Changelog = "{REPO}/blob/main/CHANGELOG.md"',
        f'Issues = "{REPO}/issues"',
        "",
        "[project.optional-dependencies]",
        *[f"{k} = {_toml_list(v)}" for k, v in sorted(extras.items())],
        "",
        "[project.scripts]",
        *[f'{k} = "{v}"' for k, v in sorted(scripts.items())],
        "",
    ]
    for group, items in sorted(entry_points.items()):
        lines.append(f'[project.entry-points."{group}"]')
        lines.extend(f'{k} = "{v}"' for k, v in sorted(items.items()))
        lines.append("")
    lines += [
        "[build-system]",
        'requires = ["hatchling"]',
        'build-backend = "hatchling.build"',
        "",
        "[tool.hatch.build.targets.wheel]",
        'packages = ["src/gapscan"]',
        "",
        "[tool.hatch.build.targets.sdist]",
        'include = ["src/gapscan", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md"]',
        "",
    ]
    return "\n".join(lines)


DIST_MARKER = '''"""Present only in the published package (written by tools/build_dist.py).

Its presence tells GapScan it runs from an installed package rather than a source checkout, so it
keeps models, security data and scan history in the per-user folder (gapscan.paths.app_dir)."""

DISTRIBUTION = "pypi"
'''


def stage(out: Path, ver: str) -> Path:
    stage_dir = out / "stage"
    shutil.rmtree(stage_dir, ignore_errors=True)
    target = stage_dir / "src" / "gapscan"
    for layer in LAYERS:
        shutil.copytree(ROOT / "packages" / layer / "src" / "gapscan", target, ignore=IGNORE,
                        dirs_exist_ok=True)  # fmt: skip
    (target / "_dist.py").write_text(DIST_MARKER, encoding="utf-8")
    (stage_dir / "pyproject.toml").write_text(pyproject(ver, merged_metadata()), encoding="utf-8")
    (stage_dir / "README.md").write_text(pypi_readme(ver), encoding="utf-8")
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        shutil.copy2(ROOT / name, stage_dir / name)
    return stage_dir


def build(out: Path) -> list[Path]:
    ver = version()
    stage_dir = stage(out, ver)
    dist = out / "dist"
    shutil.rmtree(dist, ignore_errors=True)
    subprocess.run(["uv", "build", "--out-dir", str(dist), str(stage_dir)], check=True, timeout=600)
    return sorted(dist.iterdir())


def check(wheel: Path, work: Path) -> None:
    """Install the wheel into a fresh environment and run the commands a new user runs first."""
    venv = work / "venv"
    shutil.rmtree(venv, ignore_errors=True)
    subprocess.run(["uv", "venv", "--python", "3.11", str(venv)], check=True, timeout=300)
    py = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    subprocess.run(
        ["uv", "pip", "install", "--python", str(py), str(wheel)], check=True, timeout=600
    )
    exe = venv / ("Scripts/gapscan.exe" if sys.platform == "win32" else "bin/gapscan")
    home = work / "home"
    env = {"PATH": str(exe.parent), "GAPSCAN_HOME": str(home), "HOME": str(work)}
    out = subprocess.run([str(exe), "version"], check=True, capture_output=True, text=True,
                         timeout=120, env=env).stdout  # fmt: skip
    if version() not in out:
        raise SystemExit(f"`gapscan version` printed {out!r}, expected {version()}")
    probe = (
        "import gapscan._dist, gapscan.cli, gapscan.security_pack, gapscan.scanners.semgrep as s;"
        "from gapscan.registry import registry;"
        "assert 'security' in registry().packs, 'security pack not registered';"
        "assert s.OWN_RULES.is_dir(), s.OWN_RULES;"
        "print('ok')"
    )
    subprocess.run([str(py), "-I", "-c", probe], check=True, timeout=120, env=env, cwd=work)
    print(f"checked {wheel.name}: installs, runs and finds its rules")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "build" / "pypi")
    parser.add_argument("--check", action="store_true", help="install the wheel in a fresh venv")
    args = parser.parse_args()
    files = build(args.out)
    for f in files:
        print(f)
    if args.check:
        check(next(f for f in files if f.suffix == ".whl"), args.out / "check")


if __name__ == "__main__":
    main()
