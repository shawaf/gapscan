"""Dependency fixes: upgrade a vulnerable package to the nearest version that fixes its advisories.

For every vulnerable package with a known fixed version, this finds where the project declares
it (requirements files, pyproject.toml, package.json, go.mod, pom.xml, Gradle catalogs and build
files, Gemfile, Cargo.toml) and proposes a one-line edit that raises the version, keeping the operator the
project uses (`==`, `^`, `~`, `>=`). The result is a unified diff the user can review, apply, or turn
into a pull request with `gapscan pr`.

What it does not do, on purpose:
- It never runs a package manager. `npm install`, `pip install` or `go get` can execute code from
  the project and its dependencies (hard rule 1), so a lockfile next to an edited manifest is left
  as it is and the fix says it must be regenerated.
- It does not guess fixes for transitive dependencies (packages the project does not declare); it
  says so, so the user can upgrade the parent or add an override.

A fix is marked verified only when an offline rescan of a copy with the edit applied no longer
reports the advisories. When a lockfile decides the installed version, the rescan cannot see the
edit, and the fix is marked as needing the lockfile to be regenerated instead.
"""

from __future__ import annotations

import difflib
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field

from .manifests import Dep, canonical, declared_dependencies
from .models import Category, Finding
from .scanners.osv import LOCKFILES
from .versions import ver_key

# Lockfiles that pin what a manifest declares, by ecosystem (names from the OSV adapter).
_LOCKS_BY_ECOSYSTEM: dict[str, set[str]] = {}
for _name, _eco in LOCKFILES.items():
    _LOCKS_BY_ECOSYSTEM.setdefault(_eco, set()).add(_name)
_VERSION = re.compile(r"v?\d+(?:\.[0-9A-Za-z]+)*(?:[-+][0-9A-Za-z.\-+]+)?")
MAX_EDIT_LINES = 8  # how far below a pom.xml <dependency> the <version> may sit


class ManifestEdit(BaseModel):
    file: str  # relative to the project folder
    line: int
    before: str
    after: str


class DependencyFix(BaseModel):
    package: str
    ecosystem: str
    from_version: str | None = None
    to_version: str
    advisories: list[str] = Field(default_factory=list)
    edits: list[ManifestEdit] = Field(default_factory=list)
    diff: str = ""
    lockfiles: list[str] = Field(default_factory=list)  # to regenerate after the edit
    notes: list[str] = Field(default_factory=list)
    verified: bool | None = None  # None: could not be checked by a rescan


@dataclass
class _Upgrade:
    package: str
    ecosystem: str
    installed: str | None
    target: str
    advisories: list[str]


def plan_upgrades(findings: list[Finding]) -> list[_Upgrade]:
    """One upgrade per vulnerable package: the highest of its advisories' fixed versions, so a
    single bump closes all of them. Packages with no known fix are left out."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if f.category != Category.DEPENDENCY or not f.package or not f.fixed_version:
            continue
        eco = str(f.raw.get("ecosystem") or "")
        groups.setdefault((eco, f.package), []).append(f)
    plans = []
    for (eco, package), fs in sorted(groups.items()):
        target = max((f.fixed_version or "" for f in fs), key=ver_key)
        installed = next((f.version for f in fs if f.version), None)
        if installed and ver_key(target) <= ver_key(installed):
            continue
        ids = sorted({c for f in fs for c in (f.cve or [f.rule_id])})
        plans.append(_Upgrade(package, eco, installed, target, ids))
    return plans


def _bump(spec_line: str, start: int, old: str, new: str) -> str | None:
    """Replace the version `old` at or after `start` in the line with `new`, keeping a `v` prefix
    and the operator in front of it."""
    idx = spec_line.find(old, start)
    if idx < 0:
        return None
    if old.startswith("v") and not new.startswith("v"):
        new = "v" + new
    return spec_line[:idx] + new + spec_line[idx + len(old) :]


def _edit_for(dep: Dep, target_version: str, root: Path) -> ManifestEdit | None:
    if not dep.version:
        return None
    m = _VERSION.search(dep.version)
    if not m:  # a range like "*", a git URL or a catalog reference: nothing literal to raise
        return None
    old = m.group(0)
    path = root / dep.file
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    name_rx = re.compile(re.escape(dep.name.split(":")[-1]), re.IGNORECASE)
    if dep.line > 1:  # the parser knows the line (pom.xml: the <dependency> line)
        candidates = range(dep.line - 1, min(len(lines), dep.line - 1 + MAX_EDIT_LINES))
    else:  # package.json, pyproject.toml, Cargo.toml: find the line naming the package
        candidates = range(len(lines))
    for i in candidates:
        line = lines[i]
        hit = name_rx.search(line)
        if dep.line > 1 and i > dep.line - 1:
            hit = hit or (re.search(r"<version>", line) if dep.file.endswith(".xml") else None)
        if not hit or old not in line:
            continue
        start = hit.end() if i == dep.line - 1 or dep.line <= 1 else 0
        new_line = _bump(line, start, old, target_version)
        if new_line and new_line != line:
            return ManifestEdit(file=dep.file, line=i + 1, before=line, after=new_line)
    return None


def _apply(root: Path, edits: list[ManifestEdit]) -> dict[str, tuple[str, str]]:
    """file -> (old text, new text) with every edit applied."""
    out: dict[str, tuple[str, str]] = {}
    for e in edits:
        old_text = out[e.file][1] if e.file in out else (root / e.file).read_text(encoding="utf-8")
        lines = old_text.split("\n")
        if lines[e.line - 1] != e.before:
            continue
        lines[e.line - 1] = e.after
        first = out[e.file][0] if e.file in out else old_text
        out[e.file] = (first, "\n".join(lines))
    return out


def unified_diff(changes: dict[str, tuple[str, str]]) -> str:
    parts: list[str] = []
    for file, (before, after) in sorted(changes.items()):
        parts += difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{file}",
            tofile=f"b/{file}",
        )
    return "".join(parts)


def combined_diff(root: Path, fixes: list[DependencyFix]) -> str:
    """One patch for several fixes. Each fix's own `diff` is against the original files, so two
    fixes in the same manifest would conflict if concatenated (`git apply` rejects the second hunk);
    here every kept edit is applied to the same copy of each file and diffed once. Fixes a rescan
    showed do not work are left out."""
    edits = [e for fx in fixes if fx.verified is not False for e in fx.edits]
    return unified_diff(_apply(root, edits))


def _lockfiles_near(root: Path, manifest: str, ecosystem: str) -> list[str]:
    names = _LOCKS_BY_ECOSYSTEM.get(ecosystem, set())
    folder = (root / manifest).parent
    try:
        present = {p.name.lower(): p for p in folder.iterdir() if p.is_file()}
    except OSError:
        return []
    manifest_name = Path(manifest).name.lower()
    return sorted(
        str(p.relative_to(root)) for n, p in present.items() if n in names and n != manifest_name
    )


Rescan = Callable[[Path], list[Finding]]


def propose_dependency_fixes(
    root: Path, findings: list[Finding], *, rescan: Rescan | None = None
) -> list[DependencyFix]:
    """Upgrade proposals for the vulnerable dependencies in `findings`. `rescan`, when given, runs
    the offline dependency scanner over a folder and is used to verify each proposal on a copy."""
    declared = declared_dependencies(root)
    fixes: list[DependencyFix] = []
    for up in plan_upgrades(findings):
        fix = DependencyFix(
            package=up.package, ecosystem=up.ecosystem, from_version=up.installed,
            to_version=up.target, advisories=up.advisories,
        )  # fmt: skip
        key = canonical(up.ecosystem, up.package)
        deps = [
            d for d in declared
            if canonical(d.ecosystem, d.name) == key and (not up.ecosystem or d.ecosystem == up.ecosystem)
        ]  # fmt: skip
        if not deps:
            fix.notes.append(
                f"{up.package} is not declared by this project (a transitive dependency): upgrade "
                f"the package that pulls it in, or pin {up.package} >= {up.target} with your "
                "package manager's override."
            )
            fixes.append(fix)
            continue
        for dep in deps:
            edit = _edit_for(dep, up.target, root)
            if edit is None:
                fix.notes.append(
                    f"{dep.file} declares {up.package} without a literal version to raise; set it "
                    f"to {up.target} or later by hand."
                )
                continue
            fix.edits.append(edit)
            fix.lockfiles += _lockfiles_near(root, dep.file, dep.ecosystem)
        fix.lockfiles = sorted(set(fix.lockfiles))
        changes = _apply(root, fix.edits)
        fix.diff = unified_diff(changes)
        if fix.lockfiles:
            fix.notes.append(
                f"Regenerate {', '.join(fix.lockfiles)} with your package manager after the edit. "
                "GapScan does not run package managers, because they can execute project code."
            )
        elif changes and rescan is not None:
            fix.verified = _verify(root, changes, up, rescan)
            if fix.verified is False:
                fix.notes.append("A rescan with the edit applied still reports the advisory.")
        fixes.append(fix)
    return fixes


def _verify(root: Path, changes: dict[str, tuple[str, str]], up: _Upgrade, rescan: Rescan) -> bool:
    with tempfile.TemporaryDirectory(prefix="gapscan-depfix-") as tmp:
        copy = Path(tmp) / "project"
        copy.mkdir()
        for file in changes:  # only the manifests: the dependency scan reads nothing else
            dest = copy / file
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / file, dest)
            dest.write_text(changes[file][1], encoding="utf-8")
        after = rescan(copy)
    still = {
        c
        for f in after
        if f.package and canonical(up.ecosystem, f.package) == canonical(up.ecosystem, up.package)
        for c in (f.cve or [f.rule_id])
    }
    return not (still & set(up.advisories))
