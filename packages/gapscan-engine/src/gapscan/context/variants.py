"""Android build variants from Gradle files, read as text (never built or run: hard rule #1).

A finding often holds only in some builds: a key file under `app/src/dev/`, encryption switched
on by a `buildConfigField` in the prod flavor only, cleartext allowed in a debug-only manifest. It
answers "which variants ship this file?" and "what does each flavor/build type set?", so the deep
dive can state scope from facts instead of guessing.

Supported: Gradle Kotlin DSL and Groovy, `productFlavors { create("dev") {...} }` / `dev {...}`,
`buildTypes { release {...} }` / `getByName("release") {...}`, `buildConfigField`, `resValue`,
`manifestPlaceholders`, and the standard source-set folders (`src/main`, `src/<flavor>`,
`src/<buildType>`, `src/<flavor><BuildType>`). Variants are formed as flavor x build type, which
is exact for the common single-dimension case; several flavor dimensions are not combined.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_SKIP = {".git", ".gradle", "build", "node_modules", ".idea", "Pods"}
_BLOCK_NAME = re.compile(
    r"""(?:create|register|getByName|maybeCreate)\s*\(\s*["']([\w-]+)["']\s*\)\s*\{|"""
    r"""(?<![\w.])([A-Za-z_]\w*)\s*\{"""
)
_SETTING = re.compile(
    r"""(buildConfigField|resValue)\s*\(?\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*,\s*(.+?)\)?\s*$|"""
    r"""(isMinifyEnabled|minifyEnabled|isDebuggable|debuggable|applicationIdSuffix|signingConfig)\b\s*=?\s*(.+)$|"""
    r"""manifestPlaceholders\s*(?:\[\s*["'](\w+)["']\s*\]\s*=|\+?=\s*mapOf\()\s*(.+)$"""
)
_NOT_NAMES = {"android", "defaultConfig", "productFlavors", "buildTypes", "sourceSets",
              "dependencies", "signingConfigs", "compileOptions", "kotlinOptions", "buildFeatures",
              "packaging", "lint", "testOptions", "externalNativeBuild", "splits",
              "composeOptions"}  # fmt: skip


@dataclass
class Variant:
    name: str
    settings: list[tuple[int, str]] = field(default_factory=list)  # (line, text)
    line: int = 0


@dataclass
class Module:
    gradle_file: str  # relative to the target
    root: str  # module folder relative to the target ("app")
    flavors: list[Variant] = field(default_factory=list)
    build_types: list[Variant] = field(default_factory=list)
    default_config: list[tuple[int, str]] = field(default_factory=list)
    source_sets: list[str] = field(default_factory=list)  # folder names under src/


def _block(lines: list[str], start: int) -> int:
    """Index of the line closing the `{` block that opens on line index `start`."""
    depth = 0
    for i in range(start, len(lines)):
        depth += lines[i].count("{") - lines[i].count("}")
        if depth <= 0 and i >= start and "{" in "".join(lines[start : i + 1]):
            return i
    return len(lines) - 1


def _children(lines: list[str], start: int, end: int) -> list[Variant]:
    """Named sub-blocks directly inside the block lines[start..end]."""
    out: list[Variant] = []
    i = start + 1
    while i < end:
        m = _BLOCK_NAME.search(lines[i])
        name = (m.group(1) or m.group(2)) if m else None
        if m and name and name not in _NOT_NAMES:
            close = _block(lines, i)
            v = Variant(name=name, line=i + 1)
            for k in range(i + 1, close):
                text = lines[k].strip()
                if text and _SETTING.search(text):
                    v.settings.append((k + 1, text[:200]))
            out.append(v)
            i = close + 1
            continue
        i += 1
    return out


def _find(lines: list[str], word: str) -> int | None:
    for i, line in enumerate(lines):
        if re.search(rf"(?<![\w.]){word}\s*\{{", line):
            return i
    return None


def parse_module(target: Path, gradle: Path) -> Module | None:
    text = gradle.read_text(encoding="utf-8", errors="replace")
    if (
        "com.android.application" not in text
        and "com.android.library" not in text
        and (not re.search(r"(?<![\w.])android\s*\{", text))
    ):
        return None
    lines = text.splitlines()
    module_dir = gradle.parent
    mod = Module(gradle_file=gradle.relative_to(target).as_posix(),
                 root=module_dir.relative_to(target).as_posix() or ".")  # fmt: skip
    pf = _find(lines, "productFlavors")
    if pf is not None:
        mod.flavors = _children(lines, pf, _block(lines, pf))
    bt = _find(lines, "buildTypes")
    types = _children(lines, bt, _block(lines, bt)) if bt is not None else []
    names = {t.name for t in types}
    for default in ("debug", "release"):  # always exist, even when not configured
        if default not in names:
            types.append(Variant(name=default))
    mod.build_types = types
    dc = _find(lines, "defaultConfig")
    if dc is not None:
        end = _block(lines, dc)
        mod.default_config = [(k + 1, lines[k].strip()[:200]) for k in range(dc + 1, end)
                              if _SETTING.search(lines[k].strip())]  # fmt: skip
    src = module_dir / "src"
    if src.is_dir():
        mod.source_sets = sorted(p.name for p in src.iterdir() if p.is_dir())
    return mod


def find_modules(target: Path) -> list[Module]:
    mods: list[Module] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP)
        for name in ("build.gradle.kts", "build.gradle"):
            if name in files:
                mod = parse_module(target, Path(root) / name)
                if mod is not None:
                    mods.append(mod)
    return mods


def variant_names(mod: Module) -> list[str]:
    flavors = [f.name for f in mod.flavors] or [""]
    types = [t.name for t in mod.build_types]
    return [f + (t[0].upper() + t[1:] if f else t) for f in flavors for t in types]


def variants_including(mod: Module, rel_file: str) -> list[str] | None:
    """Variants whose build includes `rel_file` (relative to the target), or None when the file is
    not under a source set of this module."""
    prefix = (mod.root + "/src/") if mod.root != "." else "src/"
    if not rel_file.startswith(prefix):
        return None
    source_set = rel_file[len(prefix) :].split("/", 1)[0]
    all_variants = variant_names(mod)
    if source_set == "main":
        return all_variants
    if source_set.startswith(("test", "androidTest")):
        return []  # tests are not shipped
    picked = []
    flavors = [f.name for f in mod.flavors]
    for v in all_variants:
        flavor = next((f for f in flavors if v.startswith(f)), "")
        build_type = v[len(flavor) :].lower() if flavor else v
        if source_set in (v, flavor, build_type) or source_set.lower() == v.lower():
            picked.append(v)
    return picked


@lru_cache(maxsize=8)
def _cached(target: str) -> tuple[Module, ...]:
    return tuple(find_modules(Path(target)))


def modules(target: Path) -> tuple[Module, ...]:
    """Android modules of a project, parsed once per scan target."""
    return _cached(str(target.resolve()))


def shipped_in(target: Path, rel: str) -> list[str]:
    """Variants whose APK contains `rel` (a file in a shipped source set), else []."""
    for mod in modules(target):
        inc = variants_including(mod, rel)
        if inc:
            return inc
    return []


_FLAG = re.compile(r"\bBuildConfig\.([A-Z][A-Z0-9_]*)\b")


def context_lines(target: Path, rel: str, code: str) -> list[str]:
    """For the triage context: which variants ship `rel`, and what each flavor/build type sets for
    the BuildConfig flags the shown code checks. Empty for files outside an Android module."""
    for mod in modules(target):
        inc = variants_including(mod, rel)
        if inc is None:
            continue
        others = [v for v in variant_names(mod) if v not in inc]
        out = [f"{rel} is built into: {', '.join(inc) or 'no shipped variant (test code)'}"
               + (f" (not into: {', '.join(others)})" if others else "")]  # fmt: skip
        for flag in sorted(set(_FLAG.findall(code))):
            for label, items in (("flavor", mod.flavors), ("buildType", mod.build_types)):
                for v in items:
                    for n, text in v.settings:
                        if f'"{flag}"' in text or f"'{flag}'" in text:
                            out.append(f"{label} {v.name} sets {flag}: {text} "
                                       f"({mod.gradle_file}:{n})")  # fmt: skip
            for n, text in mod.default_config:
                if f'"{flag}"' in text:
                    out.append(f"defaultConfig sets {flag}: {text} ({mod.gradle_file}:{n})")
        return out
    return []


def describe(target: Path, rel_file: str | None = None) -> tuple[str, list[tuple[str, int, int]]]:
    """Human-readable variant summary, plus the Gradle lines it quotes (for grounding)."""
    mods = find_modules(target)
    if not mods:
        return "no Android Gradle module found in the project", []
    out: list[str] = []
    seen: list[tuple[str, int, int]] = []
    for mod in mods:
        out.append(f"MODULE {mod.root} ({mod.gradle_file})")
        out.append("  variants: " + ", ".join(variant_names(mod)))
        out.append("  source sets present: " + (", ".join(mod.source_sets) or "none"))
        for label, line_text in (("defaultConfig", mod.default_config),):
            for n, text in line_text:
                out.append(f"  {label} {mod.gradle_file}:{n}: {text}")
                seen.append((mod.gradle_file, n, n))
        for kind, items in (("flavor", mod.flavors), ("buildType", mod.build_types)):
            for v in items:
                where = f" ({mod.gradle_file}:{v.line})" if v.line else " (Gradle default)"
                out.append(f"  {kind} {v.name}{where}")
                if v.line:
                    seen.append((mod.gradle_file, v.line, v.line))
                for n, text in v.settings:
                    out.append(f"    {mod.gradle_file}:{n}: {text}")
                    seen.append((mod.gradle_file, n, n))
        if rel_file:
            inc = variants_including(mod, rel_file)
            if inc is not None:
                shipped = ", ".join(inc) if inc else "none (test code is not shipped)"
                out.append(f"  {rel_file} is built into: {shipped}")
    return "\n".join(out), seen
