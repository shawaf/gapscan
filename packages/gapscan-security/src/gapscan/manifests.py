"""Declared dependencies read straight from manifests (text only; nothing is installed or run).

Used by the reachability check (direct or transitive?) and the malicious-package check (which
names does this project ask for?) and, for Gradle projects without a lockfile, the dependency
check. Ecosystem names follow OSV: PyPI, npm, Go, Maven, RubyGems, crates.io.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SKIP_DIRS = {".git", "node_modules", "vendor", "third_party", "build", "dist", ".venv", "venv",
             "__pycache__", ".tox", "target", ".gradle"}  # fmt: skip
MAX_BYTES = 2_000_000


@dataclass(frozen=True)
class Dep:
    ecosystem: str
    name: str  # as written, canonical form via `canonical()`
    version: str | None
    file: str
    line: int
    dev: bool = False


def canonical(ecosystem: str, name: str) -> str:
    n = name.strip().lower()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", n)
    return n


_REQ = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(?:==|~=|>=|<=|>|<|!=)\s*([^\s;,#]+))?"
)


def _requirements(path: Path, rel: str) -> list[Dep]:
    out: list[Dep] = []
    for i, line in enumerate(path.read_text("utf-8", "replace").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", "-", "git+", "http")):
            continue
        m = _REQ.match(s)
        if m:
            out.append(Dep("PyPI", m.group(1), m.group(2), rel, i))
    return out


def _pyproject(path: Path, rel: str) -> list[Dep]:
    try:
        data = tomllib.loads(path.read_text("utf-8", "replace"))
    except tomllib.TOMLDecodeError:
        return []
    specs: list[tuple[str, bool]] = [
        (s, False) for s in data.get("project", {}).get("dependencies", [])
    ]
    for group in data.get("project", {}).get("optional-dependencies", {}).values():
        specs += [(s, True) for s in group]
    for group in data.get("dependency-groups", {}).values():
        specs += [(s, True) for s in group if isinstance(s, str)]
    poetry = data.get("tool", {}).get("poetry", {})
    specs += [(k, False) for k in poetry.get("dependencies", {}) if k.lower() != "python"]
    out: list[Dep] = []
    for spec, dev in specs:
        m = _REQ.match(spec)
        if m:
            out.append(Dep("PyPI", m.group(1), m.group(2), rel, 1, dev))
    return out


def _package_json(path: Path, rel: str) -> list[Dep]:
    try:
        data = json.loads(path.read_text("utf-8", "replace"))
    except json.JSONDecodeError:
        return []
    out: list[Dep] = []
    for key, dev in (
        ("dependencies", False),
        ("devDependencies", True),
        ("optionalDependencies", False),
    ):
        for name, ver in (data.get(key) or {}).items():
            out.append(Dep("npm", name, str(ver), rel, 1, dev))
    return out


def _go_mod(path: Path, rel: str) -> list[Dep]:
    out: list[Dep] = []
    in_block = False
    for i, line in enumerate(path.read_text("utf-8", "replace").splitlines(), 1):
        s = line.split("//")[0].strip()
        if s.startswith("require ("):
            in_block = True
        elif in_block and s == ")":
            in_block = False
        elif in_block or s.startswith("require "):
            parts = s.removeprefix("require ").split()
            if len(parts) >= 2:
                out.append(Dep("Go", parts[0], parts[1], rel, i))
    return out


def _pom(path: Path, rel: str) -> list[Dep]:
    text = path.read_text("utf-8", "replace")
    return [
        Dep("Maven", f"{g}:{a}", v or None, rel, text[: m.start()].count("\n") + 1)
        for m in re.finditer(
            r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?",
            text,
        )
        for g, a, v in [(m.group(1).strip(), m.group(2).strip(), (m.group(3) or "").strip())]
    ]


def _gemfile(path: Path, rel: str) -> list[Dep]:
    out: list[Dep] = []
    for i, line in enumerate(path.read_text("utf-8", "replace").splitlines(), 1):
        m = re.match(r"""\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", line)
        if m:
            out.append(Dep("RubyGems", m.group(1), m.group(2), rel, i))
    return out


def _cargo(path: Path, rel: str) -> list[Dep]:
    try:
        data = tomllib.loads(path.read_text("utf-8", "replace"))
    except tomllib.TOMLDecodeError:
        return []
    out: list[Dep] = []
    for key, dev in (("dependencies", False), ("dev-dependencies", True)):
        for name, spec in (data.get(key) or {}).items():
            ver = spec if isinstance(spec, str) else (spec or {}).get("version")
            out.append(Dep("crates.io", name, ver, rel, 1, dev))
    return out


def _line_of(text: str, key: str, section: str = "") -> int:
    """Line of a TOML key definition (`key = ...`) inside `[section]` (aliases often repeat a
    [versions] key of the same name)."""
    start = 0
    if section and (h := re.search(rf"^\s*\[{re.escape(section)}\]", text, re.M)):
        start = h.end()
    m = re.compile(rf"^\s*\"?{re.escape(key)}\"?\s*=", re.M).search(text, start)
    return text[: m.start()].count("\n") + 1 if m else 1


def _catalog_version(spec: object, versions: dict[str, object]) -> str | None:
    """A version in a Gradle version catalog: "1.2", {ref = "x"}, or a rich version table."""
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        if "ref" in spec:
            return _catalog_version(versions.get(str(spec["ref"])), versions)
        for key in ("strictly", "require", "prefer"):
            if isinstance(spec.get(key), str):
                return str(spec[key])
    return None


def _gradle_catalog(path: Path, rel: str) -> list[Dep]:
    """gradle/libs.versions.toml: the [libraries] of a Gradle version catalog."""
    text = path.read_text("utf-8", "replace")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    versions = data.get("versions") or {}
    out: list[Dep] = []
    for alias, spec in (data.get("libraries") or {}).items():
        if isinstance(spec, str):
            parts = spec.split(":")
            if len(parts) >= 2:
                out.append(Dep("Maven", f"{parts[0]}:{parts[1]}", parts[2] if len(parts) > 2 else None,
                               rel, _line_of(text, alias, "libraries")))  # fmt: skip
            continue
        if not isinstance(spec, dict):
            continue
        module = spec.get("module") or (
            f"{spec['group']}:{spec['name']}" if spec.get("group") and spec.get("name") else None
        )
        if module:
            out.append(Dep("Maven", str(module), _catalog_version(spec.get("version"), versions),
                           rel, _line_of(text, alias, "libraries")))  # fmt: skip
    return out


_GRADLE_DEP = re.compile(
    r"""^\s*(\w*(?:[Ii]mplementation|[Aa]pi|[Cc]ompileOnly|[Rr]untimeOnly|kapt|ksp|annotationProcessor|classpath))"""
    r"""\s*\(?\s*(?:platform\(|enforcedPlatform\()?\s*["']([\w.\-]+):([\w.\-]+):([^"'@:)]+)["']"""
)
_GRADLE_VAR = re.compile(
    r"""^\s*(?:val|var|def|ext\.|extra\[?)?\s*["']?(\w+)["']?\]?\s*=\s*["']([^"'$]+)["']"""
)


def _gradle_build(path: Path, rel: str) -> list[Dep]:
    """build.gradle / build.gradle.kts: "group:artifact:version" coordinates. `$x` / `${x}` are
    resolved from simple assignments in the same file and the project's gradle.properties."""
    text = path.read_text("utf-8", "replace")
    variables: dict[str, str] = {}
    for props in (path.parent / "gradle.properties", path.parent.parent / "gradle.properties"):
        if props.is_file():
            for line in props.read_text("utf-8", "replace").splitlines():
                key, sep, value = line.partition("=")
                if sep and not key.strip().startswith("#"):
                    variables.setdefault(key.strip(), value.strip())
    for line in text.splitlines():
        if m := _GRADLE_VAR.match(line):
            variables[m.group(1)] = m.group(2)
    out: list[Dep] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = _GRADLE_DEP.match(line)
        if not m:
            continue
        conf, group, artifact, version = m.groups()
        version = re.sub(r"\$\{?(\w+)\}?", lambda v: variables.get(v.group(1), v.group(0)), version)
        dev = conf.startswith(("test", "androidTest", "kaptTest", "kspTest", "debug"))
        out.append(
            Dep("Maven", f"{group}:{artifact}", None if "$" in version else version, rel, i, dev)
        )
    return out


_PARSERS = {
    "package.json": _package_json, "go.mod": _go_mod, "pom.xml": _pom, "gemfile": _gemfile,
    "cargo.toml": _cargo, "pyproject.toml": _pyproject, "libs.versions.toml": _gradle_catalog,
    "build.gradle": _gradle_build, "build.gradle.kts": _gradle_build,
}  # fmt: skip


def declared_dependencies(target: Path) -> list[Dep]:
    out: list[Dep] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            low = name.lower()
            parser = _PARSERS.get(low)
            if parser is None and re.fullmatch(r"requirements[\w.-]*\.txt", low):
                parser = _requirements
            if parser is None:
                continue
            full = Path(root) / name
            try:
                if full.stat().st_size > MAX_BYTES:
                    continue
                out += parser(full, str(full.relative_to(target)))
            except (OSError, ValueError):
                continue
    return out


def add_declared_to_sbom(sbom: dict[str, Any] | None, deps: list[Dep]) -> dict[str, Any] | None:
    """Trivy builds the SBOM from lockfiles and cannot see Gradle dependencies without one (most
    Android apps). Add the Maven coordinates declared in version catalogs and build scripts as
    direct dependencies of the project, skipping any Trivy already listed."""
    gradle = {(d.name, d.version): d for d in deps if d.ecosystem == "Maven" and d.version}
    if not gradle:
        return sbom
    doc: dict[str, Any] = sbom or {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}
    comps: list[dict[str, Any]] = doc.setdefault("components", [])
    have = {(c.get("group", "") + ":" + c.get("name", ""), c.get("version")) for c in comps}
    have |= {(c.get("name", ""), c.get("version")) for c in comps}
    root = (doc.setdefault("metadata", {}).get("component") or {}).get("bom-ref")
    if not root:
        root = "gapscan:declared"
        doc["metadata"]["component"] = {"bom-ref": root, "type": "application", "name": "project"}
    added = []
    for (name, version), d in sorted(gradle.items()):
        if (name, version) in have:
            continue
        group, _, artifact = name.partition(":")
        purl = f"pkg:maven/{group}/{artifact}@{version}"
        comps.append({"bom-ref": purl, "type": "library", "group": group, "name": name,
                      "version": version, "purl": purl,
                      "properties": [{"name": "gapscan:declared_in", "value": d.file}]})  # fmt: skip
        added.append(purl)
    graph: list[dict[str, Any]] = doc.setdefault("dependencies", [])
    entry = next((g for g in graph if g.get("ref") == root), None)
    if entry is None:
        entry = {"ref": root, "dependsOn": []}
        graph.append(entry)
    entry.setdefault("dependsOn", []).extend(added)
    return doc
