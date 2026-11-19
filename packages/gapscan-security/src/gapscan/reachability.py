"""Dependency reachability: is the vulnerable package, and where known the vulnerable function,
actually used by this project?

Statuses (strings on `Finding.reachability`):

    reachable      a vulnerable function is called in a file that imports the package
    imported       the package is imported, but no function-level data says which call is the
                   vulnerable one (so the finding stays at full priority)
    not_reachable  the package is imported but none of the vulnerable functions is called
    not_imported   a direct dependency that no source file imports (build/runtime plugin use is
                   possible, so this lowers priority instead of dropping the finding)
    transitive     not declared by the project: pulled in by another dependency, so this check
                   cannot say (needs that dependency's own code)

Symbols come from the advisory when it lists them (`raw["symbols"]`) and from `reach_hints.toml`.
Text only: nothing is installed, built or run (hard rule #1).
"""

from __future__ import annotations

import logging
import tomllib
from functools import cache
from pathlib import Path

from .context.callgraph import find_import_sites
from .context.treesitter import calls, detect_language, parse
from .manifests import canonical, declared_dependencies
from .models import Category, Finding

log = logging.getLogger(__name__)

HINTS = Path(__file__).parent / "reach_hints.toml"
MAX_PACKAGES = 60
ECOSYSTEM_BY_FILE = {
    "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm", "package.json": "npm",
    "requirements.txt": "PyPI", "poetry.lock": "PyPI", "uv.lock": "PyPI", "pipfile.lock": "PyPI",
    "go.mod": "Go", "go.sum": "Go", "pom.xml": "Maven", "gemfile.lock": "RubyGems",
    "cargo.lock": "crates.io",
}  # fmt: skip


@cache
def _hints() -> dict[tuple[str, str], list[str]]:
    data = tomllib.loads(HINTS.read_text("utf-8"))
    out: dict[tuple[str, str], list[str]] = {}
    for h in data.get("hint", []):
        out.setdefault((h["cve"], canonical(h["ecosystem"], h["package"])), []).extend(h["symbols"])
    return out


def _ecosystem(f: Finding) -> str:
    eco = str(f.raw.get("ecosystem") or "")
    if eco:
        return eco.split(":")[0]
    name = Path(f.file or "").name.lower()
    return ECOSYSTEM_BY_FILE.get(name, "")


def symbols_for(f: Finding, eco: str) -> list[str]:
    syms = [str(s) for s in f.raw.get("symbols", [])]
    pkg = canonical(eco, f.package or "")
    for cve in f.cve:
        syms += _hints().get((cve, pkg), [])
    return sorted(set(syms))


def _called(target: Path, rel: str, symbols: list[str]) -> list[tuple[int, str]]:
    try:
        src = (target / rel).read_bytes()
    except OSError:
        return []
    pf = parse(rel, src, detect_language(rel))
    if pf is None:
        return []
    wanted = set(symbols)
    return [(c.line, c.text[:120]) for c in calls(pf) if c.name in wanted]


def annotate(findings: list[Finding], target: Path) -> None:
    """Set `reachability` and `reachability_evidence` on every dependency finding (in place)."""
    deps = [f for f in findings if f.category == Category.DEPENDENCY and f.package]
    if not deps:
        return
    declared = {
        (d.ecosystem, canonical(d.ecosystem, d.name)) for d in declared_dependencies(target)
    }
    declared_names = {n for _, n in declared}
    cache_imports: dict[str, list[tuple[str, int, str]]] = {}
    packages = sorted({f.package or "" for f in deps})
    if len(packages) > MAX_PACKAGES:  # keep the walk bounded on huge lockfiles
        rank = {p: max(x.severity.rank for x in deps if x.package == p) for p in packages}
        keep = set(sorted(packages, key=lambda p: -rank[p])[:MAX_PACKAGES])
    else:
        keep = set(packages)
    for f in deps:
        pkg = f.package or ""
        eco = _ecosystem(f)
        is_direct = (eco, canonical(eco, pkg)) in declared or canonical(eco, pkg) in declared_names
        if pkg not in keep:
            f.reachability, f.reachability_evidence = None, []
            continue
        if pkg not in cache_imports:
            try:
                cache_imports[pkg] = find_import_sites(target, pkg, limit=20)
            except Exception:  # noqa: BLE001 - reachability must never fail a scan
                log.warning("import search failed for %s", pkg)
                cache_imports[pkg] = []
        sites = cache_imports[pkg]
        if not sites:
            if is_direct:
                f.reachability = "not_imported"
                f.reachability_evidence = [
                    f"{pkg} is declared in a manifest but no source file imports it"
                ]
            else:
                f.reachability = "transitive"
                f.reachability_evidence = [
                    f"{pkg} is not declared by this project (transitive dependency)"
                ]
            continue
        evidence = [f"imported at {p}:{ln}: {txt}" for p, ln, txt in sites[:3]]
        syms = symbols_for(f, eco)
        if not syms:
            f.reachability, f.reachability_evidence = "imported", evidence
            continue
        used: list[str] = []
        for rel in sorted({p for p, _, _ in sites}):
            used += [
                f"vulnerable function called at {rel}:{ln}: {txt}"
                for ln, txt in _called(target, rel, syms)[:2]
            ]
        if used:
            f.reachability, f.reachability_evidence = "reachable", used[:4] + evidence[:1]
        else:
            f.reachability = "not_reachable"
            f.reachability_evidence = [
                f"{pkg} is imported but none of {', '.join(syms[:6])} is called"
            ] + evidence[:2]
