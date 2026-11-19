"""CycloneDX SBOM -> table rows (package, version, license, direct/transitive)."""

from __future__ import annotations

from typing import Any

from .schema import SbomRow


def _license(component: dict[str, Any]) -> str:
    names = []
    for entry in component.get("licenses") or []:
        lic = entry.get("license") or {}
        names.append(lic.get("id") or lic.get("name") or entry.get("expression") or "")
    return ", ".join(n for n in names if n)


def _ecosystem(component: dict[str, Any]) -> str:
    purl = str(component.get("purl", ""))
    if purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0]
    return ""


def sbom_rows(sbom: dict[str, Any] | None, vulnerable: set[tuple[str, str]]) -> list[SbomRow]:
    """Library components with direct/transitive flags from the SBOM's dependency graph.
    `vulnerable` is a set of (package, version) with open findings."""
    if not sbom:
        return []
    comps = sbom.get("components", [])
    deps = {d["ref"]: d.get("dependsOn", []) for d in sbom.get("dependencies", [])}
    apps = {c["bom-ref"] for c in comps if c.get("type") == "application"}
    root = (sbom.get("metadata", {}).get("component") or {}).get("bom-ref")
    direct_refs: set[str] = set()
    for ref in apps | ({root} if root else set()):
        direct_refs.update(deps.get(ref, []))
    has_graph = bool(deps)
    rows = []
    for c in comps:
        if c.get("type") == "application":
            continue
        ref = c.get("bom-ref")
        name = c.get("name", "")
        # A component is direct when a manifest/application depends on it.
        direct: bool | None = (
            (ref in direct_refs or (c.get("purl") in direct_refs)) if has_graph else None
        )
        rows.append(SbomRow(name=name, version=c.get("version", ""), type=c.get("type", "library"),
                            ecosystem=_ecosystem(c), license=_license(c), direct=direct,
                            vulnerable=(name, c.get("version", "")) in vulnerable))  # fmt: skip
    return sorted(rows, key=lambda r: (not r.vulnerable, r.name.lower()))
