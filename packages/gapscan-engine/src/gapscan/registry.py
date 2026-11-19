"""The registry domain packs fill with their scanners (ARCHITECTURE.md section 3).

Besides scanners and target packs, a pack registers the steps the engine runs on its behalf, so
the engine never imports a pack: how evidence is collected (`add_collector`), what it adds to
findings during normalize (`add_annotator`), and which findings code context traces data flow
for (`add_flow_filter`).

A pack is a `register(registry)` function published under the `gapscan.packs` entry-point group,
so adding a scanner is a new module plus one registration, not an edit to a central list. The
registry itself knows no domain: it never imports a pack, it only loads the entry points.

Only packs named in `scanners.packs` are loaded (default: the built-in `security` pack). A pack's
scanners run during `scan`, so an installed package must never add one on its own (hard rule 2:
no network calls during a local scan). Skipped packs are skipped before their code is imported.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import import_module
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path
from typing import Protocol

from .config import Config
from .core.interfaces import Annotator, Scanner, TargetPack
from .models import Category, Finding, ScanResult

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "gapscan.packs"
DEFAULT_PACKS = ("security",)
# GapScan's own packs, name -> the only target that name may load. An entry point that reuses a
# built-in name for other code is refused. Also loaded directly when the package metadata is
# missing (a frozen app or an uninstalled checkout), so a scan never runs with no scanners.
BUILTIN_PACKS = {"security": "gapscan.security_pack:register"}


@dataclass(frozen=True)
class ScannerSpec:
    name: str
    factory: Callable[[Config], Scanner]
    selectable: bool = True  # offered in the manager's scanner picker
    pack: str = ""  # set by the registry: the pack that registered it
    description: str = ""  # one line for people: what the scanner looks at
    capability: str = ""  # the capability it belongs to (e.g. "sast"); "" means ungrouped


@dataclass(frozen=True)
class Capability:
    """A named group of scanners inside a domain (ARCHITECTURE.md: Project -> Service (domain) ->
    Capability). A project enables capabilities, not individual scanners; the registry maps the
    enabled capabilities to the scanners that run. Generic by design: the ids and labels are the
    domain pack's data, so core/engine never name a security capability."""

    id: str
    label: str  # short name for people, e.g. "Static analysis (SAST)"
    description: str = ""  # one line: what this capability looks at
    domain: str = ""  # set by the registry: the pack that registered it
    reserved: bool = False  # declared for the model but has no scanners yet (e.g. dynamic)


class Collector(Protocol):
    """The `scan` stage of a pack: runs its enabled scanners over the target (never executing it,
    hard rule 1) and returns their raw findings and runs, secrets already redacted."""

    def __call__(
        self, config: Config, target: Path, workdir: Path, *, keep_workdir: bool,
        images: Sequence[Path],
    ) -> ScanResult: ...  # fmt: skip


AnnotatorFactory = Callable[[Config | None], Annotator | None]  # None: needs a config it lacks


@dataclass
class Registry:
    scanners: dict[str, ScannerSpec] = field(default_factory=dict)
    target_packs: list[TargetPack] = field(default_factory=list)  # in registration order
    packs: list[str] = field(default_factory=list)  # loaded, in load order
    capabilities: dict[str, Capability] = field(default_factory=dict)  # id -> capability
    collectors: list[Collector] = field(default_factory=list)
    annotator_factories: list[AnnotatorFactory] = field(default_factory=list)
    flow_filters: list[Callable[[Finding], bool]] = field(default_factory=list)
    _pack: str = ""

    def add_capability(
        self, id: str, label: str, *, description: str = "", reserved: bool = False
    ) -> None:
        """Declare a capability of the pack being loaded. Scanners reference it by id."""
        if id in self.capabilities:
            raise ValueError(
                f"capability {id!r} registered twice "
                f"({self.capabilities[id].domain} and {self._pack})"
            )
        self.capabilities[id] = Capability(id, label, description, self._pack, reserved)

    def add_scanner(
        self,
        name: str,
        factory: Callable[[Config], Scanner],
        *,
        selectable: bool = True,
        description: str = "",
        capability: str = "",
    ) -> None:
        if name in self.scanners:
            raise ValueError(
                f"scanner {name!r} registered twice ({self.scanners[name].pack} and {self._pack})"
            )
        if capability and capability not in self.capabilities:
            raise ValueError(
                f"scanner {name!r} names capability {capability!r}, which {self._pack} "
                "did not declare with add_capability() first"
            )
        self.scanners[name] = ScannerSpec(
            name, factory, selectable, self._pack, description, capability
        )

    def add_target_pack(self, target: TargetPack) -> None:
        """A standard findings are mapped against; its controls are listed in registration order."""
        if any(t.id == target.id for t in self.target_packs):
            raise ValueError(f"target pack {target.id!r} registered twice")
        self.target_packs.append(target)

    def add_collector(self, collector: Collector) -> None:
        """How the pack collects evidence (the `scan` stage). Collectors run in pack order."""
        self.collectors.append(collector)

    def add_annotator(self, factory: AnnotatorFactory) -> None:
        """A step inside normalize, built per run from the config (`None` when it has none: an
        annotator that needs configured data then returns None and is left out)."""
        self.annotator_factories.append(factory)

    def add_flow_filter(self, wants_flow: Callable[[Finding], bool]) -> None:
        """Which code findings are worth a data-flow trace (any filter can say no)."""
        self.flow_filters.append(wants_flow)

    def annotators_for(self, config: Config | None) -> list[Annotator]:
        built = (factory(config) for factory in self.annotator_factories)
        return [a for a in built if a is not None]

    def wants_flow(self, finding: Finding) -> bool:
        """Trace data flow for a code finding unless a pack says its weakness is not about data
        flow (for example a weak algorithm, judged by what was chosen)."""
        return finding.category == Category.CODE and all(f(finding) for f in self.flow_filters)

    def load(self, pack: str, register: Callable[[Registry], None]) -> None:
        self._pack = pack
        try:
            register(self)
        finally:
            self._pack = ""
        self.packs.append(pack)


def _load_ref(ref: str) -> Callable[[Registry], None]:
    module, _, attr = ref.partition(":")
    fn: Callable[[Registry], None] = getattr(import_module(module), attr)
    return fn


def _origin(ep: EntryPoint) -> str:
    dist = getattr(ep, "dist", None)
    return f"{ep.value} from {dist.name}" if dist is not None else ep.value


def _usable(eps: Iterable[EntryPoint]) -> dict[str, EntryPoint]:
    """One entry point per name; spoofed built-in names and ambiguous names are refused."""
    by_name: dict[str, list[EntryPoint]] = {}
    for ep in eps:
        if ep.name in BUILTIN_PACKS and ep.value != BUILTIN_PACKS[ep.name]:
            log.warning("refusing pack %r (%s): the name belongs to a built-in pack",
                        ep.name, _origin(ep))  # fmt: skip
            continue
        by_name.setdefault(ep.name, []).append(ep)
    out = {}
    for name, found in by_name.items():
        if len({e.value for e in found}) > 1:
            log.warning("refusing pack %r: registered by more than one package (%s)",
                        name, "; ".join(_origin(e) for e in found))  # fmt: skip
            continue
        out[name] = found[0]
    return out


@lru_cache(maxsize=8)
def registry(allowed: tuple[str, ...] = DEFAULT_PACKS) -> Registry:
    """The allowed packs, loaded once per allowlist, in allowlist order."""
    reg = Registry()
    available = _usable(entry_points(group=ENTRY_POINT_GROUP))
    for name, ep in sorted(available.items()):
        if name not in allowed:
            log.warning("ignoring installed pack %r (%s): not in scanners.packs", name, _origin(ep))
    for name in allowed:
        if name in available:
            reg.load(name, available[name].load())
        elif name in BUILTIN_PACKS:
            log.warning("pack %r has no %s entry point; loading it directly",
                        name, ENTRY_POINT_GROUP)  # fmt: skip
            reg.load(name, _load_ref(BUILTIN_PACKS[name]))
        else:
            log.warning("pack %r is in scanners.packs but not installed", name)
    return reg


def registry_for(config: Config) -> Registry:
    return registry(tuple(config.scanners.packs))


def selectable_scanners(allowed: tuple[str, ...] = DEFAULT_PACKS) -> tuple[str, ...]:
    """Scanner names a user may pick, in registration order."""
    return tuple(s.name for s in registry(allowed).scanners.values() if s.selectable)


def background_scanners(allowed: tuple[str, ...] = DEFAULT_PACKS) -> tuple[str, ...]:
    """Scanners that are not offered in the picker: they run whenever the config enables them."""
    return tuple(s.name for s in registry(allowed).scanners.values() if not s.selectable)


def domains(allowed: tuple[str, ...] = DEFAULT_PACKS) -> tuple[str, ...]:
    """The loaded domains (packs), in load order. A project enables a service per domain."""
    return tuple(registry(allowed).packs)


def capabilities(allowed: tuple[str, ...] = DEFAULT_PACKS) -> list[Capability]:
    """Every capability the loaded packs declare, in registration order."""
    return list(registry(allowed).capabilities.values())


def capabilities_for_domain(
    domain: str, allowed: tuple[str, ...] = DEFAULT_PACKS
) -> list[Capability]:
    """The capabilities a single domain declares."""
    return [c for c in registry(allowed).capabilities.values() if c.domain == domain]


def scanners_by_capability(allowed: tuple[str, ...] = DEFAULT_PACKS) -> dict[str, list[str]]:
    """capability id -> the scanner names in it, in registration order. Scanners with no capability
    are grouped under the empty-string key."""
    out: dict[str, list[str]] = {}
    for spec in registry(allowed).scanners.values():
        out.setdefault(spec.capability, []).append(spec.name)
    return out


def scanners_for_capabilities(
    enabled: Iterable[str], allowed: tuple[str, ...] = DEFAULT_PACKS
) -> tuple[str, ...]:
    """The scanner names to run for a set of enabled capability ids, in registration order.
    Unknown capability ids are ignored; a scanner with no capability is never pulled in this way."""
    wanted = set(enabled)
    return tuple(
        s.name
        for s in registry(allowed).scanners.values()
        if s.capability and s.capability in wanted
    )


def capability_catalogue(allowed: tuple[str, ...] = DEFAULT_PACKS) -> list[dict[str, object]]:
    """Every capability the loaded packs declare, as plain data for an API or UI."""
    return [
        {"id": c.id, "label": c.label, "description": c.description,
         "domain": c.domain, "reserved": c.reserved}
        for c in capabilities(allowed)
    ]  # fmt: skip


def resolve_capabilities(
    domain: str, config: dict[str, object], allowed: tuple[str, ...] = DEFAULT_PACKS
) -> list[str]:
    """The capability ids enabled for a service: the explicit list in `config["capabilities"]`,
    intersected with the domain's non-reserved capabilities; an absent list means all of them."""
    available = [c.id for c in capabilities(allowed) if c.domain == domain and not c.reserved]
    chosen = config.get("capabilities")
    if chosen is None:
        return available
    picked = set(chosen) if isinstance(chosen, (list, tuple, set)) else set()
    return [cid for cid in available if cid in picked]


@dataclass(frozen=True)
class ScannerStatus:
    name: str
    available: bool
    version: str = ""
    description: str = ""
    pack: str = ""
    registered: bool = True


def scanner_status(config: Config, names: Iterable[str]) -> list[ScannerStatus]:
    """Whether each named scanner can run here, and its version, asked of the adapter itself.
    A version probe may start a program, so callers that poll should cache the answer."""
    specs = registry_for(config).scanners
    out = []
    for name in names:
        spec = specs.get(name)
        if spec is None:
            out.append(ScannerStatus(name, False, registered=False))
            continue
        scanner = spec.factory(config)
        available, version = scanner.is_available(), ""
        if available:
            try:
                version = scanner.version()
            except Exception:  # noqa: BLE001 - informational only: a probe failure is not fatal
                log.warning("%s: version probe failed", name, exc_info=True)
        out.append(ScannerStatus(name, available, version, spec.description, spec.pack))
    return out


def build_scanners(config: Config) -> list[Scanner]:
    """The scanners `config.scanners.enabled` names, in that order; unknown names are logged."""
    specs = registry_for(config).scanners
    unknown = [n for n in config.scanners.enabled if n not in specs]
    if unknown:
        log.warning("ignoring unknown scanners in config: %s", ", ".join(unknown))
    return [specs[n].factory(config) for n in config.scanners.enabled if n in specs]
