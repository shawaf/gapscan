"""Scanner registry: packs register scanners through the `gapscan.packs` entry
point; nothing in the engine keeps a central list, and only allowlisted packs are ever loaded."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from gapscan import registry as reg_mod
from gapscan.config import Config, load_config
from gapscan.core.interfaces import Scanner
from gapscan.models import Finding
from gapscan.registry import (
    BUILTIN_PACKS,
    Registry,
    build_scanners,
    capabilities,
    capabilities_for_domain,
    domains,
    registry,
    scanners_by_capability,
    scanners_for_capabilities,
    selectable_scanners,
)
from gapscan.scanners import scan_target
from gapscan.security_pack import register as security

SECURITY = ["semgrep", "osv", "trivy", "gitleaks", "checkov", "bandit", "taint", "malware"]


@pytest.fixture
def fresh_registry() -> Iterator[None]:
    registry.cache_clear()
    yield
    registry.cache_clear()


class DummyScanner:
    name = "dummy"

    def is_available(self) -> bool:
        return True

    def version(self) -> str:
        return "1"

    def run(self, target: Path, workdir: Path) -> list[Finding]:
        return []


def extra(r: Registry) -> None:
    r.add_scanner("dummy", lambda c: DummyScanner(), selectable=False)


def ep(name: str, fn: Callable[[Registry], None], value: str | None = None, dist: str = "x"):
    """A stand-in entry point that records whether its code was loaded."""
    loaded: list[str] = []

    def load():
        loaded.append(name)
        return fn

    return SimpleNamespace(name=name, value=value or f"{dist}.pack:register",
                           dist=SimpleNamespace(name=dist), load=load, loaded=loaded)  # fmt: skip


def installed(monkeypatch, *eps) -> None:
    monkeypatch.setattr(reg_mod, "entry_points", lambda group: list(eps))


def builtin() -> SimpleNamespace:
    return ep("security", security, BUILTIN_PACKS["security"], "gapscan")


# --- the default ---------------------------------------------------------------------------------


def test_the_security_pack_registers_through_its_entry_point() -> None:
    reg = registry()
    assert list(reg.scanners) == SECURITY and reg.packs == ["security"]
    assert {s.pack for s in reg.scanners.values()} == {"security"}
    assert Config().scanners.packs == ["security"]


def test_build_scanners_follows_the_config_order(caplog) -> None:
    cfg = Config(scanners={"enabled": ["gitleaks", "nope", "semgrep"]})
    with caplog.at_level(logging.WARNING):
        built = build_scanners(cfg)
    assert [s.name for s in built] == ["gitleaks", "semgrep"]
    assert all(isinstance(s, Scanner) for s in built)
    assert "nope" in caplog.text
    default = load_config(None)
    assert [s.name for s in build_scanners(default)] == list(default.scanners.enabled)


def test_the_manager_offers_the_selectable_scanners_in_registration_order() -> None:
    from gapscan.server.jobs import KNOWN_SCANNERS

    assert KNOWN_SCANNERS == selectable_scanners() == tuple(SECURITY[:6])


def test_a_scanner_name_can_be_registered_once() -> None:
    reg = Registry()
    reg.load("one", lambda r: r.add_scanner("dummy", lambda c: DummyScanner()))
    with pytest.raises(ValueError, match="registered twice"):
        reg.load("two", lambda r: r.add_scanner("dummy", lambda c: DummyScanner()))


# --- capabilities (Project -> Service (domain) -> Capability) ------------------------------------


def test_the_security_domain_declares_its_capabilities() -> None:
    assert domains() == ("security",)
    ids = [c.id for c in capabilities()]
    assert ids == ["sast", "sca", "secrets", "iac", "containers", "dynamic"]
    assert capabilities_for_domain("security") == capabilities()
    assert {c.domain for c in capabilities()} == {"security"}
    reserved = {c.id for c in capabilities() if c.reserved}
    assert reserved == {"containers", "dynamic"}


def test_scanners_group_under_their_capability() -> None:
    by_cap = scanners_by_capability()
    assert by_cap["sast"] == ["semgrep", "bandit", "taint"]
    assert by_cap["sca"] == ["osv", "trivy", "malware"]
    assert by_cap["secrets"] == ["gitleaks"]
    assert by_cap["iac"] == ["checkov"]
    # Every scanner in the security pack belongs to a capability.
    assert "" not in by_cap


def test_enabled_capabilities_map_to_their_scanners_in_registration_order() -> None:
    assert scanners_for_capabilities(["secrets"]) == ("gitleaks",)
    assert scanners_for_capabilities(["sast", "secrets"]) == (
        "semgrep", "gitleaks", "bandit", "taint",
    )  # fmt: skip
    # Reserved capabilities contribute no scanners; unknown ids are ignored.
    assert scanners_for_capabilities(["containers", "dynamic", "nope"]) == ()
    assert scanners_for_capabilities([]) == ()


def test_a_scanner_cannot_name_an_undeclared_capability() -> None:
    reg = Registry()
    with pytest.raises(ValueError, match="did not declare"):
        reg.load(
            "one",
            lambda r: r.add_scanner("dummy", lambda c: DummyScanner(), capability="ghost"),
        )


def test_a_capability_is_declared_once() -> None:
    reg = Registry()
    with pytest.raises(ValueError, match="registered twice"):
        reg.load(
            "one",
            lambda r: (r.add_capability("x", "X"), r.add_capability("x", "X again")),
        )


# --- the allowlist -------------------------------------------------------------------------------


def test_an_installed_pack_not_on_the_allowlist_is_never_loaded(
    monkeypatch, fresh_registry, caplog
):
    other = ep("extra", extra, dist="some-plugin")
    installed(monkeypatch, builtin(), other)
    with caplog.at_level(logging.WARNING):
        reg = registry()
    assert "dummy" not in reg.scanners and other.loaded == []  # its code never ran
    assert "extra" in caplog.text and "some-plugin" in caplog.text
    assert build_scanners(Config(scanners={"enabled": ["dummy"]})) == []


def test_an_allowlisted_pack_adds_a_scanner_without_touching_the_engine(
    monkeypatch, fresh_registry
):
    installed(monkeypatch, builtin(), ep("extra", extra))
    cfg = Config(scanners={"packs": ["security", "extra"], "enabled": ["dummy", "bandit"]})
    assert [s.name for s in build_scanners(cfg)] == ["dummy", "bandit"]
    assert registry(("security", "extra")).scanners["dummy"].pack == "extra"
    assert "dummy" not in selectable_scanners(("security", "extra"))


def test_a_pack_cannot_take_a_built_in_name(monkeypatch, fresh_registry, caplog):
    spoof = ep("security", extra, dist="evil")
    installed(monkeypatch, spoof)
    with caplog.at_level(logging.WARNING):
        reg = registry()
    assert spoof.loaded == [] and "evil" in caplog.text
    assert list(reg.scanners) == SECURITY  # the real built-in pack, loaded directly


def test_a_name_two_packages_claim_is_refused(monkeypatch, fresh_registry, caplog):
    a, b = ep("extra", extra, dist="one"), ep("extra", extra, dist="two")
    installed(monkeypatch, builtin(), a, b)
    with caplog.at_level(logging.WARNING):
        reg = registry(("security", "extra"))
    assert a.loaded == b.loaded == [] and "dummy" not in reg.scanners
    assert "more than one package" in caplog.text


def test_an_allowlisted_pack_that_is_not_installed_is_reported(monkeypatch, fresh_registry, caplog):
    installed(monkeypatch, builtin())
    with caplog.at_level(logging.WARNING):
        reg = registry(("security", "missing"))
    assert reg.packs == ["security"] and "'missing'" in caplog.text


def test_without_package_metadata_the_built_in_pack_still_loads(
    monkeypatch, fresh_registry, caplog
):
    installed(monkeypatch)
    with caplog.at_level(logging.WARNING):
        reg = registry()
    assert list(reg.scanners) == SECURITY and "loading it directly" in caplog.text


def test_every_scanner_run_records_its_pack(monkeypatch, fresh_registry, tmp_path):
    installed(monkeypatch, builtin(), ep("extra", extra))
    cfg = Config(scanners={"packs": ["security", "extra"], "enabled": ["dummy"]})
    result = scan_target(cfg, tmp_path, tmp_path / "work")
    assert [(r.scanner, r.pack, r.status) for r in result.runs] == [("dummy", "extra", "ok")]
