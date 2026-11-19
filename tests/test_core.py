"""Core layer: models moved to `gapscan.core`, old imports still work, and
today's implementations conform to the interfaces core declares."""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest
from pydantic import BaseModel, ValidationError

import gapscan.models as legacy_models
from gapscan.config import LLMConfig, load_config
from gapscan.core import interfaces, models
from gapscan.core.interfaces import (
    Control,
    ControlRef,
    Egress,
    EgressDisabled,
    LLMProvider,
    NoEgress,
    Scanner,
    Store,
    TargetPack,
)
from gapscan.llm import client as llm_client
from gapscan.llm.client import LLMClient
from gapscan.scanners import base as scanner_base
from gapscan.scanners import build_scanners
from gapscan.server.db import Database


def _public_names(module: object) -> set[str]:
    """Top-level classes and assignments a module defines itself (not names it imports)."""
    tree = ast.parse(Path(module.__file__).read_text())  # type: ignore[attr-defined]
    names = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
    names |= {t.id for n in tree.body if isinstance(n, ast.Assign) for t in n.targets
              if isinstance(t, ast.Name)}  # fmt: skip
    return {n for n in names if not n.startswith("_")}


def test_legacy_models_module_re_exports_every_core_model() -> None:
    assert set(legacy_models.__all__) == _public_names(models)
    for name in legacy_models.__all__:
        assert getattr(legacy_models, name) is getattr(models, name)


def test_moved_interfaces_are_re_exported_from_their_old_homes() -> None:
    assert scanner_base.Scanner is interfaces.Scanner
    assert llm_client.LLMError is interfaces.LLMError
    assert llm_client.ChatResult is interfaces.ChatResult


def test_every_built_in_scanner_conforms_to_scanner() -> None:
    scanners = build_scanners(load_config(None))
    assert scanners
    for scanner in scanners:
        assert isinstance(scanner, Scanner), scanner


def test_local_llm_client_conforms_to_llm_provider() -> None:
    client = LLMClient(LLMConfig(model="m:1"), httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(500))))  # fmt: skip
    assert isinstance(client, LLMProvider)
    assert client.model == "m:1"


def test_local_server_database_conforms_to_store(tmp_path: Path) -> None:
    assert isinstance(Database(tmp_path / "gapscan.db"), Store)


def test_no_egress_refuses_every_send() -> None:
    class Payload(BaseModel):
        fingerprint: str

    egress = NoEgress()
    assert isinstance(egress, Egress)
    with pytest.raises(EgressDisabled, match="evidence"):
        egress.send("evidence", Payload(fingerprint="abc"))


def test_control_ref_is_immutable_and_hashable() -> None:
    ref = ControlRef(target="example", version="1.0", control_id="C-1")
    assert {ref, ControlRef(target="example", version="1.0", control_id="C-1")} == {ref}
    with pytest.raises(ValidationError):
        ref.control_id = "C-2"  # type: ignore[misc]


def test_a_target_pack_maps_findings_to_controls() -> None:
    ref = ControlRef(target="example", version="1.0", control_id="C-1")

    class ExamplePack:
        id = "example"
        name = "Example standard"
        version = "1.0"

        def controls(self) -> list[Control]:
            return [Control(ref=ref, title="Do the thing")]

        def controls_for(self, finding: models.Finding) -> list[ControlRef]:
            return [ref] if finding.rule_id == "r1" else []

        def checkable(self) -> frozenset[str]:
            return frozenset({"C-1"})

    pack = ExamplePack()
    assert isinstance(pack, TargetPack)
    finding = models.Finding(scanner="s", rule_id="r1", title="t",
                             severity=models.Severity.LOW, category=models.Category.CODE)  # fmt: skip
    assert pack.controls_for(finding) == [ref]
