"""Mode composition (ARCHITECTURE.md section 4, hard rule 2): the local composition cannot reach
the cloud, because no part of it is able to.

Local mode is GapScan with only local adapters wired in: the local LLM provider, which refuses any
endpoint that is not localhost, a private address or an owner-listed internal host, and no egress
at all. No hosted provider and no cloud egress exist yet. This test is the tripwire for when they
do: it finds every LLM provider and egress implementation in the package and fails on any that is
not one of the local ones, so the composition rules must be written before a cloud adapter lands.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

import httpx
import pytest
from pydantic import ValidationError

import gapscan
from gapscan.config import Config, LLMConfig
from gapscan.core.interfaces import EgressDisabled, NoEgress
from gapscan.llm.client import LLMClient, LLMError

LOCAL_PROVIDERS = {LLMClient}
LOCAL_EGRESS = {NoEgress}
OPTIONAL = ("gapscan.desktop",)  # needs the desktop window toolkit, not installed everywhere


def _classes() -> list[type]:
    found: dict[str, type] = {}
    for mod in pkgutil.walk_packages(gapscan.__path__, "gapscan."):
        try:
            module = importlib.import_module(mod.name)
        except ImportError:
            if mod.name.startswith(OPTIONAL):
                continue
            raise
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__.startswith("gapscan.") and not getattr(cls, "_is_protocol", False):
                found[f"{cls.__module__}.{cls.__qualname__}"] = cls
    return list(found.values())


def _is_llm_provider(cls: type) -> bool:
    return all(callable(getattr(cls, m, None)) for m in ("chat", "list_models", "answer_settings"))


def _is_egress(cls: type) -> bool:
    send = getattr(cls, "send", None)
    return callable(send) and list(inspect.signature(send).parameters)[:3] == ["self", "kind",
                                                                             "payload"]  # fmt: skip


def test_the_only_llm_provider_is_the_local_one() -> None:
    providers = {c for c in _classes() if _is_llm_provider(c)}
    assert providers == LOCAL_PROVIDERS, (
        "a new LLM provider exists: write its composition rules (which apps may wire it, and the "
        "local-endpoint check) before adding it here"
    )


def test_the_only_egress_is_none() -> None:
    egress = {c for c in _classes() if _is_egress(c)}
    assert egress == LOCAL_EGRESS, "a cloud egress exists: wire it only into cloud compositions"
    with pytest.raises(EgressDisabled):
        NoEgress().send("evidence", Config())


@pytest.mark.parametrize("url", ["https://api.example.com/v1", "http://8.8.8.8:11434",
                                 "https://llm.example.org"])  # fmt: skip
def test_the_local_provider_refuses_public_endpoints(url: str) -> None:
    with pytest.raises(ValidationError):
        LLMConfig(endpoint=url)  # the config refuses it
    cfg = LLMConfig.model_construct(**{**LLMConfig().model_dump(), "endpoint": url})
    with pytest.raises(LLMError, match="non-local"):  # and the client re-checks on its own
        LLMClient(cfg, httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))))


def test_an_owner_listed_internal_host_is_the_only_way_off_the_machine() -> None:
    cfg = LLMConfig(endpoint="https://llm.corp.example.com", internal_hosts=["*.corp.example.com"])
    assert LLMClient(cfg).model == cfg.model
