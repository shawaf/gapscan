"""Tests for configuration loading and the local-endpoint safety rule."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from gapscan.config import Config, LLMConfig, find_config_file, load_config


def test_defaults_are_sane() -> None:
    cfg = Config()
    assert cfg.general.max_llm_findings == 200
    assert cfg.llm.backend == "ollama"
    assert cfg.llm.temperature == 0.0
    assert "semgrep" in cfg.scanners.enabled


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:11434",
        "http://127.0.0.1:11434",
        "http://192.168.1.10:11434",
        "http://ollama.local:11434",
    ],
)
def test_local_endpoints_allowed(endpoint: str) -> None:
    assert LLMConfig(endpoint=endpoint).endpoint == endpoint


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://api.openai.com/v1",
        "http://example.com:11434",
        "http://8.8.8.8:11434",
    ],
)
def test_public_endpoints_refused(endpoint: str) -> None:
    with pytest.raises(ValidationError):
        LLMConfig(endpoint=endpoint)


def test_internal_model_servers_by_name() -> None:
    # private-use names need no entry; a corporate DNS name needs an explicit one
    assert LLMConfig(endpoint="http://gpu01.internal:11434").endpoint
    assert LLMConfig(endpoint="http://llm.home.arpa:11434").endpoint
    with pytest.raises(ValidationError, match="internal_hosts"):
        LLMConfig(endpoint="https://llm.corp.example.com")
    hosts = ["llm.corp.example.com", "*.gpu.example.com"]
    assert LLMConfig(endpoint="https://LLM.corp.example.com.", internal_hosts=hosts).endpoint
    assert LLMConfig(endpoint="http://a.gpu.example.com", internal_hosts=hosts).endpoint
    for url in (
        "http://gpu.example.com",
        "http://evilgpu.example.com",
        "http://example.com.evil.io",
    ):
        with pytest.raises(ValidationError):
            LLMConfig(endpoint=url, internal_hosts=hosts)
    with pytest.raises(ValidationError, match="embedding_endpoint"):  # checked too, not just at use
        LLMConfig(embedding_endpoint="https://api.example.com")
    with pytest.raises(ValidationError):  # a tier cannot smuggle in a public host either
        LLMConfig(tier="x", tiers={"x": {"profile": "best", "endpoint": "https://api.example.com"}})


def test_client_enforces_the_same_rule() -> None:
    from gapscan.llm.client import LLMClient, LLMError

    cfg = LLMConfig(
        endpoint="https://llm.corp.example.com", internal_hosts=["llm.corp.example.com"]
    )
    LLMClient(cfg)
    cfg.endpoint = "https://api.example.com"  # changed after validation
    with pytest.raises(LLMError):
        LLMClient(cfg)


def test_load_from_toml_file(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("GAPSCAN_CONFIG", raising=False)
    cfg_file = tmp_path / "gapscan.toml"
    cfg_file.write_text(
        '[general]\nmax_llm_findings = 42\n\n[llm]\nmodel = "my-model:7b"\n',
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert cfg.general.max_llm_findings == 42
    assert cfg.llm.model == "my-model:7b"


def test_env_var_overrides_file(tmp_path, monkeypatch) -> None:
    cfg_file = tmp_path / "gapscan.toml"
    cfg_file.write_text('[llm]\nmodel = "from-file"\n', encoding="utf-8")
    monkeypatch.setenv("GAPSCAN_LLM__MODEL", "from-env")
    cfg = load_config(cfg_file)
    assert cfg.llm.model == "from-env"


def test_find_config_searches_upward(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("GAPSCAN_CONFIG", raising=False)
    (tmp_path / "gapscan.toml").write_text("", encoding="utf-8")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    found = find_config_file(start=nested)
    assert found == tmp_path / "gapscan.toml"


def test_missing_explicit_config_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does-not-exist.toml")
