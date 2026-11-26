"""The opt-in hosted model for triage (`llm.allow_remote`): any provider over HTTPS once the user
agrees, key from the environment, every message masked again before it leaves, and nothing changes
unless it is set."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from gapscan.config import LLMConfig, endpoint_is_remote
from gapscan.llm.client import LLMClient, LLMError, openai_url

AWS = "AKIA" + "JKQW2XM7LPR5ZT3N"
REMOTE = {"backend": "openai", "endpoint": "https://api.example.com", "allow_remote": True}


def test_a_public_endpoint_is_still_refused_without_the_opt_in() -> None:
    with pytest.raises(ValidationError, match="allow_remote"):
        LLMConfig(backend="openai", endpoint="https://api.example.com")


def test_the_opt_in_accepts_any_provider_over_https() -> None:
    with pytest.raises(ValidationError, match="https"):
        LLMConfig(**{**REMOTE, "endpoint": "http://api.example.com"})
    assert endpoint_is_remote(LLMConfig(**{**REMOTE, "backend": "ollama",
                                           "endpoint": "https://ollama.com"}))  # fmt: skip
    with pytest.raises(ValidationError):  # embeddings always stay local
        LLMConfig(**REMOTE, embedding_endpoint="https://api.example.com")
    assert endpoint_is_remote(LLMConfig(**REMOTE))
    assert not endpoint_is_remote(LLMConfig(**{**REMOTE, "endpoint": "http://localhost:8080"}))


def test_the_client_needs_the_key_in_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GAPSCAN_LLM_API_KEY", raising=False)
    with pytest.raises(LLMError, match="GAPSCAN_LLM_API_KEY"):
        LLMClient(LLMConfig(**REMOTE))


def test_messages_are_masked_and_the_key_is_sent_as_a_bearer_token(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("MY_KEY", "sk-test-123")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = {"choices": [{"message": {"content": "{}"}}], "usage": {}}
        return httpx.Response(200, json=body)

    cfg = LLMConfig(**REMOTE, api_key_env="MY_KEY")
    client = LLMClient(cfg, http=httpx.Client(transport=httpx.MockTransport(handler)))
    client.chat([{"role": "user", "content": f"key = '{AWS}'"}])
    sent = json.loads(seen[0].content)
    assert AWS not in json.dumps(sent)
    assert seen[0].headers["authorization"] == "Bearer sk-test-123"
    assert str(seen[0].url) == "https://api.example.com/v1/chat/completions"
    assert "api.example.com" in caplog.text and "sk-test-123" not in caplog.text
    assert client.answer_settings()["endpoint"] == "api.example.com"  # cached apart from local


def test_a_local_client_sends_no_key_and_does_not_rewrite_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GAPSCAN_LLM_API_KEY", "sk-should-not-be-sent")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    cfg = LLMConfig(backend="openai", endpoint="http://localhost:8080")
    client = LLMClient(cfg, http=httpx.Client(transport=httpx.MockTransport(handler)))
    client.chat([{"role": "user", "content": "plain"}])
    assert "authorization" not in seen[0].headers
    assert "endpoint" not in client.answer_settings()


@pytest.mark.parametrize(
    ("endpoint", "url"),
    [
        ("http://localhost:8080", "http://localhost:8080/v1/chat/completions"),
        ("http://localhost:8080/v1/", "http://localhost:8080/v1/chat/completions"),
        ("https://api.openai.com", "https://api.openai.com/v1/chat/completions"),
        ("https://api.groq.com/openai/v1", "https://api.groq.com/openai/v1/chat/completions"),
        (
            "https://generativelanguage.googleapis.com/v1beta/openai",
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        ),
    ],
)
def test_provider_paths_are_kept(endpoint: str, url: str) -> None:
    assert openai_url(endpoint, "chat/completions") == url


def test_a_provider_with_its_own_key_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZ", "k1")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    cfg = LLMConfig(**{**REMOTE, "endpoint": "https://x.openai.azure.com/openai/v1"},
                    api_key_env="AZ", api_key_header="api-key")  # fmt: skip
    LLMClient(cfg, http=httpx.Client(transport=httpx.MockTransport(handler))).chat(
        [{"role": "user", "content": "hi"}]
    )
    assert seen[0].headers["api-key"] == "k1" and "authorization" not in seen[0].headers
    assert str(seen[0].url) == "https://x.openai.azure.com/openai/v1/chat/completions"


def test_a_hosted_ollama_gets_the_key_and_masked_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GAPSCAN_LLM_API_KEY", "ok-1")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"message": {"content": "{}"}, "done": True})

    cfg = LLMConfig(backend="ollama", endpoint="https://ollama.com", allow_remote=True)
    LLMClient(cfg, http=httpx.Client(transport=httpx.MockTransport(handler))).chat(
        [{"role": "user", "content": f"k={AWS}"}]
    )
    assert seen[0].headers["authorization"] == "Bearer ok-1"
    assert AWS not in seen[0].content.decode()
