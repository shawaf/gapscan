"""LLM client: Ollama's native API, or any OpenAI-compatible server (llama.cpp, vLLM).

The endpoint must be localhost or a configured internal host (hard rule #2); the config
validator enforces this and the client re-checks before every connection. The one exception is a
hosted model the user opted into with `llm.allow_remote` (HTTPS only, key from the
environment): every message is then secret-masked again before it leaves the machine. Prompts are
never logged at INFO level (hard rule: logging).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import LLMConfig, endpoint_allowed, endpoint_is_remote, remote_endpoint_ok
from ..core.interfaces import ChatResult as ChatResult  # declared in core; re-exported here
from ..core.interfaces import LLMError as LLMError
from ..redact import mask

log = logging.getLogger(__name__)


def openai_url(endpoint: str, route: str) -> str:
    """An OpenAI-compatible route under `endpoint`. A bare host gets the usual `/v1` prefix
    (`http://localhost:8080` -> `/v1/models`); an endpoint that already names its API path keeps
    it, since providers differ (`https://api.groq.com/openai/v1`, Gemini's `.../v1beta/openai`)."""
    base = endpoint.rstrip("/")
    return f"{base}/{route}" if urlparse(base).path.strip("/") else f"{base}/v1/{route}"


def assert_local_endpoint(endpoint: str, internal_hosts: Iterable[str] = ()) -> None:
    if not endpoint_allowed(endpoint, internal_hosts):
        raise LLMError(f"refusing non-local LLM endpoint host {urlparse(endpoint).hostname!r}")


class LLMClient:
    """The local `LLMProvider`."""

    def __init__(self, cfg: LLMConfig, http: httpx.Client | None = None) -> None:
        self.remote = endpoint_is_remote(cfg)
        if self.remote:
            if not remote_endpoint_ok(cfg.endpoint):
                raise LLMError("a hosted model needs an https:// endpoint")
            key = os.environ.get(cfg.api_key_env, "")
            if not key:
                raise LLMError(
                    f"llm.allow_remote is on but ${cfg.api_key_env} is empty: set the API key there"
                )
            header = cfg.api_key_header or "Authorization"
            headers = {header: f"Bearer {key}" if header.lower() == "authorization" else key}
            log.warning(
                "triage uses the hosted model at %s: masked review prompts leave this machine",
                urlparse(cfg.endpoint).hostname,
            )
        else:
            assert_local_endpoint(cfg.endpoint, cfg.internal_hosts)
            headers = {}
        self.cfg = cfg
        self.endpoint = cfg.endpoint.rstrip("/")
        self._http = http or httpx.Client(timeout=cfg.timeout_s, headers=headers)
        if http is not None and headers:
            self._http.headers.update(headers)

    @property
    def model(self) -> str:
        """The configured default model (`LLMProvider.model`)."""
        return self.cfg.model

    def answer_settings(self) -> dict[str, Any]:
        cfg = self.cfg
        options: dict[str, Any] = {"t": cfg.temperature, "seed": cfg.seed,
                                   "ctx": cfg.context_tokens, "think": cfg.think}  # fmt: skip
        if cfg.backend != "ollama":  # another runtime can answer differently: never share answers
            options["backend"] = cfg.backend
        if self.remote:
            options["endpoint"] = urlparse(cfg.endpoint).hostname
        return options

    # --- discovery -----------------------------------------------------------------

    def list_models(self) -> list[dict[str, Any]]:
        """Installed models: [{name, size_gb, params, quant}] (size/params only on Ollama)."""
        try:
            if self.cfg.backend == "ollama":
                r = self._http.get(f"{self.endpoint}/api/tags")
                r.raise_for_status()
                return [
                    {
                        "name": m["name"],
                        "size_gb": round(m.get("size", 0) / 1e9, 1),
                        "params": m.get("details", {}).get("parameter_size", ""),
                        "quant": m.get("details", {}).get("quantization_level", ""),
                    }
                    for m in r.json().get("models", [])
                ]
            r = self._http.get(openai_url(self.endpoint, "models"))
            r.raise_for_status()
            return [{"name": m["id"], "size_gb": 0.0, "params": "", "quant": ""}
                    for m in r.json().get("data", [])]  # fmt: skip
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise LLMError(f"cannot list models at {self.endpoint}: {exc}") from exc

    # --- chat ----------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any] | None = None,
        model: str | None = None,
        max_tokens: int = 700,
    ) -> ChatResult:
        """One non-streaming completion. With `schema`, the server is asked to constrain the
        output to that JSON schema (the caller must still validate it)."""
        model = model or self.cfg.model
        if self.remote:  # leaving the machine: mask secrets once more, whatever the prompt holds
            messages = [{**m, "content": mask(m.get("content", ""))} for m in messages]
        started = time.monotonic()
        try:
            if self.cfg.backend == "ollama":
                result = self._chat_ollama(model, messages, schema, max_tokens)
            else:
                result = self._chat_openai(model, messages, schema, max_tokens)
        except httpx.TimeoutException as exc:
            raise LLMError(f"model {model!r} timed out after {self.cfg.timeout_s}s") from exc
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
            raise LLMError(f"model request failed for {model!r}: {exc}") from exc
        result.duration_s = round(time.monotonic() - started, 2)
        log.debug("llm call model=%s in=%s out=%s %.1fs", model, result.prompt_tokens,
                  result.completion_tokens, result.duration_s)  # fmt: skip
        return result

    def _chat_ollama(self, model: str, messages: list[dict[str, str]],
                     schema: dict[str, Any] | None, max_tokens: int) -> ChatResult:  # fmt: skip
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "think": self.cfg.think,
            "options": {
                "temperature": self.cfg.temperature,
                "seed": self.cfg.seed,
                "num_ctx": self.cfg.context_tokens,
                "num_predict": max_tokens,
            },
        }
        if schema is not None:
            body["format"] = schema
        r = self._http.post(f"{self.endpoint}/api/chat", json=body)
        if r.status_code >= 400:
            raise httpx.HTTPError(f"{r.status_code}: {r.text[:200]}")
        data = r.json()
        return ChatResult(
            text=data["message"]["content"],
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
        )

    def _chat_openai(self, model: str, messages: list[dict[str, str]],
                     schema: dict[str, Any] | None, max_tokens: int) -> ChatResult:  # fmt: skip
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": self.cfg.temperature,
            "seed": self.cfg.seed,
            "max_tokens": max_tokens,
        }
        if schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "response", "schema": schema, "strict": True},
            }
        r = self._http.post(openai_url(self.endpoint, "chat/completions"), json=body)
        if r.status_code >= 400:
            raise httpx.HTTPError(f"{r.status_code}: {r.text[:200]}")
        data = r.json()
        usage = data.get("usage", {})
        return ChatResult(
            text=data["choices"][0]["message"]["content"] or "",
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
        )
