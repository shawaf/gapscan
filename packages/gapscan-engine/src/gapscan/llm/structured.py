"""Schema-validated model output with repair retries (hard rule #6): invalid output is retried
with a repair prompt, then raised as StructuredOutputError so the caller can mark the finding
`triage_failed`. Output is never silently accepted."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Generic, TypeVar

from pydantic import BaseModel, ValidationError

from ..core.interfaces import ChatResult, LLMProvider
from .cache import ResponseCache, cache_key

T = TypeVar("T", bound=BaseModel)
MAX_REPAIRS = 2

_REPAIR = (
    "Your previous reply was not valid. Problem: {problem}\n"
    "Reply again with ONLY a JSON object matching the required schema. No prose, no code fences."
)


class StructuredOutputError(RuntimeError):
    def __init__(self, message: str, attempts: int, last_text: str) -> None:
        super().__init__(message)
        self.attempts = attempts
        self.last_text = last_text


@dataclass
class StructuredResult(Generic[T]):
    value: T
    attempts: int  # 1 = valid on the first try
    prompt_tokens: int
    completion_tokens: int
    duration_s: float
    cached: bool = False


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t
        t = t.rsplit("```", 1)[0]
    return t.strip()


def _problem(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        parts = [f"{'.'.join(map(str, e['loc'])) or 'root'}: {e['msg']}" for e in exc.errors()[:4]]
        return "; ".join(parts)
    return f"not parseable as JSON ({exc})"[:200]


def structured_chat(
    client: LLMProvider,
    messages: list[dict[str, str]],
    model_cls: type[T],
    *,
    model: str | None = None,
    max_repairs: int = MAX_REPAIRS,
    max_tokens: int = 700,
    cache: ResponseCache | None = None,
    prompt_version: str = "",
) -> StructuredResult[T]:
    schema = model_cls.model_json_schema()
    convo = list(messages)
    key = ""
    if cache is not None:
        options = {**client.answer_settings(), "schema": model_cls.__name__}
        key = cache_key(prompt_version, model or client.model, options, messages)
        if (hit := cache.get(key)) is not None:
            try:
                return StructuredResult(model_cls.model_validate_json(hit), 0, 0, 0, 0.0, True)
            except ValidationError:
                pass  # schema changed since it was cached: ask the model again
    total = ChatResult("")
    last = ""
    for attempt in range(1, max_repairs + 2):
        res = client.chat(convo, schema=schema, model=model, max_tokens=max_tokens)
        total.prompt_tokens += res.prompt_tokens
        total.completion_tokens += res.completion_tokens
        total.duration_s += res.duration_s
        last = res.text
        try:
            value = model_cls.model_validate(json.loads(_strip_fences(res.text)))
        except (json.JSONDecodeError, ValidationError) as exc:
            repair = _REPAIR.format(problem=_problem(exc))
            convo = [
                *convo,
                {"role": "assistant", "content": res.text[:2000]},
                {"role": "user", "content": repair},
            ]
            continue
        if cache is not None:
            cache.put(key, model or client.model, prompt_version, value.model_dump_json())
        return StructuredResult(value, attempt, total.prompt_tokens, total.completion_tokens,
                                round(total.duration_s, 2))  # fmt: skip
    raise StructuredOutputError(
        f"model output invalid after {max_repairs + 1} attempts", max_repairs + 1, last[:500]
    )
