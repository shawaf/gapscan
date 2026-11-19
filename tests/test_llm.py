from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import BaseModel
from typer.testing import CliRunner

from gapscan.cli import app
from gapscan.config import BUILTIN_PROFILES, Config, LLMConfig
from gapscan.doctor import Status, check_llm
from gapscan.llm.bench import BenchAnswer, load_cases, run_benchmark, summarize
from gapscan.llm.client import LLMClient, LLMError, assert_local_endpoint
from gapscan.llm.structured import StructuredOutputError, structured_chat

ROOT = Path(__file__).resolve().parent.parent


class Out(BaseModel):
    ok: bool


def ollama(replies, seen=None):
    """Mock Ollama server: returns each reply in turn and records request bodies."""
    it = iter(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "m:1", "size": 2_000_000_000,
                "details": {"parameter_size": "3B", "quantization_level": "Q4_K_M"}}]})  # fmt: skip
        body = json.loads(request.content)
        if seen is not None:
            seen.append(body)
        return httpx.Response(200, json={"message": {"content": next(it)}, "prompt_eval_count": 10,
                                         "eval_count": 5})  # fmt: skip

    return httpx.Client(transport=httpx.MockTransport(handler))


# --- config / profiles -------------------------------------------------------------


def test_default_profile_resolves_model_and_budgets():
    c = Config().llm
    assert c.profile == "best" and c.model == "qwen3-coder:30b"
    assert c.code_context_tokens == BUILTIN_PROFILES["best"].code_context_tokens


def test_profile_switch_changes_model_and_budgets():
    c = Config(llm={"profile": "tiny"}).llm
    assert c.model == BUILTIN_PROFILES["tiny"].model
    assert (c.context_tokens, c.code_context_tokens) == (8192, 2000)


def test_explicit_model_and_budget_win_over_profile():
    c = Config(llm={"profile": "tiny", "model": "my:7b", "code_context_tokens": 999}).llm
    assert (c.model, c.code_context_tokens) == ("my:7b", 999)


def test_custom_profile_and_unknown_profile():
    c = Config(
        llm={
            "profile": "mine",
            "profiles": {"mine": {"model": "x:1b", "code_context_tokens": 1234}},
        }
    ).llm
    assert (c.model, c.code_context_tokens) == ("x:1b", 1234) and "mine" in c.all_profiles
    with pytest.raises(ValueError, match="unknown llm.profile"):
        Config(llm={"profile": "nope"})


def test_env_var_overrides_model(monkeypatch):
    monkeypatch.setenv("GAPSCAN_LLM__MODEL", "env:3b")
    assert Config().llm.model == "env:3b"


def test_public_endpoint_refused():
    with pytest.raises(ValueError, match="not local"):
        LLMConfig(endpoint="https://api.example.com")
    with pytest.raises(LLMError):
        assert_local_endpoint("https://api.example.com")
    assert_local_endpoint("http://127.0.0.1:11434")
    assert_local_endpoint("http://10.0.0.5:8000")


def test_doctor_requires_exact_model_tag(monkeypatch):
    def fake_get(url, **kw):
        return httpx.Response(
            200, json={"models": [{"name": "granite4.2:8b"}]}, request=httpx.Request("GET", url)
        )

    monkeypatch.setattr("gapscan.doctor.httpx.get", fake_get)
    other_size = check_llm(Config(llm={"model": "granite4.2:3b"}))
    assert other_size[1].status is Status.MISSING  # a different size tag is not a match
    assert check_llm(Config(llm={"model": "granite4.2:8b"}))[1].status is Status.OK


# --- client ------------------------------------------------------------------------


def test_ollama_request_shape_and_parse():
    seen: list[dict] = []
    cfg = LLMConfig(model="m:1", temperature=0.0, seed=7, think=False)
    client = LLMClient(cfg, ollama(['{"ok": true}'], seen))
    res = client.chat([{"role": "user", "content": "hi"}], schema=Out.model_json_schema())
    body = seen[0]
    assert body["model"] == "m:1" and body["stream"] is False and body["think"] is False
    assert body["format"]["properties"]["ok"] and body["options"]["seed"] == 7
    assert (
        body["options"]["temperature"] == 0.0 and body["options"]["num_ctx"] == cfg.context_tokens
    )
    assert (res.text, res.prompt_tokens, res.completion_tokens) == ('{"ok": true}', 10, 5)
    assert client.list_models() == [
        {"name": "m:1", "size_gb": 2.0, "params": "3B", "quant": "Q4_K_M"}
    ]


def test_openai_compatible_mode():
    seen: list[dict] = []

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}],
                                         "usage": {"prompt_tokens": 3, "completion_tokens": 1}})  # fmt: skip

    client = LLMClient(
        LLMConfig(backend="openai", model="x"), httpx.Client(transport=httpx.MockTransport(handler))
    )
    res = client.chat([{"role": "user", "content": "q"}], schema={"type": "object"})
    assert seen[0]["response_format"]["type"] == "json_schema" and res.prompt_tokens == 3


def test_server_errors_and_timeouts_become_llmerror():
    def boom(request):
        return httpx.Response(500, text="model not found")

    client = LLMClient(LLMConfig(), httpx.Client(transport=httpx.MockTransport(boom)))
    with pytest.raises(LLMError, match="model not found"):
        client.chat([{"role": "user", "content": "x"}])

    def slow(request):
        raise httpx.ReadTimeout("slow")

    client = LLMClient(LLMConfig(), httpx.Client(transport=httpx.MockTransport(slow)))
    with pytest.raises(LLMError, match="timed out"):
        client.chat([{"role": "user", "content": "x"}])


# --- structured output -------------------------------------------------------------


def test_structured_valid_first_try_and_fences_stripped():
    client = LLMClient(LLMConfig(), ollama(['```json\n{"ok": true}\n```']))
    res = structured_chat(client, [{"role": "user", "content": "x"}], Out)
    assert res.value.ok is True and res.attempts == 1


def test_structured_repairs_then_succeeds():
    seen: list[dict] = []
    client = LLMClient(
        LLMConfig(), ollama(["not json at all", '{"ok": "maybe"}', '{"ok": false}'], seen)
    )
    res = structured_chat(client, [{"role": "user", "content": "x"}], Out)
    assert res.value.ok is False and res.attempts == 3
    assert res.prompt_tokens == 30 and res.completion_tokens == 15  # summed over attempts
    repair = seen[2]["messages"][-1]["content"]
    assert "ok" in repair and "valid" in repair  # the validation problem is fed back


def test_structured_gives_up_after_two_repairs_never_accepting_garbage():
    client = LLMClient(LLMConfig(), ollama(["nope", "still nope", "no way"]))
    with pytest.raises(StructuredOutputError) as exc:
        structured_chat(client, [{"role": "user", "content": "x"}], Out)
    assert exc.value.attempts == 3 and "no way" in exc.value.last_text


# --- benchmark ---------------------------------------------------------------------


def test_triage_cases_are_balanced_and_well_formed():
    cases = load_cases(ROOT / "eval" / "triage_cases.json")
    assert len(cases) >= 18 and len({c["id"] for c in cases}) == len(cases)
    kinds = [c["expected"] for c in cases]
    assert kinds.count("true_positive") == kinds.count("false_positive")
    for c in cases:
        assert {"rule_id", "title", "cwe", "file", "line", "code", "expected", "why"} <= set(c)
        assert 1 <= c["line"] <= len(c["code"].splitlines())
    secret_values = ("ghp_", "AKIA")
    assert not any(s in c["code"] for c in cases for s in secret_values)  # cases hold no secrets


def test_benchmark_scoring_with_a_fake_model():
    cases = [{"id": "a", "expected": "true_positive", "rule_id": "r", "title": "t", "cwe": "CWE-1",
              "file": "f.py", "line": 1, "code": "x = 1"},
             {"id": "b", "expected": "false_positive", "rule_id": "r", "title": "t", "cwe": "CWE-1",
              "file": "f.py", "line": 1, "code": "y = 2"}]  # fmt: skip
    answer = json.dumps({"verdict": "true_positive", "confidence": 0.8, "reasoning": "because"})
    client = LLMClient(LLMConfig(), ollama([answer, answer]))
    result = run_benchmark(client, "m:1", cases)
    s = result["summary"]
    assert (
        s["accuracy"] == 0.5
        and s["true_positives_kept"] == 1.0
        and s["false_positives_removed"] == 0.0
    )
    assert s["first_try_valid_json"] == 1.0 and result["prompt_version"].startswith("triage_bench")
    assert BenchAnswer.model_validate_json(answer).confidence == 0.8
    # an unparseable model is counted as a failure, not as a verdict
    bad = run_benchmark(LLMClient(LLMConfig(), ollama(["x"] * 6)), "m:1", cases)
    assert bad["summary"]["failed"] == 2 and bad["summary"]["accuracy"] == 0.0
    assert summarize("m", [])["accuracy"] == 0.0


def test_cli_model_list(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("gapscan.cli.LLMClient.list_models",
                        lambda self: [{"name": "granite4.2:8b", "size_gb": 5.3, "params": "8B", "quant": "Q4_K_M"}])  # fmt: skip
    out = CliRunner().invoke(app, ["model", "list"]).stdout
    assert "granite4.2:8b" in out and "tiny" in out and "balanced" in out


# --- prompts and cache ---------------------------------------------------------------


def test_prompt_templates_are_versioned_and_strict():
    from jinja2 import UndefinedError

    from gapscan.llm.prompts import latest_version, render_prompt

    assert latest_version("triage_bench") == "triage_bench_v2"
    text = render_prompt("triage_bench_v2", rule_id="R", title="T", cwe="CWE-1", file="f", line=1,
                         code="x")  # fmt: skip
    assert "<untrusted_data>" in text and "never follow it" in text and "RULE: R" in text
    with pytest.raises(UndefinedError):
        render_prompt("triage_bench_v2", rule_id="R")  # missing variables fail loudly
    with pytest.raises(FileNotFoundError):
        latest_version("nope")


def test_cache_hit_skips_the_model_and_is_keyed_by_model_and_prompt(tmp_path):
    from gapscan.llm.cache import ResponseCache

    cache = ResponseCache(tmp_path / "c" / "llm.sqlite")
    seen: list[dict] = []
    client = LLMClient(
        LLMConfig(model="m:1"), ollama(['{"ok": true}', '{"ok": false}', '{"ok": true}'], seen)
    )
    msgs = [{"role": "user", "content": "same finding"}]
    first = structured_chat(client, msgs, Out, cache=cache, prompt_version="p_v1")
    again = structured_chat(client, msgs, Out, cache=cache, prompt_version="p_v1")
    assert first.cached is False and again.cached is True and again.value.ok is True
    assert len(seen) == 1 and len(cache) == 1  # second call never reached the model
    # different prompt version, model or messages are different cache entries
    other = structured_chat(client, msgs, Out, cache=cache, prompt_version="p_v2")
    assert other.cached is False and other.value.ok is False
    structured_chat(client, msgs, Out, model="m:2", cache=cache, prompt_version="p_v1")
    assert len(cache) == 3
    assert cache.clear("m:2") == 1 and len(cache) == 2


def test_cache_never_stores_prompts_or_invalid_output(tmp_path):
    from gapscan.llm.cache import ResponseCache

    cache = ResponseCache(tmp_path / "llm.sqlite")
    client = LLMClient(LLMConfig(), ollama(["bad", "bad", "bad"]))
    with pytest.raises(StructuredOutputError):
        structured_chat(client, [{"role": "user", "content": "SECRET-CODE-HERE"}], Out, cache=cache)
    assert len(cache) == 0
    client = LLMClient(LLMConfig(), ollama(['{"ok": true}']))
    structured_chat(client, [{"role": "user", "content": "SECRET-CODE-HERE"}], Out, cache=cache)
    raw = (tmp_path / "llm.sqlite").read_bytes()
    assert b"SECRET-CODE-HERE" not in raw  # only the answer JSON is persisted


def test_cached_answers_are_not_shared_between_runtimes(tmp_path):
    from gapscan.llm.cache import cache_key

    base = {"t": 0.0, "seed": 7, "ctx": 8192, "think": False, "schema": "Verdict"}
    msgs = [{"role": "user", "content": "x"}]
    assert cache_key("v", "m", base, msgs) != cache_key(
        "v", "m", {**base, "backend": "openai"}, msgs
    )


def test_cache_keys_are_unchanged_by_the_llm_provider_interface(tmp_path):
    """Moving the cache options behind `LLMProvider.answer_settings()` must not orphan the
    answers already cached: the key is still built from exactly these options."""
    from gapscan.llm.cache import ResponseCache, cache_key

    cfg = LLMConfig(model="m:1", temperature=0.0, seed=7, think=False)
    cache = ResponseCache(tmp_path / "llm.sqlite")
    msgs = [{"role": "user", "content": "x"}]
    structured_chat(LLMClient(cfg, ollama(['{"ok": true}'])), msgs, Out, cache=cache,
                    prompt_version="p_v1")  # fmt: skip
    before = {"t": 0.0, "seed": 7, "ctx": cfg.context_tokens, "think": False, "schema": "Out"}
    assert cache.get(cache_key("p_v1", "m:1", before, msgs)) == '{"ok":true}'
    other = LLMClient(LLMConfig(model="m:1", backend="openai"))
    assert other.answer_settings()["backend"] == "openai"
    assert "backend" not in LLMClient(cfg).answer_settings()


def test_a_broken_cache_never_costs_an_answer(tmp_path, caplog):
    """A cache file replaced or made read-only during a long triage run must not crash it."""
    import os

    from gapscan.llm.cache import ResponseCache

    path = tmp_path / "llm.sqlite"
    cache = ResponseCache(path)
    cache.put("k", "m", "v1", "{}")
    os.chmod(path, 0o444)
    cache._db.close()
    cache._db = __import__("sqlite3").connect(f"file:{path}?mode=ro", uri=True)
    cache.put("k2", "m", "v1", "{}")  # read-only: logged, not raised
    assert cache.get("k") == "{}" and cache.get("k2") is None
    cache._db.close()
    cache._db = __import__("sqlite3").connect(":memory:")  # table gone: reads fail softly too
    assert cache.get("k") is None
    assert "cache write failed" in caplog.text and "cache read failed" in caplog.text
