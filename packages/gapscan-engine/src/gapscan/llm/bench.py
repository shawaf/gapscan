"""Model benchmark: run labeled triage cases through any model and report accuracy, schema
validity, speed and tokens, so the model choice rests on measurements. This is the seed of
the Phase 8 evaluation harness."""

from __future__ import annotations

import json
import statistics
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..core.interfaces import LLMError, LLMProvider
from .prompts import render_prompt
from .structured import StructuredOutputError, structured_chat

PROMPT_VERSION = "triage_bench_v2"


class BenchVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class BenchAnswer(BaseModel):
    verdict: BenchVerdict
    confidence: float = Field(ge=0, le=1)
    reasoning: str = Field(max_length=600)


def _render(case: dict[str, Any]) -> str:
    numbered = "\n".join(f"{i + 1:>4} | {ln}" for i, ln in enumerate(case["code"].splitlines()))
    return render_prompt(PROMPT_VERSION, **{**case, "code": numbered})


def run_case(client: LLMProvider, model: str, case: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"id": case["id"], "expected": case["expected"]}
    try:
        res = structured_chat(client, [{"role": "user", "content": _render(case)}], BenchAnswer,
                              model=model)  # fmt: skip
    except StructuredOutputError as exc:
        return {**out, "status": "invalid_output", "attempts": exc.attempts, "verdict": None,
                "correct": False}  # fmt: skip
    except LLMError as exc:
        return {
            **out,
            "status": "error",
            "error": str(exc)[:200],
            "verdict": None,
            "correct": False,
        }
    v = res.value
    return {**out, "status": "ok", "attempts": res.attempts, "verdict": v.verdict.value,
            "confidence": v.confidence, "correct": v.verdict.value == case["expected"],
            "seconds": res.duration_s, "prompt_tokens": res.prompt_tokens,
            "completion_tokens": res.completion_tokens, "reasoning": v.reasoning}  # fmt: skip


def summarize(model: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(results)
    tp = [r for r in results if r["expected"] == "true_positive"]
    fp = [r for r in results if r["expected"] == "false_positive"]
    ok = [r for r in results if r["status"] == "ok"]
    secs = [r["seconds"] for r in ok]
    return {
        "model": model,
        "cases": n,
        "accuracy": round(sum(r["correct"] for r in results) / n, 3) if n else 0.0,
        # The two numbers that matter for triage: real bugs kept, false alarms removed.
        "true_positives_kept": round(sum(r["correct"] for r in tp) / len(tp), 3) if tp else None,
        "false_positives_removed": (
            round(sum(r["correct"] for r in fp) / len(fp), 3) if fp else None
        ),
        "first_try_valid_json": round(sum(r.get("attempts") == 1 for r in ok) / n, 3) if n else 0.0,
        "failed": sum(r["status"] != "ok" for r in results),
        "median_seconds": round(statistics.median(secs), 1) if secs else None,
        "mean_completion_tokens": (
            round(statistics.mean(r["completion_tokens"] for r in ok)) if ok else None
        ),
    }


def run_benchmark(client: LLMProvider, model: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    results = [run_case(client, model, c) for c in cases]
    return {
        "prompt_version": PROMPT_VERSION,
        "summary": summarize(model, results),
        "results": results,
    }


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    return cases
