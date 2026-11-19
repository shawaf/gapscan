"""Run the evaluation: scan each target, score the scanners against ground truth, have the model
triage (all findings of the labeled fixtures; a reproducible sample elsewhere), score the triage,
and write one comparable result file per run.

Nothing here executes the targets: they are only scanned (hard rule #1)."""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..agent.review import triage_top_findings
from ..config import Config
from ..core.interfaces import LLMProvider
from ..core.version import __version__
from ..models import Finding, ScanResult
from ..owasp.packs import TOP10
from ..pipeline import run_scan
from . import benchmark as bench
from .labels import finding_truth, load_labels
from .metrics import TriageItem, check_targets, scanner_metrics, triage_metrics
from .targets import Target, is_fetched, load_targets

Progress = Callable[[str], None]
SCAN_TIMEOUT_S = 3600


def _eval_config(config: Config) -> Config:
    """A copy tuned for evaluation: long scanner timeouts and no cap on how many findings are triaged."""
    cfg = config.model_copy(deep=True)
    cfg.scanners.timeout_s = max(cfg.scanners.timeout_s, SCAN_TIMEOUT_S)
    cfg.general.max_llm_findings = 1_000_000
    return cfg


def _require(client: LLMProvider | None) -> LLMProvider:
    """The provider triage runs on; the app constructs it (ARCHITECTURE.md section 4)."""
    if client is None:
        raise ValueError("triage needs an LLM provider: pass client=, or triage=False")
    return client


def _scan(cfg: Config, directory: Path, progress: Progress) -> tuple[ScanResult, float]:
    progress(f"scanning {directory} ...")
    t0 = time.monotonic()
    result = run_scan(cfg, directory)
    return result, round(time.monotonic() - t0, 1)


def _scanner_runs(result: ScanResult) -> list[dict[str, Any]]:
    return [{"scanner": r.scanner, "status": r.status, "version": r.version, "findings": r.finding_count,
             "seconds": r.duration_s} for r in result.runs]  # fmt: skip


def _mistakes(
    items: list[TriageItem], findings: dict[str, Finding], limit: int = 40
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i in items:
        v = i.verdict
        if v is None or v.triage_failed:
            out.append(
                {"finding": i.finding_id, "problem": "triage_failed" if v else "not_triaged"}
            )
            continue
        wrong = (i.vulnerable and v.verdict.value == "false_positive") or (
            not i.vulnerable and v.verdict.value in ("true_positive", "likely_true_positive")
        )
        if wrong:
            f = findings[i.finding_id]
            out.append({"finding": i.finding_id, "rule": f.rule_id, "location": f"{f.file}:{f.start_line}", "kind": i.kind,
                        "truth": "vulnerable" if i.vulnerable else "not_vulnerable", "verdict": v.verdict.value,
                        "confidence": v.confidence, "reasoning": v.reasoning[:240]})  # fmt: skip
    return out[:limit]


# --------------------------------------------------------------------------- fixtures


def run_fixtures(config: Config, directory: Path, *, triage: bool = True, client: LLMProvider | None = None,
                 progress: Progress = lambda _m: None) -> dict[str, Any]:  # fmt: skip
    cfg = _eval_config(config)
    labels = load_labels(directory)
    result, scan_s = _scan(cfg, directory, progress)
    out: dict[str, Any] = {
        "target": str(directory),
        "scan_seconds": scan_s,
        "scanners": _scanner_runs(result),
        "scanner": scanner_metrics(result.findings, labels),
    }
    if not triage:
        return out
    progress(f"triaging {len(result.findings)} findings ...")
    verdicts = triage_top_findings(cfg, result, directory, limit=len(result.findings), client=_require(client),
                                   on_verdict=lambda v: progress(f"  {v.finding_id} {v.verdict.value}"))  # fmt: skip
    by_id = {f.id: f for f in result.findings}
    vmap = {v.finding_id: v for v in verdicts}
    items = []
    for f in result.findings:
        truth = finding_truth(f, labels)
        items.append(TriageItem(f.id, truth.vulnerable, vmap.get(f.id), truth.kind))
    tm = triage_metrics(items)
    per_cwe: dict[str, list[TriageItem]] = {}
    for item in items:
        lb = next(
            (x for x in labels if finding_truth(by_id[item.finding_id], labels).site == x.id), None
        )
        per_cwe.setdefault(lb.cwe if lb else "(stray)", []).append(item)
    out.update(triage=tm, checks=check_targets(tm), triage_by_cwe={k: triage_metrics(v) for k, v in sorted(per_cwe.items())},
               mistakes=_mistakes(items, by_id), models=sorted({v.model for v in verdicts}),
               prompt_versions=sorted({v.prompt_version for v in verdicts}))  # fmt: skip
    return out


# --------------------------------------------------------------------------- OWASP Benchmark


def run_benchmark_java(config: Config, target: Target, root: Path, *, sample: int = 3, triage: bool = True,
                       client: LLMProvider | None = None, progress: Progress = lambda _m: None) -> dict[str, Any]:  # fmt: skip
    cfg = _eval_config(config)
    base = root / target.name
    cases = bench.load_expected(base / target.truth_file)
    result, scan_s = _scan(cfg, base / target.scan_subdir, progress)
    flagged = bench.flagged_cases(result.findings, cases)
    out: dict[str, Any] = {
        "target": target.name,
        "sha": target.sha,
        "license": target.license,
        "scan_seconds": scan_s,
        "scanners": _scanner_runs(result),
        "findings": len(result.findings),
        "test_cases": len(cases),
        "scorecard": bench.scorecard(set(flagged), cases),
    }
    if not triage:
        return out
    picked = bench.triage_sample(flagged, cases, sample)
    progress(f"triaging a sample of {len(picked)} benchmark findings ...")
    subset = result.model_copy(update={"findings": [f for f, _ in picked]})
    for f in subset.findings:
        f.llm_triage = True
    verdicts = triage_top_findings(cfg, subset, base / target.scan_subdir, limit=len(picked), client=_require(client),
                                   on_verdict=lambda v: progress(f"  {v.finding_id} {v.verdict.value}"))  # fmt: skip
    vmap = {v.finding_id: v for v in verdicts}
    items = [TriageItem(f.id, case.real, vmap.get(f.id), "benchmark") for f, case in picked]
    tm = triage_metrics(items)
    # Scorecard after review: the sampled cases whose finding the model dismissed no longer count as flagged.
    still = {
        case.name
        for f, case in picked
        if vmap.get(f.id) is None or vmap[f.id].verdict.value != "false_positive"
    }
    sampled_names = {case.name for _, case in picked}
    sampled_cases = {n: cases[n] for n in sampled_names}
    out.update(triage_sample=len(picked), triage=tm, checks=check_targets(tm),
               scorecard_sample_before=bench.scorecard(sampled_names, sampled_cases),
               scorecard_sample_after=bench.scorecard(still, sampled_cases),
               mistakes=_mistakes(items, {f.id: f for f, _ in picked}),
               models=sorted({v.model for v in verdicts}))  # fmt: skip
    return out


# --------------------------------------------------------------------------- unlabeled apps


def run_stats_target(config: Config, target: Target, root: Path, *, sample: int = 15, triage: bool = True,
                     client: LLMProvider | None = None, progress: Progress = lambda _m: None) -> dict[str, Any]:  # fmt: skip
    """Apps with no line-level ground truth: scale, runtime, category spread, and how much of a
    sample of top findings the model dismisses (a rate, not an accuracy)."""
    cfg = _eval_config(config)
    base = root / target.name
    result, scan_s = _scan(cfg, base / target.scan_subdir if target.scan_subdir else base, progress)
    open_findings = result.findings
    out: dict[str, Any] = {
        "target": target.name,
        "sha": target.sha,
        "license": target.license,
        "scan_seconds": scan_s,
        "scanners": _scanner_runs(result),
        "findings": len(open_findings),
        "by_severity": dict(Counter(f.severity.value for f in open_findings)),
        "by_category": dict(Counter(f.category.value for f in open_findings)),
        "by_owasp": dict(Counter(c for f in open_findings for c in f.control_ids(TOP10))),
        "files_with_findings": len({f.file for f in open_findings if f.file}),
    }
    if triage and open_findings:
        code = [f for f in open_findings if f.category.value in ("code", "secret", "config")]
        subset = result.model_copy(update={"findings": code[:sample]})
        progress(f"triaging {len(subset.findings)} top findings of {target.name} ...")
        verdicts = triage_top_findings(cfg, subset, base, limit=sample, client=_require(client))
        counts = Counter(v.verdict.value for v in verdicts if not v.triage_failed)
        out["triage_sample"] = {"reviewed": len(verdicts), "verdicts": dict(counts),
                                "dismissal_rate": round(counts.get("false_positive", 0) / max(len(verdicts), 1), 3),
                                "mean_seconds": round(sum(v.seconds for v in verdicts) / max(len(verdicts), 1), 1)}  # fmt: skip
    return out


# --------------------------------------------------------------------------- orchestration


def run_eval(config: Config, *, targets_file: Path, fixtures_dir: Path, selected: list[str], triage: bool = True,
             sample: int = 3, client: LLMProvider | None = None, progress: Progress = lambda _m: None,
             local_targets: dict[str, Any] | None = None, memory_mode: str = "none") -> dict[str, Any]:  # fmt: skip
    targets = load_targets(targets_file)
    selected = [
        x
        for n in selected
        for x in ([f"local:{k}" for k in (local_targets or {})] if n == "local" else [n])
    ]
    root = config.data.eval_dir
    results: dict[str, Any] = {}
    skipped: dict[str, str] = {}
    for name in selected:
        if name == "fixtures":
            results["fixtures"] = run_fixtures(
                config, fixtures_dir, triage=triage, client=client, progress=progress
            )
        elif name in targets:
            t = targets[name]
            if not is_fetched(root, t):
                skipped[name] = "not downloaded (run `gapscan eval fetch`)"
                continue
            if t.truth == "benchmark-csv":
                results[name] = run_benchmark_java(
                    config, t, root, sample=sample, triage=triage, client=client, progress=progress
                )
            else:
                results[name] = run_stats_target(
                    config, t, root, triage=triage, client=client, progress=progress
                )
        elif name.startswith("local:") and name[6:] in (local_targets or {}):
            from .local import run_local  # noqa: PLC0415 - optional, private projects only

            lt = (local_targets or {})[name[6:]]
            if not lt.path.is_dir() or not lt.labels.is_file():
                skipped[name] = "project folder or labels file not found"
                continue
            results[name] = run_local(config, lt, triage=triage, client=client, progress=progress,
                                      memory_mode=memory_mode)  # fmt: skip
        else:
            skipped[name] = "unknown target"
    models = sorted({m for r in results.values() for m in r.get("models", [])}) or [
        config.llm.model if triage else "no-triage"
    ]
    return {
        "meta": {
            "date": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "gapscan_version": __version__,
            "models": models,
            "triage": triage,
            "benchmark_sample_per_group": sample,
            "llm_profile": config.llm.profile,
            "memory_mode": memory_mode,
        },  # fmt: skip
        "results": results,
        "skipped": skipped,
    }


def result_path(directory: Path, result: dict[str, Any]) -> Path:
    model = (
        (result["meta"]["models"][0] if result["meta"]["models"] else "no-model")
        .replace(":", "_")
        .replace("/", "_")
    )
    # Two runs on the same day with different targets must not overwrite each other.
    targets = "+".join(sorted(k.replace(":", "-") for k in result.get("results", {})))
    suffix = f"-{targets}" if targets else ""
    mode = result.get("meta", {}).get("memory_mode", "none")
    suffix += f"-memory-{mode}" if mode != "none" else ""
    return directory / f"{result['meta']['date'][:10]}-{model}{suffix}.json"


def write_result(directory: Path, result: dict[str, Any]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = result_path(directory, result)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return path


def headline(result: dict[str, Any]) -> dict[str, Any]:
    """The few numbers that matter, flattened, for comparing two result files."""
    out: dict[str, Any] = {}
    r = result["results"]
    if "fixtures" in r:
        f = r["fixtures"]
        out["fixtures.recall"] = f["scanner"]["recall"]
        out["fixtures.finding_precision"] = f["scanner"]["finding_precision"]
        for k in (
            "accuracy",
            "decisive_accuracy",
            "false_positive_reduction",
            "true_positives_dismissed",
            "injection_resistance",
            "mean_tokens",
            "mean_seconds",
            "undecided",
        ):
            if "triage" in f:
                out[f"fixtures.{k}"] = f["triage"][k]
        for k in ("false_positive_reduction", "true_positives_dismissed"):
            ci = f.get("triage", {}).get(f"{k}_ci")
            if ci:
                out[f"fixtures.{k}_95ci"] = f"{ci[0]:.0%} to {ci[1]:.0%}"
    for name, v in r.items():
        if name == "fixtures":
            continue
        if "scorecard" in v:
            out[f"{name}.tpr"] = v["scorecard"]["overall"]["tpr"]
            out[f"{name}.fpr"] = v["scorecard"]["overall"]["fpr"]
            out[f"{name}.score"] = v["scorecard"]["overall"]["score"]
        if "triage" in v:
            for k in (
                "accuracy",
                "decisive_accuracy",
                "false_positive_reduction",
                "true_positives_dismissed",
            ):
                out[f"{name}.triage.{k}"] = v["triage"][k]
        if "triage_sample" in v and isinstance(v["triage_sample"], dict):
            out[f"{name}.dismissal_rate"] = v["triage_sample"]["dismissal_rate"]
        if name.startswith("local:"):
            out[f"{name}.scanner_precision"] = v.get("scanner_precision_on_labeled")
        out[f"{name}.findings"] = v.get("findings")
        out[f"{name}.scan_seconds"] = v.get("scan_seconds")
    return out
