"""Data flywheel (opt-in, on-premises): reviewer decisions become a fine-tuning dataset.

Each decision a person made on a finding (false positive, fixed, accepted risk) is turned into one
training example: the exact prompt the triage model would see, and the answer the reviewer's
decision implies, as JSON that validates against `TriageAnswer`. Examples are split by a hash of the
finding id into a training file and a held-out file (PLAN Phase 10: a tuned model is accepted only
if it beats the base model on held-out data). Secret-looking text is masked. Nothing leaves the
machine: the output is two local files and a manifest, and the export refuses to run unless
`[flywheel] enabled = true`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .agent.triage import finding_text, weakness_kind
from .config import Config
from .context.extract import build_context
from .llm.prompts import latest_version, render_prompt
from .models import ScanResult, TriageAnswer, VerdictLabel
from .redact import mask
from .report.decisions import Decisions

LABELS = {
    "false_positive": VerdictLabel.FALSE_POSITIVE,
    "fixed": VerdictLabel.TRUE_POSITIVE,  # someone fixed it, so it was real
    "accepted_risk": VerdictLabel.TRUE_POSITIVE,  # real, but the risk was accepted
}
MIN_NOTE = 12


class FlywheelDisabled(RuntimeError):
    """The owner has not opted in."""


@dataclass
class ExportStats:
    train: int
    heldout: int
    skipped: int
    out_dir: Path


def _holdout(finding_id: str, percent: int) -> bool:
    return int(hashlib.sha256(finding_id.encode()).hexdigest(), 16) % 100 < percent


def build_example(
    config: Config, result: ScanResult, target: Path, decision_id: str, kind: str, note: str
) -> dict[str, object] | None:
    finding = next((f for f in result.findings if f.id == decision_id), None)
    label = LABELS.get(kind)
    if finding is None or label is None:
        return None
    ctx = build_context(finding, target.resolve(), budget_tokens=config.llm.code_context_tokens)
    version = latest_version("triage")
    prompt = render_prompt(
        version,
        category=finding.category.value,
        weakness=weakness_kind(finding),
        finding_text=finding_text(finding, ctx),
        warning="",
    )
    reasoning = (
        " ".join(note.split())[:600]
        if len(note.split()) >= 2 and len(note) >= MIN_NOTE
        else (
            "A reviewer judged this a false alarm."
            if label is VerdictLabel.FALSE_POSITIVE
            else "A reviewer confirmed this as a real weakness."
        )
    )
    answer = TriageAnswer(
        verdict=label, confidence=0.9 if note else 0.75, reasoning=mask(reasoning)
    )
    return {
        "messages": [
            {"role": "user", "content": mask(prompt)},
            {"role": "assistant", "content": answer.model_dump_json(exclude_none=True)},
        ],
        "meta": {"finding_id": finding.id, "rule": finding.rule_id, "decision": kind,
                 "prompt_version": version},
    }  # fmt: skip


def export_dataset(
    config: Config, result: ScanResult, decisions: Decisions, target: Path, out_dir: Path
) -> ExportStats:
    if not config.flywheel.enabled:
        raise FlywheelDisabled(
            "the data flywheel is off. Set [flywheel] enabled = true in your config to export "
            "reviewer decisions as a local fine-tuning dataset (nothing is sent anywhere)."
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    train: list[str] = []
    held: list[str] = []
    skipped = 0
    for d in decisions.by_id().values():
        ex = build_example(config, result, target, d.finding_id, d.decision, d.note)
        if ex is None:
            skipped += 1
            continue
        line = json.dumps(ex, ensure_ascii=False)
        (held if _holdout(d.finding_id, config.flywheel.holdout_percent) else train).append(line)
    (out_dir / "train.jsonl").write_text("\n".join(train) + ("\n" if train else ""), "utf-8")
    (out_dir / "heldout.jsonl").write_text("\n".join(held) + ("\n" if held else ""), "utf-8")
    (out_dir / "manifest.json").write_text(
        json.dumps(
            {
                "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "train": len(train),
                "heldout": len(held),
                "skipped": skipped,
                "holdout_percent": config.flywheel.holdout_percent,
                "format": "chat messages (user prompt, assistant JSON answer) + meta",
                "note": "Local file. Contains code excerpts from your project: treat it like the source.",
            },
            indent=2,
        )
        + "\n",
        "utf-8",
    )
    return ExportStats(len(train), len(held), skipped, out_dir)
