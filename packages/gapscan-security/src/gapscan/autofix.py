"""Verified autofix: a patch is offered only if GapScan itself confirms it works.

1. The model proposes a patch as exact text (`old` -> `new`), validated against a schema (hard
   rule #6). Nothing is ever applied to the real project during this step.
2. The patch is applied to a temporary *copy* of the project.
3. The scanners that reported the finding are run on the copy before and after the patch. The patch
   is verified only if the finding is gone and no new finding appeared.
4. A rejected patch is retried once with the reason as feedback; otherwise there is no offer.

Not done on purpose: running the project's own build or tests against the patch. That would execute
scanned code, which hard rule #1 forbids; the roadmap's optional sandboxed test step needs the owner
to amend that rule first.
"""

from __future__ import annotations

import difflib
import logging
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field

from .agent.triage import finding_text
from .config import Config
from .context.extract import build_context
from .core.interfaces import LLMError, LLMProvider
from .llm.cache import ResponseCache
from .llm.prompts import latest_version, render_prompt
from .llm.structured import StructuredOutputError, structured_chat
from .models import Category, CodeContext, Finding
from .scanners import scan_target

log = logging.getLogger(__name__)

PROMPT_NAME = "autofix"
MAX_ATTEMPTS = 2
MAX_CHANGED_LINES = 40
MAX_COPY_FILES = 8000
MAX_COPY_BYTES = 150 * 1024 * 1024
COPY_SKIP = (
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    ".tox",
)


class PatchProposal(BaseModel):
    """What the model fills."""

    old: str = Field(min_length=1, max_length=4000)
    new: str = Field(max_length=4000)
    explanation: str = Field(max_length=800)


class Check(BaseModel):
    name: str
    ok: bool
    detail: str = ""


class FixOffer(BaseModel):
    finding_id: str
    file: str
    diff: str
    old: str  # the exact text replaced and its replacement, so `apply_offer` needs nothing else
    new: str
    explanation: str
    verified: bool
    checks: list[Check] = Field(default_factory=list)
    new_findings: list[str] = Field(default_factory=list)
    attempts: int = 1
    prompt_version: str = ""
    model: str = ""


class NoFix(Exception):
    """No verified fix: `str(exc)` says why (shown to the user)."""


def _key(f: Finding) -> tuple[str, str, str]:
    return (f.file or "", ",".join(sorted(f.cwe)) or f.rule_id, f.category.value)


def apply_proposal(original: str, p: PatchProposal) -> str:
    """The patched file text, or NoFix if the proposal is not a clean single replacement."""
    n = original.count(p.old)
    if n != 1:
        raise NoFix(f"`old` must appear exactly once in the file but appears {n} times")
    if p.old == p.new:
        raise NoFix("the patch changes nothing")
    patched = original.replace(p.old, p.new, 1)
    changed = sum(
        1
        for ln in difflib.unified_diff(
            original.splitlines(), patched.splitlines(), lineterm="", n=0
        )
        if ln[:1] in "+-" and ln[:3] not in ("+++", "---")
    )
    if changed > MAX_CHANGED_LINES:
        raise NoFix(f"the patch changes {changed} lines (limit {MAX_CHANGED_LINES})")
    return patched


def _copy_project(target: Path, dest: Path) -> None:
    files = size = 0
    for p in target.rglob("*"):
        if p.is_file() and not any(part in COPY_SKIP for part in p.relative_to(target).parts):
            files += 1
            size += p.stat().st_size
            if files > MAX_COPY_FILES or size > MAX_COPY_BYTES:
                raise NoFix("project too large to verify a patch on a copy")
    shutil.copytree(target, dest, ignore=shutil.ignore_patterns(*COPY_SKIP), symlinks=False)


def _scan_keys(config: Config, root: Path, work: Path) -> Counter[tuple[str, str, str]]:
    return Counter(_key(f) for f in scan_target(config, root, work).findings)


def verify_patch(
    config: Config, target: Path, finding: Finding, file: str, patched: str
) -> tuple[list[Check], list[str]]:
    """Run the reporting scanners on a copy before and after the patch."""
    names = [s for s in finding.sources or [finding.scanner] if s in config.scanners.enabled]
    if not names:
        raise NoFix("none of the scanners that reported this finding is enabled, cannot verify")
    cfg = config.model_copy(deep=True)
    cfg.scanners.enabled = names
    with tempfile.TemporaryDirectory(prefix="gapscan-fix-") as tmp:
        copy = Path(tmp) / "project"
        _copy_project(target, copy)
        before = _scan_keys(cfg, copy, Path(tmp) / "w1")
        (copy / file).write_text(patched, encoding="utf-8")
        after = _scan_keys(cfg, copy, Path(tmp) / "w2")
    k = _key(finding)
    removed = after[k] < before[k]
    new = [
        f"{a} {b}" for (a, b, _c), n in after.items() if n > before[(a, b, _c)] and (a, b, _c) != k
    ]
    checks = [
        Check(name="finding removed", ok=removed, detail=f"{before[k]} -> {after[k]} like it"),
        Check(name="no new findings", ok=not new, detail=", ".join(new[:5])),
        Check(name="re-scanned with", ok=True, detail=", ".join(names)),
    ]
    return checks, new


def _diff(file: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(True), after.splitlines(True), f"a/{file}", f"b/{file}"
        )
    )


def suggest_verified_fix(
    config: Config,
    target: Path,
    finding: Finding,
    *,
    client: LLMProvider,
    cache: ResponseCache | None = None,
    context: CodeContext | None = None,
) -> FixOffer:
    """A verified patch for `finding`, or NoFix explaining why there is none."""
    if finding.category not in (Category.CODE, Category.CONFIG) or not finding.file:
        raise NoFix(
            "autofix covers code and configuration findings; use the upgrade or rotation advice"
        )
    target = target.resolve()
    path = (target / finding.file).resolve()
    if not path.is_relative_to(target) or not path.is_file():
        raise NoFix("the flagged file is not inside the target")
    original = path.read_text(encoding="utf-8")
    context = context or build_context(
        finding, target, budget_tokens=config.llm.code_context_tokens
    )
    version = latest_version(PROMPT_NAME)
    feedback = ""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        prompt = render_prompt(
            version, finding_text=finding_text(finding, context), feedback=feedback
        )
        try:
            res = structured_chat(
                client, [{"role": "user", "content": prompt}], PatchProposal,
                max_tokens=900, cache=cache, prompt_version=version,
            )  # fmt: skip
        except (StructuredOutputError, LLMError) as exc:
            raise NoFix(f"the model did not return a usable patch: {str(exc)[:200]}") from exc
        try:
            patched = apply_proposal(original, res.value)
            checks, new = verify_patch(config, target, finding, finding.file, patched)
        except NoFix as exc:
            feedback = str(exc)
            if attempt == MAX_ATTEMPTS:
                raise
            continue
        if all(c.ok for c in checks):
            return FixOffer(
                finding_id=finding.id, file=finding.file, diff=_diff(finding.file, original, patched),
                old=res.value.old, new=res.value.new, explanation=res.value.explanation, verified=True, checks=checks, new_findings=new,
                attempts=attempt, prompt_version=version, model=client.model,
            )  # fmt: skip
        feedback = "; ".join(f"{c.name}: {c.detail or 'failed'}" for c in checks if not c.ok)
        if attempt == MAX_ATTEMPTS:
            raise NoFix(f"the patch did not verify ({feedback})")
    raise NoFix("no patch proposed")  # unreachable; keeps the type checker satisfied


def apply_offer(target: Path, offer: FixOffer) -> None:
    """Write a verified patch to the real file (only on an explicit request)."""
    root = target.resolve()
    path = (root / offer.file).resolve()
    if not path.is_relative_to(root) or not offer.verified:
        raise NoFix("refusing to apply an unverified patch or one outside the target")
    patch = PatchProposal(old=offer.old, new=offer.new, explanation=offer.explanation)
    path.write_text(apply_proposal(path.read_text("utf-8"), patch), encoding="utf-8")
