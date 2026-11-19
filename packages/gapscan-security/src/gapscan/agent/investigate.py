"""Deep-dive investigation of one confirmed finding.

Triage decides whether a finding is real. This pass explains it the way a manual audit would:
what protection exists and where, which builds are affected, where else the same root cause
appears, what is missing, how to fix it in order, and how to verify the fix.

The model writes the prose; Python decides what may be shown as fact (hard rule #5):
- a cited `file:line` is kept only if those lines were shown to the model, either in the
  finding's own context or in a tool result;
- a `missing` claim is kept only if it names a `search_repo` text whose search covered every
  file and found nothing;
- a `related` location must be somewhere else: refs inside the investigated lines are dropped;
- everything else is dropped and listed in `Investigation.dropped`.

Same safety properties as the triage loop (agent.py): read-only allowlisted tools confined to
the target, tool output wrapped as untrusted data, schema-validated steps with repair retries.
"""

from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from ..context.injection import find_injection_lines, warning_for
from ..core.interfaces import LLMError, LLMProvider
from ..llm.cache import ResponseCache
from ..llm.prompts import latest_version, render_prompt
from ..llm.structured import StructuredOutputError, structured_chat
from ..models import (
    CodeContext,
    EvidenceEffect,
    Finding,
    Investigation,
    InvestigationAnswer,
    ToolCallRecord,
    Verdict,
)
from .agent import _tool_message
from .checklists import checklist_for, render_checklist
from .grounding import _REF, Seen, _norm, seen_from_context
from .grouping import group_id, weakness_class
from .tools import DEEP_TOOL_DESCRIPTIONS, ToolBox, manifest_lines
from .triage import finding_text, neutralize_delimiters

PROMPT_NAME = "investigate"
DEFAULT_MAX_TOOL_CALLS = 12

DeepTool = Literal[
    "read_code", "find_callers", "find_definition", "find_imports", "lookup_cwe", "search_kb",
    "search_repo", "list_files", "build_variants", "read_config",
]  # fmt: skip


class DeepStep(BaseModel):
    """One model turn in the deep dive: a tool call or the final investigation."""

    action: Literal["tool", "final"]
    tool: DeepTool | None = None
    args: dict[str, str | int] = Field(default_factory=dict)
    answer: InvestigationAnswer | None = None

    @model_validator(mode="after")
    def _consistent(self) -> DeepStep:
        if self.action == "tool" and (self.tool is None or self.answer is not None):
            raise ValueError("a tool step needs `tool` and must not include `answer`")
        if self.action == "final" and (self.answer is None or self.tool is not None):
            raise ValueError("a final step needs `answer` and must not include `tool`")
        return self


# --- grounding ---------------------------------------------------------------------------

# A search for a plain English word ("validation") proves nothing about code; absence claims
# must rest on code-shaped text: punctuation, an uppercase letter or a digit.
_CODE_SHAPED = re.compile(r"[._()=:<>/\-\[\]{}\"'$#@,;]|[A-Z]|\d")


def is_code_shaped(text: str) -> bool:
    return bool(_CODE_SHAPED.search(text.strip()))


def _overlaps(ref: str, own: list[tuple[str, int, int]]) -> bool:
    m = _REF.match(ref)
    if m is None:
        return False
    lo, hi = int(m["lo"]), int(m["hi"] or m["lo"])
    return any(_norm(m["file"]) == _norm(f) and lo <= b and a <= hi for f, a, b in own)


def own_lines(members: list[Finding]) -> list[tuple[str, int, int]]:
    """The lines the investigated group itself is about."""
    return [(f.file, f.start_line, f.end_line or f.start_line)
            for f in members if f.file and f.start_line]  # fmt: skip


def other_issue_lines(members: list[Finding], known: list[Finding]) -> list[tuple[str, int, int]]:
    """Lines of scan findings that are a different weakness from the investigated group (and
    not also flagged for the same weakness): a "related" ref there is another issue."""
    kinds = {weakness_class(m) for m in members}
    same = own_lines([f for f in known if weakness_class(f) in kinds])
    other = own_lines([f for f in known if weakness_class(f) not in kinds])
    return [o for o in other if not any(o[0] == s[0] and o[1] <= s[2] and s[1] <= o[2]
                                        for s in same)]  # fmt: skip


def ground(
    answer: InvestigationAnswer,
    seen: Seen,
    own: list[tuple[str, int, int]] | None = None,
    other_issues: list[tuple[str, int, int]] | None = None,
    vetted: set[str] | None = None,
) -> tuple[InvestigationAnswer, list[str]]:
    """Keep only items whose refs were shown to the model; return the reasons for the rest."""
    dropped: list[str] = []
    evidence = []
    for e in answer.evidence:
        if e.effect == EvidenceEffect.MISSING:
            key = (e.search or "").strip().lower()
            plain = not is_code_shaped(e.search or "") and key not in (vetted or set())
            if key in seen.empty_searches and plain:
                dropped.append(f"evidence (missing): {e.search!r} is a plain word, not code, so "
                               f"an empty search for it does not show {e.claim!r}")  # fmt: skip
            elif key in seen.empty_searches:
                update: dict[str, str | None] = {"search_scope": seen.empty_searches[key]}
                if e.ref and not seen.covers(e.ref):
                    update["ref"] = None  # the claim stands on the search
                evidence.append(e.model_copy(update=update))
            else:
                dropped.append(f"evidence (missing): no complete empty search backs {e.claim!r}")
        elif e.ref and seen.covers(e.ref):
            # only absence claims rest on a search; never show an unbacked "found nothing"
            evidence.append(e.model_copy(update={"search": None, "search_scope": None}))
        else:
            dropped.append(f"evidence: {e.ref or 'no ref'} was not shown for {e.claim!r}")
    scope = []
    for s in answer.scope:
        if seen.covers(s.ref):
            scope.append(s)
        else:
            dropped.append(f"scope: {s.ref} was not shown for {s.where!r}")
    related = []
    for r in answer.related:
        if not seen.covers(r.ref):
            dropped.append(f"related: {r.ref} was not shown")
        elif _overlaps(r.ref, own or []):
            dropped.append(f"related: {r.ref} is the finding itself, not another location")
        elif _overlaps(r.ref, other_issues or []):
            dropped.append(f"related: {r.ref} is a different kind of issue found by the scan")
        else:
            related.append(r)
    kept = answer.model_copy(update={"evidence": evidence, "scope": scope, "related": related})
    return kept, dropped


# --- loop -------------------------------------------------------------------------------


def _triage_text(verdict: Verdict) -> str:
    lines = [f"TRIAGE VERDICT: {verdict.verdict.value} (confidence {verdict.confidence:.2f})"]
    if verdict.reasoning:
        lines.append(f"TRIAGE REASONING: {verdict.reasoning}")
    if verdict.exploit_scenario:
        lines.append(f"EXPLOIT SCENARIO: {verdict.exploit_scenario}")
    for note in verdict.policy_notes:  # facts GapScan computed (e.g. which builds ship a secret)
        lines.append(f"GAPSCAN FACT: {note}")
    return neutralize_delimiters("\n".join(lines))


def _group_text(finding: Finding, members: list[Finding]) -> str:
    others = [m for m in members if m.id != finding.id]
    if not others:
        return ""
    lines = ["OTHER SCANNER RESULTS FOR THIS SAME ISSUE (one investigation covers them all):"]
    for m in others[:10]:
        where = f"{m.file}:{m.start_line}" if m.file and m.start_line else (m.file or m.package)
        lines.append(f"- {', '.join(m.sources)} {m.rule_id} at {where}: {m.title[:120]}")
    return neutralize_delimiters("\n".join(lines))


def investigate(
    client: LLMProvider,
    finding: Finding,
    context: CodeContext | None,
    verdict: Verdict,
    toolbox: ToolBox,
    *,
    members: list[Finding] | None = None,
    known: list[Finding] | None = None,
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    cache: ResponseCache | None = None,
    max_tokens: int = 2000,
) -> Investigation:
    """Investigate `finding` (the first member of its root-cause group, see agent/grouping.py);
    `members` are every finding the result will be shown on, including `finding`; `known` are
    all scan findings, used to reject "related" refs that point at a different issue."""
    members = members or [finding]
    version = latest_version(PROMPT_NAME)
    suspected = list(context.injection_lines) if context else []
    seen = seen_from_context(context)
    text = finding_text(finding, context)
    if finding.package and finding.file:  # dependency: show where the package is declared
        decl = manifest_lines(toolbox, finding.file, finding.package)
        if decl.ok and decl.seen:
            text += f"\n\nWHERE {finding.file} DECLARES {finding.package}:\n"
            text += neutralize_delimiters(decl.text)
            for file, lo, hi in decl.seen:
                seen.add(file, lo, hi)
    if group := _group_text(finding, members):
        text += "\n\n" + group
    entry = checklist_for(members)
    prompt = render_prompt(
        version,
        checklist=render_checklist(entry) if entry else "",
        finding_text=text,
        triage_text=_triage_text(verdict),
        warning=warning_for(suspected) if suspected else "",
        max_tool_calls=max_tool_calls,
        tool_lines=list(DEEP_TOOL_DESCRIPTIONS.values()),
    )
    messages: list[dict[str, str]] = [{"role": "user", "content": prompt}]
    records: list[ToolCallRecord] = []
    seen_calls: set[str] = set()
    attempts, tokens, seconds, cached = 0, 0, 0.0, True
    answer: InvestigationAnswer | None = None

    def failed(error: str) -> Investigation:
        return Investigation(
            finding_id=finding.id, group_id=group_id(members), covers=[m.id for m in members],
            failed=True, error=error[:300], prompt_version=version,
            model=client.model, attempts=attempts, tool_calls=records,
            injection_suspected=bool(suspected), tokens=tokens, seconds=round(seconds, 2),
        )  # fmt: skip

    try:
        while answer is None:
            forced = len(records) >= max_tool_calls
            if forced:
                messages.append({"role": "user", "content": (
                    "Tool budget used up. Give your final investigation now as the JSON object "
                    'with "action": "final".')})  # fmt: skip
            res = structured_chat(
                client, messages, DeepStep, max_tokens=max_tokens, cache=cache,
                prompt_version=version,
            )  # fmt: skip
            attempts += res.attempts
            tokens += res.prompt_tokens + res.completion_tokens
            seconds += res.duration_s
            cached = cached and res.cached
            step = res.value
            if step.action == "final" or forced:
                if step.answer is None:
                    raise StructuredOutputError("no final answer after tool budget", attempts, "")
                answer = step.answer
                break
            assert step.tool is not None  # guaranteed by the validator
            call_key = json.dumps([step.tool, step.args], sort_keys=True)
            if call_key in seen_calls:
                text, ok, ref, outcome = (
                    "You already made this exact call; use the earlier result.", False, None, None,
                )  # fmt: skip
            else:
                seen_calls.add(call_key)
                tr = toolbox.execute(step.tool, step.args)
                text, ok, ref, outcome = tr.text, tr.ok, tr.evidence_ref, tr.outcome
                for file, lo, hi in tr.seen:
                    seen.add(file, lo, hi)
                if step.tool == "search_repo" and outcome == "no_matches":
                    key = str(step.args.get("text", "")).strip().lower()
                    # a whole-project search outranks a narrower one for the same text
                    if seen.empty_searches.get(key) != "":
                        seen.empty_searches[key] = tr.scope
            records.append(ToolCallRecord(tool=step.tool, args=dict(step.args), ok=ok,
                                          evidence_ref=ref, outcome=outcome))  # fmt: skip
            suspect = bool(find_injection_lines(list(enumerate(text.splitlines()))))
            suspected = suspected or ([0] if suspect else [])
            messages += [
                {"role": "assistant", "content": step.model_dump_json(exclude_none=True)},
                {"role": "user", "content": _tool_message(step.tool, step.args, ok, text, suspect)},
            ]
    except StructuredOutputError as exc:
        return failed(str(exc))
    except LLMError as exc:
        return failed(str(exc))
    other = other_issue_lines(members, known or [])
    vetted = {s.strip().lower() for c in (entry or {}).get("controls", []) for s in c["signals"]}
    kept, dropped = ground(answer, seen, own_lines(members), other, vetted)
    return Investigation(
        finding_id=finding.id, group_id=group_id(members), covers=[m.id for m in members],
        answer=kept, dropped=dropped, prompt_version=version,
        model=client.model, cached=cached, attempts=attempts, tool_calls=records,
        injection_suspected=bool(suspected), tokens=tokens, seconds=round(seconds, 2),
    )  # fmt: skip
