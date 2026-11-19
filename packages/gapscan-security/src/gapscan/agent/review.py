"""The security pack's model review: triage of the top findings, the deep dive into confirmed
root causes and the repository summary, with the agent's tools, rules and knowledge base.

The engine runs the review flow (`gapscan.services.review_scan`: limits, progress, what happens
when the deep dive fails); this module is the domain's side of it. Apps pass an `AgentSteps` on
the model provider they wired.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..config import Config
from ..context.extract import build_context
from ..core.interfaces import LLMProvider
from ..kb import load_kb
from ..llm.cache import ResponseCache
from ..memory import Memory, render_memory, retrieve
from ..models import Finding, Investigation, RepoSummary, ScanResult, Verdict, VerdictLabel
from ..redact import mask
from .agent import triage_with_tools
from .grouping import group_findings
from .investigate import investigate
from .rules import deterministic_verdict
from .summarize import summarize_repo
from .tools import KnowledgeBase, ToolBox, language_for_finding
from .triage import guard_memory_use, triage_finding, with_references


def triage_top_findings(
    config: Config,
    result: ScanResult,
    target: Path,
    *,
    limit: int,
    client: LLMProvider,
    cache: ResponseCache | None = None,
    kb: KnowledgeBase | None = None,
    on_verdict: Callable[[Verdict], None] | None = None,
    memories: list[Memory] | None = None,
    memory_provider: Callable[[Finding], list[Memory]] | None = None,
) -> list[Verdict]:
    """Triage the highest-priority findings flagged for the LLM, with tools when enabled.

    `memories` are the team's notes; the most relevant ones are shown to the model for each
    finding. `memory_provider` lets a caller choose them per finding (used by the evaluation)."""
    if cache is None:  # not `or`: an empty ResponseCache is falsy (it defines __len__)
        cache = ResponseCache(config.data.dir / "cache" / "llm.sqlite")
    kb = kb or load_kb(config)  # None until `gapscan kb build` has been run
    by_id = {f.id: f for f in result.findings}
    verdicts = []
    for f in [f for f in result.findings if f.llm_triage][:limit]:
        ctx = build_context(f, target.resolve(), budget_tokens=config.llm.code_context_tokens)
        rule_verdict = deterministic_verdict(f, ctx, target)
        if rule_verdict is not None:  # decided by code: no model call, no tokens
            rule_verdict = with_references(rule_verdict, kb, f)
            verdicts.append(rule_verdict)
            if on_verdict:
                on_verdict(rule_verdict)
            continue
        picked = memory_provider(f) if memory_provider else retrieve(memories or [], f)
        ctx.memories = [mask(render_memory(m)) for m in picked]
        ctx.memory_ids = [m.id for m in picked]
        if config.agent.use_tools:
            toolbox = ToolBox(target, ctx.language or language_for_finding(by_id[f.id]), kb)
            v = triage_with_tools(client, by_id[f.id], ctx, toolbox, cache=cache,
                                  max_tool_calls=config.agent.max_tool_calls)  # fmt: skip
        else:
            v = triage_finding(client, by_id[f.id], ctx, cache=cache, kb=kb)
        v = v.model_copy(update={"memories_used": ctx.memory_ids, "memory_notes": ctx.memories})
        v = guard_memory_use(f, v, [m.kind for m in picked])
        verdicts.append(v)
        if on_verdict:
            on_verdict(v)
    return verdicts


DEEP_DIVE_VERDICTS = (VerdictLabel.TRUE_POSITIVE, VerdictLabel.LIKELY_TRUE_POSITIVE)


def deep_dive_groups(
    config: Config, result: ScanResult, verdicts: list[Verdict], limit: int
) -> list[list[Finding]]:
    """Root-cause groups worth a deep dive, highest priority first, at most `limit` groups.

    Members are findings judged real (true or likely true positive, by the model or a
    deterministic rule); a group qualifies when its top member is at or above
    `agent.deep_dive_min_priority`. The first member of each group is the one investigated."""
    real = {v.finding_id for v in verdicts
            if not v.triage_failed and v.verdict in DEEP_DIVE_VERDICTS}  # fmt: skip
    groups = group_findings([f for f in result.findings if f.id in real])
    groups = [g for g in groups if g[0].priority >= config.agent.deep_dive_min_priority]
    groups.sort(key=lambda g: (-g[0].priority, g[0].id))
    return groups[:limit]


def deep_dive_findings(
    config: Config,
    result: ScanResult,
    target: Path,
    verdicts: list[Verdict],
    *,
    limit: int,
    client: LLMProvider,
    cache: ResponseCache | None = None,
    kb: KnowledgeBase | None = None,
    on_investigation: Callable[[Investigation], None] | None = None,
) -> list[Investigation]:
    """Detailed, grounded investigations, one per root-cause group of
    confirmed findings; `Investigation.covers` lists every finding each one applies to."""
    if cache is None:  # not `or`: an empty ResponseCache is falsy (it defines __len__)
        cache = ResponseCache(config.data.dir / "cache" / "llm.sqlite")
    kb = kb or load_kb(config)
    vmap = {v.finding_id: v for v in verdicts}
    out = []
    for members in deep_dive_groups(config, result, verdicts, limit):
        f = members[0]
        ctx = build_context(f, target.resolve(), budget_tokens=config.llm.code_context_tokens)
        toolbox = ToolBox(target, ctx.language or language_for_finding(f), kb)
        inv = investigate(client, f, ctx, vmap[f.id], toolbox, members=members,
                          known=result.findings, cache=cache,
                          max_tool_calls=config.agent.deep_dive_tool_calls)  # fmt: skip
        out.append(inv)
        if on_investigation:
            on_investigation(inv)
    return out


def summarize_scan(
    config: Config,
    result: ScanResult,
    verdicts: list[Verdict],
    *,
    client: LLMProvider,
    cache: ResponseCache | None = None,
) -> RepoSummary:
    """Repo-level summary: Python-computed stats plus a validated model-written narrative."""
    if cache is None:  # not `or`: an empty ResponseCache is falsy (it defines __len__)
        cache = ResponseCache(config.data.dir / "cache" / "llm.sqlite")
    return summarize_repo(client, result, verdicts, cache=cache)


OnVerdict = Callable[[Verdict], None]
OnInvestigation = Callable[[Investigation], None]


class AgentSteps:
    """The review steps (`gapscan.services.ReviewSteps`) on one model provider."""

    def __init__(self, client: LLMProvider) -> None:
        self.client = client

    def triage(
        self,
        cfg: Config,
        result: ScanResult,
        target: Path,
        limit: int,
        on_verdict: OnVerdict,
        memories: list[Memory] | None = None,
    ) -> list[Verdict]:
        return triage_top_findings(cfg, result, target, limit=limit, client=self.client,
                                   on_verdict=on_verdict, memories=memories)  # fmt: skip

    def deep_dive_count(
        self, cfg: Config, result: ScanResult, verdicts: list[Verdict], limit: int
    ) -> int:
        return len(deep_dive_groups(cfg, result, verdicts, limit))

    def deep_dive(
        self,
        cfg: Config,
        result: ScanResult,
        target: Path,
        verdicts: list[Verdict],
        limit: int,
        on_investigation: OnInvestigation,
    ) -> list[Investigation]:
        return deep_dive_findings(cfg, result, target, verdicts, limit=limit, client=self.client,
                                  on_investigation=on_investigation)  # fmt: skip

    def summarize(self, cfg: Config, result: ScanResult, verdicts: list[Verdict]) -> RepoSummary:
        return summarize_scan(cfg, result, verdicts, client=self.client)
