"""Token budget manager: trim a CodeContext until its rendering fits the budget.

Tokens are estimated at ~4 characters each (no tokenizer is available offline); the budget
should leave headroom for the prompt template and the model's answer. The finding's own
lines are never removed.
"""

from __future__ import annotations

from collections.abc import Callable

from ..models import CodeContext

CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    return len(text) // CHARS_PER_TOKEN + 1


def _shrink_code(ctx: CodeContext, radius: int) -> bool:
    """Keep only numbered lines within `radius` of the finding; True if anything was cut."""
    if not ctx.start_line:
        return False
    lo, hi = ctx.start_line - radius, (ctx.end_line or ctx.start_line) + radius
    kept, cut = [], False
    for line in ctx.code.splitlines():
        num = line[2:].split("|", 1)[0].strip()
        if num.isdigit() and not (lo <= int(num) <= hi):
            cut = True
            continue
        kept.append(line)
    if cut:
        ctx.code = "\n".join(kept)
    return cut


def fit_to_budget(ctx: CodeContext, max_tokens: int) -> CodeContext:
    """Trim `ctx` in place, least important material first, and return it."""

    def fits() -> bool:
        return estimate_tokens(ctx.render()) <= max_tokens

    steps: list[tuple[str, Callable[[], bool]]] = [
        ("imports", lambda: _cut(ctx, "imports", 8)),
        ("caller snippets", lambda: _shorten_callers(ctx)),
        ("helpers", lambda: _cut(ctx, "helpers", 2)),
        ("definitions", lambda: _cut(ctx, "definitions", 2)),
        ("imports", lambda: _cut(ctx, "imports", 0)),
        ("callers", lambda: _cut(ctx, "callers", 1)),
        ("function body", lambda: _shrink_code(ctx, 25)),
        ("untrusted sources", lambda: _cut(ctx, "untrusted_sources", 4)),
        ("callers", lambda: _cut(ctx, "callers", 0)),
        ("function body", lambda: _shrink_code(ctx, 12)),
        ("function body", lambda: _shrink_code(ctx, 5)),
        ("definitions", lambda: _cut(ctx, "definitions", 0)),
        ("helpers", lambda: _cut(ctx, "helpers", 1)),
        ("untrusted sources", lambda: _cut(ctx, "untrusted_sources", 0)),
        ("function body", lambda: _shrink_code(ctx, 1)),
        ("data flow", lambda: _cut(ctx, "flow", 3)),
        ("team memories", lambda: _cut(ctx, "memories", 1)),
    ]
    for label, step in steps:
        if fits():
            break
        if step() and label not in ctx.trimmed:
            ctx.trimmed.append(label)
    return ctx


def _cut(ctx: CodeContext, attr: str, keep: int) -> bool:
    items = getattr(ctx, attr)
    if len(items) <= keep:
        return False
    setattr(ctx, attr, items[:keep])
    return True


def _shorten_callers(ctx: CodeContext) -> bool:
    changed = False
    for c in ctx.callers:
        if len(c.snippet) > 80:
            c.snippet = c.snippet[:80] + "..."
            changed = True
    return changed
