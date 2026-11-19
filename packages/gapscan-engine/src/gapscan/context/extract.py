"""Build the CodeContext for a finding: enclosing function, signature, imports, surrounding
lines, untrusted-source hints and a few callers, trimmed to the token budget.

Reads files only inside the target directory (hard rule #3) and never executes anything.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..models import Category, CodeContext, Finding
from ..redact import SNIPPET_PLACEHOLDER, mask
from ..registry import registry
from .budget import fit_to_budget
from .callgraph import find_callers
from .flow import trace_flow
from .injection import find_injection_lines
from .sources import find_untrusted_sources
from .treesitter import (
    calls,
    detect_language,
    enclosing_function,
    functions,
    imports,
    module_definitions,
    parse,
)
from .variants import context_lines as variant_context

log = logging.getLogger(__name__)

MAX_FILE_BYTES = 2_000_000
MAX_FUNCTION_LINES = 80  # larger functions are shown as signature + window


def _numbered(
    lines: list[str], lo: int, hi: int, mark: tuple[int, int] | None, withhold: bool = False
) -> str:
    """Numbered source lines. Secrets never reach the model (hard rule #4): token-shaped
    strings are masked everywhere, and the flagged lines of a secret finding are withheld."""
    out = []
    for n in range(max(lo, 1), min(hi, len(lines)) + 1):
        marked = bool(mark and mark[0] <= n <= mark[1])
        text = SNIPPET_PLACEHOLDER if (withhold and marked) else mask(lines[n - 1])
        out.append(f"{'>>' if marked else '  '}{n:>5} | {text}")
    return "\n".join(out)


def _safe_path(target: Path, rel: str) -> Path | None:
    """Resolve `rel` under `target`; refuse anything that escapes it (symlinks, ..)."""
    root = target.resolve()
    p = (root / rel).resolve()
    return p if p.is_relative_to(root) and p.is_file() else None


MAX_DEFINITIONS = 5
MAX_DEFINITION_LINES = 6


def _used_definitions(
    pf: object, lines: list[str], start: int, end: int, body_start: int
) -> list[str]:
    """Module-level definitions the function mentions (allowlists, validators, base paths), as
    numbered, secret-masked source lines."""
    defs = module_definitions(pf)  # type: ignore[arg-type]
    body = "\n".join(lines[body_start - 1 : end])  # not the decorators or the signature
    body = re.sub(r"\"[^\"\n]*\"|'[^'\n]*'", '""', body)  # a name inside a string is not a use
    out: list[str] = []
    for name, (lo, hi) in sorted(defs.items(), key=lambda kv: kv[1][0]):
        if lo >= start and hi <= end:
            continue  # defined inside the function itself: already visible
        if re.search(rf"(?<![\w.$]){re.escape(name)}(?![\w$])", body):
            hi = min(hi, lo + MAX_DEFINITION_LINES - 1)
            out.append(_numbered(lines, lo, hi, None).replace("\n", "\n"))
        if len(out) >= MAX_DEFINITIONS:
            break
    return out


MAX_HELPERS = 3
MAX_HELPER_LINES = 25


def _called_helpers(pf: object, lines: list[str], fn_lo: int, fn_hi: int) -> list[str]:
    """Bodies of functions defined in this file that the flagged function calls. What a helper such
    as `doSomething(param)` returns (often a constant, sometimes the tainted value itself) decides
    whether the finding is real, and it usually sits right below the function in the same file."""
    names = {c.name for c in calls(pf) if fn_lo <= c.line <= fn_hi}  # type: ignore[arg-type]
    out: list[str] = []
    for f in functions(pf):  # type: ignore[arg-type]
        if f.name in names and not (f.start_line >= fn_lo and f.end_line <= fn_hi):
            hi = min(f.end_line, f.start_line + MAX_HELPER_LINES - 1)
            out.append(_numbered(lines, f.start_line, hi, None))
        if len(out) >= MAX_HELPERS:
            break
    return out


def build_context(
    finding: Finding,
    target: Path,
    *,
    window: int = 8,
    max_callers: int = 3,
    budget_tokens: int = 4000,
) -> CodeContext:
    ctx = CodeContext(finding_id=finding.id, file=finding.file or "", start_line=finding.start_line,
                      end_line=finding.end_line or finding.start_line)  # fmt: skip
    if not finding.file or not finding.start_line:
        ctx.note = "finding has no file location (e.g. a dependency); no code context"
        return ctx
    path = _safe_path(target, finding.file)
    if path is None or path.stat().st_size > MAX_FILE_BYTES:
        ctx.note = "file not readable inside the target"
        return ctx
    source = path.read_bytes()
    ctx.language = detect_language(finding.file)
    lines = source.decode("utf-8", "replace").splitlines()
    span = (finding.start_line, finding.end_line or finding.start_line)
    pf = parse(finding.file, source, ctx.language)
    fn = enclosing_function(pf, finding.start_line) if pf else None

    if fn and (fn.end_line - fn.start_line + 1) <= MAX_FUNCTION_LINES:
        lo, hi = fn.start_line, fn.end_line
    else:
        lo, hi = span[0] - window, span[1] + window
    if fn:
        ctx.function_name, ctx.function_signature = fn.qualified_name, fn.signature
        ctx.function_lines = (fn.start_line, fn.end_line)
        if hi - lo + 1 < fn.end_line - fn.start_line + 1:
            ctx.code = _numbered(lines, fn.start_line, fn.body_start_line, None) + "\n    ...\n"
    secret = finding.category == Category.SECRET
    ctx.code += _numbered(lines, lo, hi, span, secret)
    if pf:
        ctx.imports = [mask(i) for i in imports(pf)[:40]]
    scan_lo, scan_hi = (fn.start_line, fn.end_line) if fn else (lo, hi)
    ctx.untrusted_sources = find_untrusted_sources(
        [(n, mask(lines[n - 1])) for n in range(max(scan_lo, 1), min(scan_hi, len(lines)) + 1)]
    )
    ctx.injection_lines = find_injection_lines(
        [(n, lines[n - 1]) for n in range(max(lo, 1), min(hi, len(lines)) + 1)]
    )
    if pf and fn:
        ctx.helpers = _called_helpers(pf, lines, fn.start_line, fn.end_line)
        ctx.definitions = _used_definitions(
            pf, lines, fn.start_line, fn.end_line, fn.body_start_line
        )
    if fn and ctx.language:
        ctx.callers = find_callers(target, fn.name, ctx.language, finding.file, max_callers,
                                   exclude_lines=(fn.start_line, fn.end_line))  # fmt: skip
    for c in ctx.callers:
        c.snippet = mask(c.snippet)
    if pf and fn and registry().wants_flow(finding):
        flow = trace_flow(pf, fn, span[0], span[1], target.resolve())
        if flow:
            ctx.flow = [mask(line) for line in flow.lines]
            ctx.flow_status = flow.status
    # Which Android builds ship this file, and the build settings the shown code checks.
    shown = "\n".join([ctx.code, *ctx.helpers, *ctx.definitions])
    ctx.variants = [mask(v) for v in variant_context(target, finding.file, shown)]
    return fit_to_budget(ctx, budget_tokens)
