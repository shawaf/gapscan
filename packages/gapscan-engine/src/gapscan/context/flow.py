"""Heuristic data-flow chain from a request handler to the flagged line.

For the values used at the flagged call, trace backwards: through assignments inside the function,
through helper calls, and (by name) through callers, hop by hop, until the value is a literal, comes
from a sanitizer, or comes from request input (a route handler's parameters, `req.query`, ...). The
result is shown to the model as a short chain and summarized as a status that Python rules use:

    request    request or other external input reaches the line, no sanitizer seen on the path
    sanitized  some path goes through a validator, escaper or allowlist-like call
    constant   every value traced to a literal
    unknown    not enough visible to say

This is name-based and approximate (no type resolution, no real taint engine), so every line it
produces says so. It only parses text (hard rule #1) and never raises: any failure means "no flow".
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import constfold
from .callgraph import find_callers
from .sources import _RULES as SOURCE_RULES
from .treesitter import (
    FunctionInfo,
    ParsedFile,
    detect_language,
    enclosing_function,
    functions,
    module_definitions,
    parse,
)

log = logging.getLogger(__name__)

MAX_DEPTH = 4  # assignment hops inside one function
MAX_HOPS = 8  # caller hops across functions
MAX_STEPS = 400  # total work per finding
MAX_CALLERS = 3
MAX_PATHS_SHOWN = 4
MAX_STATEMENT_LINES = 6

KEYWORDS = frozenset(  # noqa: SIM905 - one readable block of words
    [
        "if",
        "else",
        "elif",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "default",
        "return",
        "new",
        "this",
        "self",
        "cls",
        "super",
        "null",
        "None",
        "nil",
        "true",
        "false",
        "True",
        "False",
        "const",
        "let",
        "var",
        "val",
        "final",
        "static",
        "public",
        "private",
        "protected",
        "void",
        "int",
        "long",
        "short",
        "byte",
        "char",
        "float",
        "double",
        "bool",
        "boolean",
        "string",
        "String",
        "str",
        "in",
        "is",
        "not",
        "and",
        "or",
        "await",
        "async",
        "function",
        "def",
        "fun",
        "func",
        "class",
        "try",
        "catch",
        "except",
        "finally",
        "throw",
        "throws",
        "with",
        "as",
        "lambda",
        "typeof",
        "instanceof",
        "of",
        "from",
        "import",
        "export",
        "extends",
        "implements",
        "interface",
        "enum",
        "struct",
        "type",
        "readonly",
        "override",
        "abstract",
        "open",
        "internal",
        "suspend",
        "get",
        "set",
        "where",
        "when",
        "guard",
        "defer",
        "Optional",
        "List",
        "Map",
        "Set",
        "Array",
        "Object",
        "Number",
        "Boolean",
        "Promise",
        "Buffer",
    ]
)
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_STRING = re.compile(r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`")
_NUMBER = re.compile(r"\b\d[\d_.]*\b")
_STRING_PREFIX = re.compile(r'(?<![\w$])[fFrRbBuU]{1,2}(?=")')
_INTERPOLATION = [
    re.compile(r"\$\{([^}]*)\}"),  # JS/TS template, Kotlin, Dart
    re.compile(r"\\\(([^)]*)\)"),  # Swift
    re.compile(r"(?<![\w$])\$([A-Za-z_]\w*)"),  # Kotlin / Dart short form
    re.compile(r"(?<=[\w\"'])\{([A-Za-z_][^{}]*)\}"),  # "...{name}..." used with .format()
]
# Python f-strings: every {expression} inside an f"..." / rf'...' literal, wherever it sits
# (f"echo {bar}" was missed when only braces right after a word character were matched).
_FSTRING = re.compile(
    r"""(?<![\w$])(?:[rR]?[fF]|[fF][rR])("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')"""
)
_FSTRING_FIELD = re.compile(r"(?<!\{)\{(?!\{)([^{}]+)\}")
STRONG_SANITIZER = re.compile(
    r"\b(?:escape\w*|sanitiz\w*|quote\w*|encodeURI\w*|parameteri[sz]\w*|validate\w*|isValid\w*|"
    r"is_valid\w*|allowlist\w*|whitelist\w*|safe_join|secure_filename|basename|"
    r"html\.escape|markupsafe|DOMPurify|bleach|shlex\.quote|escapeHtml\w*|urlencode)\s*\(",
    re.IGNORECASE,
)
ROUTE_MARKER = re.compile(
    r"@(?:Get|Post|Put|Patch|Delete|All|Head|Options|Controller|RequestMapping|GetMapping|"
    r"PostMapping|PutMapping|DeleteMapping|PatchMapping|GET|POST|PUT|DELETE|Path|Route)\b|"
    r"@\w+\.(?:route|get|post|put|delete|patch|websocket)\(|"
    r"\b(?:app|router|server|api|routes)\.(?:get|post|put|delete|patch|use|all)\(|"
    r"\b(?:doGet|doPost|doPut|doDelete|doFilter|service)\s*\(|HttpServletRequest|"
    r"\bfun\s+Route\.|\bcall\.receive|\.(?:HandleFunc|Handle)\(|http\.ResponseWriter"
)
PARAM_SOURCE = re.compile(
    r"@(?:Param|Query|Body|Headers?|Req|Request|RequestParam|PathVariable|RequestBody|"
    r"RequestHeader|CookieValue|Ctx|UploadedFiles?|Cookies|Ip|QueryParam|FormParam|PathParam)\b|"
    r"HttpServletRequest|\*http\.Request|\bRequest\b|\bFormData\b"
)
REQUEST_NAMES = {"req", "request", "ctx", "context", "r"}
SKIP_PARAMS = {"self", "cls", "this", "res", "response", "next", "resp", "w", "reply"}


@dataclass
class Origin:
    kind: str  # request | external | constant | sanitized | param | unknown
    detail: str
    trail: tuple[str, ...] = ()  # hops from the sink to this origin, nearest first


@dataclass
class Flow:
    status: str = "unknown"
    lines: list[str] = field(default_factory=list)


@dataclass
class _Param:
    name: str
    decl: str
    index: int  # position among the callable parameters (self/cls/this skipped)


@dataclass
class _Scope:
    pf: ParsedFile
    fn: FunctionInfo
    params: list[_Param]
    handler: bool


class _Budget:
    def __init__(self) -> None:
        self.steps = 0

    def spend(self) -> bool:
        self.steps += 1
        return self.steps <= MAX_STEPS


# --------------------------------------------------------------------------- text helpers


def strip_literals(text: str) -> str:
    stripped = _NUMBER.sub(" ", _STRING.sub('""', text))
    return _STRING_PREFIX.sub("", stripped)  # f"..." and r"..." leave a stray prefix letter


def interpolations(text: str) -> list[str]:
    out: list[str] = []
    for pattern in _INTERPOLATION:
        out += pattern.findall(text)
    for literal in _FSTRING.findall(text):
        for expr in _FSTRING_FIELD.findall(literal):
            out.append(re.split(r"![rsa]|:", expr, maxsplit=1)[0])  # drop !r and :format specs
    return out


def idents(text: str) -> list[str]:
    """Identifiers used as values: not member names (`a.b` gives `a`), not callee names, not keywords."""
    with_interp = " ".join([strip_literals(text), *interpolations(text)])
    out: list[str] = []
    for m in _IDENT.finditer(with_interp):
        name = m.group(0)
        before = with_interp[max(0, m.start() - 1) : m.start()]
        after = with_interp[m.end() : m.end() + 1]
        spread = with_interp[max(0, m.start() - 3) : m.start()] == "..."
        if (
            name in KEYWORDS
            or (before == "." and not spread)
            or after == "("
            or name.isdigit()
            or before == "@"
        ):
            continue
        following = with_interp[m.end() :].lstrip()[:2]
        if following[:1] == ":" or (following[:1] == "=" and following != "=="):
            continue  # object key or keyword argument, not a value
        if name[:1].isupper() and following[:1] == ".":
            continue  # a type or namespace (Paths.get, JSON.parse), not data
        if name not in out:
            out.append(name)
    return out


def _balanced_end(text: str, open_at: int) -> int | None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for i in range(open_at, len(text)):
        c = text[i]
        if c in pairs:
            stack.append(pairs[c])
        elif stack and c == stack[-1]:
            stack.pop()
            if not stack:
                return i
    return None


def split_top(text: str) -> list[str]:
    parts: list[str] = []
    depth, start = 0, 0
    for i, c in enumerate(text):
        if c in "([{<" and not (c == "<" and text[i : i + 2] in ("<=", "<<")):
            depth += 1
        elif c in ")]}>" and not (c == ">" and text[max(0, i - 1) : i + 1] in ("=>", "->")):
            depth = max(0, depth - 1)
        elif c == "," and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def call_args(text: str, callee: str) -> list[str] | None:
    """Argument expressions of the first `callee(...)` call in `text` (None when not found)."""
    m = re.search(rf"(?<![\w$]){re.escape(callee)}\s*\(", text)
    if not m:
        return None
    open_at = m.end() - 1
    close = _balanced_end(text, open_at)
    if close is None:
        return split_top(text[open_at + 1 :])
    return split_top(text[open_at + 1 : close])


def statement_at(lines: list[str], line: int) -> str:
    """The statement that starts at `line` (1-based), joined across lines until brackets balance."""
    text = ""
    for n in range(line, min(line + MAX_STATEMENT_LINES, len(lines) + 1)):
        text += (" " if text else "") + lines[n - 1].strip()
        depth = sum(text.count(c) for c in "([{") - sum(text.count(c) for c in ")]}")
        if depth <= 0 and not text.rstrip().endswith(("+", ",", "(", "&&", "||", "?", ":", "=")):
            break
    return text


def sink_values(lines: list[str], start: int, end: int) -> list[str]:
    """Identifiers used as arguments in the flagged statement (receivers and callees excluded)."""
    text = " ".join(lines[start - 1 : end]).strip()
    if end - start < 2:
        text = statement_at(lines, start)
    found: list[str] = []
    # content of every parenthesis group in the statement
    depth_starts: list[int] = []
    groups: list[str] = []
    for i, c in enumerate(text):
        if c == "(":
            depth_starts.append(i)
        elif c == ")" and depth_starts:
            s = depth_starts.pop()
            if not depth_starts:  # outermost groups only; nested ones are inside them
                groups.append(text[s + 1 : i])
    for g in groups or [text]:
        for name in idents(g):
            if name not in found:
                found.append(name)
    return found[:8]


# --------------------------------------------------------------------------- scopes


def _params(pf: ParsedFile, fn: FunctionInfo) -> list[_Param]:
    sig = fn.signature
    start = None
    m = (
        re.search(rf"(?<![\w$.@]){re.escape(fn.name)}\s*(?:<[^>(]*>)?\s*\(", sig)
        if fn.name
        else None
    )
    if m:
        start = m.end() - 1
    else:  # anonymous / arrow functions: the first parenthesis that is not a decorator call
        for mm in re.finditer(r"\(", sig):
            if not re.search(r"@[\w.]+\s*$", sig[: mm.start()]):
                start = mm.start()
                break
    if start is None:
        return []
    end = _balanced_end(sig, start)
    inner = sig[start + 1 : end] if end is not None else sig[start + 1 :]
    out: list[_Param] = []
    index = 0
    for decl in split_top(inner):
        decl_clean = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", decl).strip()
        decl_clean = re.sub(
            r"^(?:final|const|var|val|let|readonly|public|private|protected)\s+", "", decl_clean
        )
        decl_clean = decl_clean.lstrip("*&.")  # python *args, go pointers/variadics
        name = _param_name(decl_clean, pf.language)
        if not name or name in SKIP_PARAMS:
            continue
        out.append(_Param(name, decl, index))
        index += 1
    return out


def _param_name(decl: str, language: str) -> str | None:  # noqa: PLR0911
    head = decl.split("=")[0].strip()
    if ":" in head and language in (
        "python",
        "typescript",
        "tsx",
        "javascript",
        "kotlin",
        "swift",
        "dart",
    ):
        left = head.split(":")[0].strip()
        words = _IDENT.findall(left)
        return str(words[-1]) if words else None
    words = _IDENT.findall(head)
    if not words:
        return None
    return str(words[0] if language == "go" else words[-1])


def _is_handler(pf: ParsedFile, fn: FunctionInfo) -> bool:
    first_line = pf.lines[fn.start_line - 1] if 0 < fn.start_line <= len(pf.lines) else ""
    return bool(ROUTE_MARKER.search(fn.signature) or ROUTE_MARKER.search(first_line))


def _scope(pf: ParsedFile, fn: FunctionInfo) -> _Scope:
    return _Scope(pf, fn, _params(pf, fn), _is_handler(pf, fn))


# --------------------------------------------------------------------------- tracing


def _source_kind(text: str) -> tuple[str, str] | None:
    for kind, pattern in SOURCE_RULES:
        if pattern.search(text):
            return ("request" if kind == "http_param" else "external", kind)
    return None


# Loop variables count as assigned from the iterated value (each element comes from it).
_LOOPS = (
    # JS/TS, Java, Kotlin, Dart, C#: `for (const x of expr) {`, `for (Type x : expr)`, `for (x in expr)`
    re.compile(r"\bfor(?:each)?\s*\(\s*(?:(?:const|let|var|final|val|auto)\s+|[\w$<>\[\].?]+\s+)?"
               r"(?P<vars>[\w$]+)\s+(?:of|in|:)\s+(?P<expr>.+?)\)\s*\{?\s*$"),
    # Python and Swift: `for a, b in expr:` / `for x in expr {`
    re.compile(r"^\s*(?:async\s+)?for\s+\(?(?P<vars>[\w$]+(?:\s*,\s*[\w$]+)*)\)?\s+in\s+"
               r"(?P<expr>.+?)\s*[:{]\s*(?:#.*)?$"),
)  # fmt: skip
# Web frameworks whose module-level `request` object is the incoming request.
_FRAMEWORK_REQUEST = re.compile(
    r"^\s*from\s+(?:flask|quart|werkzeug(?:\.\w+)*|sanic|bottle)\s+import\s+[^#\n]*\brequest\b",
    re.MULTILINE,
)


def _assignments(scope: _Scope, name: str, before: int) -> list[tuple[int, str]]:
    """Assignments to `name` inside the function above `before`, nearest last."""
    pf, fn = scope.pf, scope.fn
    pattern_simple = re.compile(
        rf"(?<![\w.$]){re.escape(name)}\s*(?:[-+*/|&^%]|\?\?|\|\||&&|<<|>>)?(?::=|=)(?![=>])"
    )
    pattern_tuple = re.compile(
        rf"(?<![\w.$]){re.escape(name)}\s*(?:,\s*[\w$]+\s*)+(?::=|=)(?![=>])"
    )
    pattern_destructure = re.compile(
        rf"[\[{{(][^=;]*(?<![\w.$]){re.escape(name)}(?![\w$])[^=;]*[\]}})]\s*(?::=|=)(?![=>])"
    )
    found: list[tuple[int, str]] = []
    lo = max(fn.body_start_line, 1)
    for n in range(lo, min(before, len(pf.lines) + 1)):
        raw = pf.lines[n - 1]
        loop = next((m for pat in _LOOPS if (m := pat.search(raw))), None)
        if loop and name in re.findall(r"[\w$]+", loop.group("vars")):
            found.append((n, loop.group("expr").strip()))  # each element comes from the iterable
            continue
        if (
            pattern_destructure.search(raw)
            or pattern_tuple.search(raw)
            or pattern_simple.search(raw)
        ):
            stmt = statement_at(pf.lines, n)
            eq = re.search(r"(?<![=!<>])(?::=|=)(?![=>])", stmt)
            if eq:
                found.append((n, stmt[eq.end() :].strip().rstrip(";")))
    return found[-4:]


_CAST = re.compile(r"^\(\s*[\w.<>\[\]]+\s*\)\s*")  # `(String) map.get("k")`
# Same-file helpers: `helper(...)`, and methods called on `this`/`self` or on a freshly built object
# of a class in the file (`new Test().doSomething(...)`, the benchmarks' inner-class helpers).
_HELPER_CALL = re.compile(
    r"(?:(?<![\w$.])|(?<=\bthis\.)|(?<=\bself\.)|(?<=\)\.))([A-Za-z_$][\w$]*)\s*\("
)


def _literal_value(scope: _Scope, name: str, line: int) -> constfold.Value | None:
    """The value of a local that is assigned exactly once, to a numeric or boolean literal."""
    assigned = _assignments(scope, name, line)
    if len(assigned) != 1 or _mutations(scope, name, line):
        return None
    return constfold.literal_number(assigned[0][1])


def _dead(scope: _Scope, n: int) -> bool:
    """Line `n` sits in an if/else branch whose condition is known and never takes it."""
    branch = constfold.branch_of(scope.pf.lines, n, max(scope.fn.body_start_line, 1))
    if branch is None:
        return False
    cond, when = branch
    value = constfold.eval_condition(cond, scope.pf.language, lambda k: _literal_value(scope, k, n))
    return value is not None and value != when


_AUGMENTED = re.compile(r"(?<![=!<>])(?:[-+*/|&^%]|<<|>>|\?\?|\|\||&&|\*\*|//)=(?!=)")


def _live_assignments(
    scope: _Scope, assigned: list[tuple[int, str]], line: int
) -> list[tuple[int, str]]:
    """Assignments that can still hold the value at `line`: not in a branch that never runs, and
    not overwritten by a later assignment at the function's top level (which always runs)."""
    live = [(n, rhs) for n, rhs in assigned if not _dead(scope, n)]
    if not live:
        return assigned  # every candidate looked dead: do not trust that, keep them all
    lines = scope.pf.lines
    body = [ln for ln in lines[max(scope.fn.body_start_line, 1) : line - 1] if ln.strip()]
    top = min((len(ln) - len(ln.lstrip(" \t")) for ln in body), default=0)
    out: list[tuple[int, str]] = []
    for n, rhs in live:
        text = lines[n - 1]
        unconditional = len(text) - len(text.lstrip(" \t")) == top and not text.strip().startswith(
            ("if", "else", "}", "elif", "for", "while", "case")
        )
        # `x += y` (and |=, ??=, ...) adds to the old value: only a plain `=` replaces it.
        replaces = unconditional and not _AUGMENTED.search(text)
        out = [(n, rhs)] if replaces else [*out, (n, rhs)]
    return out


def _container_element(
    scope: _Scope, name: str, key: str | int, line: int
) -> tuple[str, int] | None:
    created = _assignments(scope, name, line)
    if not created:
        return None
    at, rhs = created[-1]
    return constfold.element(scope.pf.lines, name, at, rhs, line, key, scope.pf.language)


def _helper_returns_constant(pf: ParsedFile, name: str) -> bool:
    """True when a same-file function `name` only ever returns literals (memoized per file; a
    helper whose answer depends on itself counts as not constant)."""
    key = ("returns_constant", name)
    if key not in pf._cache:
        pf._cache[key] = False  # in progress: a recursive helper is not provably constant
        pf._cache[key] = _returns_constant(pf, name)
    return bool(pf._cache[key])


def _returns_constant(pf: ParsedFile, name: str) -> bool:
    for f in functions(pf):
        if f.name != name:
            continue
        returns = []
        for n in range(f.body_start_line, f.end_line + 1):
            m = re.match(r"\s*return\b(.*)$", pf.lines[n - 1])
            if m:
                returns.append(m.group(1).strip().rstrip(";"))
        if not returns:
            return False
        scope = _scope(pf, f)
        for expr in returns:
            if not expr:
                continue
            origins = _expr(scope, expr, f.end_line + 1, MAX_DEPTH - 2, 0, _Budget(), None)
            if not origins or any(o.kind != "constant" for o in origins):
                return False
        return True
    return False


def _expr(
    scope: _Scope, text: str, line: int, depth: int, hops: int, budget: _Budget, target: Path | None
) -> list[Origin]:
    src = _source_kind(text)
    if not budget.spend() or depth < 0:
        # Recognizing request input needs no further tracing, so it is reported even at the
        # limit (the path to it was already followed); only the deeper search stops here.
        if src:
            return [Origin(src[0], f"{src[1].replace('_', ' ')}: `{text.strip()[:80]}`")]
        return [Origin("unknown", "analysis limit reached")]
    out: list[Origin] = []
    if src:
        out.append(Origin(src[0], f"{src[1].replace('_', ' ')}: `{text.strip()[:80]}`"))
    sanitizer = STRONG_SANITIZER.search(text)
    if sanitizer:
        out.append(Origin("sanitized", f"`{sanitizer.group(0).rstrip('( ')}`"))
    lang = scope.pf.language
    # A conditional expression whose condition is known: only the branch that runs carries data.
    tern = constfold.split_ternary(text, lang)
    if tern is not None:
        taken = constfold.eval_condition(tern[0], lang, lambda n: _literal_value(scope, n, line))
        if taken is not None:
            chosen = tern[1] if taken else tern[2]
            note = f"`{tern[0].strip()[:50]}` is always {'true' if taken else 'false'}"
            return [Origin(o.kind, o.detail, (note, *o.trail))
                    for o in _expr(scope, chosen, line, depth, hops, budget, target)]  # fmt: skip
    # A literal-index read of a list or map built in straight-line code: follow that element only.
    read = constfold.read_of(_CAST.sub("", text.strip(), count=1))
    if read is not None:
        stored = _container_element(scope, read[0], read[1], line)
        if stored is not None:
            value, at = stored
            note = f"`{read[0]}[{read[1]!r}]` holds `{value[:50]}` (line {at})"
            return [Origin(o.kind, o.detail, (note, *o.trail))
                    for o in _expr(scope, value, at, depth - 1, hops, budget, target)]  # fmt: skip
    # calls to same-file helpers that only return literals contribute a constant, not their args
    remainder = text
    for call in _HELPER_CALL.finditer(text):
        if _helper_returns_constant(scope.pf, call.group(1)):
            close = _balanced_end(text, call.end() - 1)
            if close is not None:
                out.append(Origin("constant", f"`{call.group(1)}(...)` always returns a literal"))
                remainder = remainder.replace(text[call.start() : close + 1], '""')
    names = idents(remainder)
    if not names:
        if not out and not strip_literals(remainder).replace('""', "").strip(
            " +-*/%()[]{}<>,.;:?!&|=~"
        ):
            out.append(Origin("constant", "a literal"))
        elif not out:
            out.append(Origin("unknown", f"`{text.strip()[:60]}`"))
        return out
    for ident in names[:6]:
        out += _ident(scope, ident, line, depth, hops, budget, target)
    return out


_MUTATORS = (
    "append", "extend", "insert", "add", "addAll", "update", "setdefault", "push", "unshift",
    "put", "putAll", "concat", "set",
)  # fmt: skip


def _mutations(scope: _Scope, name: str, before: int) -> list[tuple[int, str]]:
    """Values put INTO the container `name` after it was created, above `before`:
    `name.append(x)`, `name.put(k, x)`, `name[k] = x` and similar. A list or map that starts as a
    literal (`args = []`) and is filled later is not a constant (found on BenchmarkPython, where
    `argList = []` followed by `argList.append(f"echo {bar}")` was wrongly traced to a literal)."""
    pf, fn = scope.pf, scope.fn
    method = re.compile(rf"(?<![\w.$]){re.escape(name)}\s*\.\s*({'|'.join(_MUTATORS)})\s*\(")
    item = re.compile(rf"(?<![\w.$]){re.escape(name)}\s*\[[^\]]*\]\s*=(?!=)")
    found: list[tuple[int, str]] = []
    for n in range(max(fn.body_start_line, 1), min(before, len(pf.lines) + 1)):
        stmt = statement_at(pf.lines, n)
        if (m := method.search(stmt)) is not None:
            args = call_args(stmt[m.start() :], m.group(1))
            if args:
                found.append((n, ", ".join(args)))
        elif (m := item.search(stmt)) is not None:
            found.append((n, stmt[m.end() :].strip().rstrip(";")))
    return found[-6:]


def _ident(
    scope: _Scope, name: str, line: int, depth: int, hops: int, budget: _Budget, target: Path | None
) -> list[Origin]:
    param = next((p for p in scope.params if p.name == name), None)
    assigned = _live_assignments(scope, _assignments(scope, name, line), line)
    if param and not assigned:
        return _param(scope, param, hops, budget, target)
    if assigned:
        out: list[Origin] = []
        for n, rhs in assigned:
            for o in _expr(scope, rhs, n, depth - 1, hops, budget, target):
                out.append(
                    Origin(o.kind, o.detail, (f"`{name}` = `{rhs[:60]}` (line {n})", *o.trail))
                )
        first = assigned[0][0]
        for n, value in _mutations(scope, name, line):
            if n <= first:
                continue  # filled before its latest creation: overwritten
            for o in _expr(scope, value, n, depth - 1, hops, budget, target):
                out.append(
                    Origin(o.kind, o.detail, (f"`{name}` gets `{value[:60]}` (line {n})", *o.trail))
                )
        return out
    outer = _outer_function(scope)
    if outer is not None:  # a closure: the value comes from the enclosing function
        return _ident(
            _scope(scope.pf, outer), name, scope.fn.start_line, depth, hops, budget, target
        )
    defs = module_definitions(scope.pf)
    if name in defs:
        lo, hi = defs[name]
        stmt = statement_at(scope.pf.lines, lo)
        eq = re.search(r"(?<![=!<>])(?::=|=)(?![=>])", stmt)
        if eq:
            return [
                Origin(
                    o.kind, o.detail, (f"`{name}` defined at module level (line {lo})", *o.trail)
                )
                for o in _expr(
                    scope, stmt[eq.end() :].strip().rstrip(";"), lo, depth - 1, hops, budget, target
                )
            ]
    if name == "request" and _FRAMEWORK_REQUEST.search("\n".join(scope.pf.lines)):
        return [Origin("request", "`request`: the web framework's incoming request object")]
    return [Origin("unknown", f"`{name}` is defined outside the function and was not traced")]


def _outer_function(scope: _Scope) -> FunctionInfo | None:
    """The innermost function that strictly contains this one (callbacks and closures)."""
    fn = scope.fn
    best: FunctionInfo | None = None
    for f in functions(scope.pf):
        contains = f.start_line <= fn.start_line and f.end_line >= fn.end_line
        different = (f.start_line, f.end_line) != (fn.start_line, fn.end_line)
        smaller = best is None or (f.end_line - f.start_line) < (best.end_line - best.start_line)
        if contains and different and smaller:
            best = f
    return best


def _param(
    scope: _Scope, param: _Param, hops: int, budget: _Budget, target: Path | None
) -> list[Origin]:
    here = f"`{param.name}` is parameter {param.index + 1} of `{scope.fn.qualified_name}`"
    if PARAM_SOURCE.search(param.decl) or (scope.handler and param.name in REQUEST_NAMES):
        return [Origin("request", f"request input: {param.decl.strip()[:80]}", (here,))]
    if scope.handler:  # route variables (Flask `def user(id)`), handler arguments
        return [
            Origin("request", f"parameter of route handler `{scope.fn.qualified_name}`", (here,))
        ]
    if target is None or hops >= MAX_HOPS or not scope.fn.name or scope.fn.name.startswith("<"):
        return [Origin("unknown", "not followed further", (here,))]
    language = scope.pf.language
    callers = find_callers(target, scope.fn.name, language, scope.pf.path, MAX_CALLERS,
                           exclude_lines=(scope.fn.start_line, scope.fn.end_line))  # fmt: skip
    if not callers:
        return [Origin("unknown", "no callers found (entry point or dynamic call)", (here,))]
    out: list[Origin] = []
    for c in callers:
        if not budget.spend():
            break
        path = (target / c.file).resolve()
        if not path.is_relative_to(target.resolve()) or not path.is_file():
            continue
        cpf = parse(c.file, path.read_bytes(), detect_language(c.file))
        if cpf is None:
            continue
        cfn = enclosing_function(cpf, c.line)
        if cfn is None:
            out.append(Origin("unknown", f"called at module level ({c.file}:{c.line})", (here,)))
            continue
        stmt = statement_at(cpf.lines, c.line)
        args = call_args(stmt, scope.fn.name)
        if args is None:
            continue
        arg = _argument(args, param)
        if arg is None:
            continue
        hop = f"called by `{cfn.qualified_name}` ({c.file}:{c.line})"
        for o in _expr(_scope(cpf, cfn), arg, c.line, MAX_DEPTH - 1, hops + 1, budget, target):
            out.append(Origin(o.kind, o.detail, (here, hop, *o.trail)))
    return out or [Origin("unknown", "callers pass it in a way that was not traced", (here,))]


def _argument(args: list[str], param: _Param) -> str | None:
    for a in args:  # keyword argument
        m = re.match(rf"\s*{re.escape(param.name)}\s*[=:]\s*(.+)$", a)
        if m:
            return m.group(1)
    positional = [a for a in args if not re.match(r"\s*[A-Za-z_]\w*\s*=(?!=)", a)]
    return positional[param.index] if param.index < len(positional) else None


# --------------------------------------------------------------------------- public


def _summarize(origins: list[Origin]) -> str:
    kinds = {o.kind for o in origins}
    if "sanitized" in kinds:
        return "sanitized"
    if kinds & {"request", "external"}:
        return "request"
    if kinds == {"constant"}:
        return "constant"
    return "unknown"


def _render(origins: list[Origin], status: str) -> list[str]:
    labels = {"request": "REQUEST INPUT", "external": "EXTERNAL INPUT", "sanitized": "SANITIZER",
              "constant": "CONSTANT"}  # fmt: skip
    order = {"request": 0, "external": 0, "sanitized": 1, "constant": 2}
    best: dict[tuple[str, str], Origin] = {}
    for o in origins:  # one line per distinct end point, keeping the shortest way there
        key = (o.kind, o.detail)
        if key not in best or len(o.trail) < len(best[key].trail):
            best[key] = o
    lines: list[str] = []
    for o in sorted(best.values(), key=lambda x: (order.get(x.kind, 3), len(x.trail))):
        end = f"{labels.get(o.kind, 'UNTRACED')}: {o.detail}"
        trail = list(o.trail)
        if len(trail) > 5:  # keep where it starts and the last hops before the end point
            trail = [trail[0], f"... {len(trail) - 4} more steps ...", *trail[-3:]]
        lines.append(" <- ".join([*trail, end])[:600])
        if len(lines) >= MAX_PATHS_SHOWN:
            break
    verdict = {
        "request": "RESULT: request or external input reaches the flagged line and no sanitizer, "
        "validator or allowlist was seen on that path.",
        "sanitized": "RESULT: a path to the flagged line goes through a sanitizing or validating "
        "call; check that it really neutralizes the input.",
        "constant": "RESULT: every value used at the flagged line traces to a literal.",
        "unknown": "RESULT: could not trace where the value comes from.",
    }[status]
    return [*lines, verdict]


def trace_flow(pf: ParsedFile, fn: FunctionInfo, start: int, end: int, target: Path) -> Flow | None:
    """The flow chain for the flagged statement, or None when nothing could be traced."""
    try:
        scope = _scope(pf, fn)
        values = sink_values(pf.lines, start, end)
        if not values:
            return None
        budget = _Budget()
        origins: list[Origin] = []
        direct = _source_kind(" ".join(pf.lines[start - 1 : end]))
        if direct:  # the flagged statement reads request input itself
            origins.append(
                Origin(direct[0], f"{direct[1].replace('_', ' ')} read on the flagged line")
            )
        for name in values:
            origins += _ident(scope, name, start, MAX_DEPTH, 0, budget, target)
        if not origins:
            return None
        status = _summarize(origins)
        return Flow(status=status, lines=_render(origins, status))
    except Exception:  # noqa: BLE001 - tracing is advice; it must never break a scan
        log.debug("flow tracing failed", exc_info=True)
        return None
