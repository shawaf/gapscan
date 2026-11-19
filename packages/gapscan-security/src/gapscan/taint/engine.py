"""Inter-procedural taint analysis over tree-sitter syntax trees.

Every function gets a *summary*: which parameters flow to its return value, which flow to a sink
(and which sink), and whether it returns data that comes straight from an untrusted source.
Summaries are computed to a fixed point over the whole project, so a value read in one file,
passed through helpers in other files and written to a sink in a third file is reported with the
full path. Within a function the analysis is flow-ordered: an assignment at the top level of the
function replaces the old taint, an assignment inside a branch or loop only adds to it.

Limits (all deliberate, all documented in docs/taint.md): name-based call resolution (no types),
no aliasing, no flow through fields of other objects except this/self fields, no reflection.

Hard rule #1: this only parses text. Nothing from the scanned project is run, built or imported.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tree_sitter import Node

from ..context.callgraph import SKIP_DIRS as SKIP_DIRS_FOR_TAINT
from ..context.treesitter import ParsedFile, detect_language, parse
from .constfold import UNKNOWN, fold, truth
from .specs import Model, Sanitizer, Sink, build_model, project_frameworks

log = logging.getLogger(__name__)

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
MAX_PASSES = 6
MAX_PATH = 8
MAX_CANDIDATES = 4
MAX_STEPS_PER_FUNCTION = 200_000  # expression evaluations; past this a function is skipped


class BudgetExceeded(Exception):
    """One function needed too much work: skip it rather than stall the scan."""


FUNC_TYPES = frozenset({
    "method_declaration", "constructor_declaration", "function_definition", "function_declaration",
    "method_definition", "arrow_function", "function_expression", "generator_function_declaration",
    "lambda_expression", "lambda",
})  # fmt: skip
CALL_TYPES = frozenset({
    "method_invocation", "call", "call_expression", "object_creation_expression", "new_expression",
})  # fmt: skip
ASSIGN_TYPES = frozenset({
    "assignment", "augmented_assignment", "assignment_expression", "augmented_assignment_expression",
})  # fmt: skip
MEMBER_TYPES = frozenset({"field_access", "attribute", "member_expression"})
LITERAL_TYPES = frozenset({
    "string_literal", "character_literal", "decimal_integer_literal", "hex_integer_literal",
    "decimal_floating_point_literal", "true", "false", "null_literal", "integer", "float", "none",
    "number", "null", "undefined", "regex", "comment", "line_comment", "block_comment", "boolean",
    "text_block",
})  # fmt: skip
BRANCH_TYPES = frozenset({
    "if_statement", "for_statement", "while_statement", "enhanced_for_statement", "do_statement",
    "switch_statement", "switch_expression", "for_in_statement", "catch_clause", "except_clause",
    "else_clause", "elif_clause", "switch_block", "match_statement", "case_clause", "switch_case",
})  # fmt: skip
CONTAINER_TYPES = frozenset({
    "block", "statement_block", "expression_statement", "else_clause", "elif_clause",
    "catch_clause", "finally_clause", "switch_block", "switch_block_statement_group", "try_statement",
    "try_with_resources_statement", "resource_specification", "resource", "with_statement",
    "switch_rule", "case_clause", "switch_case", "with_clause", "class_body", "labeled_statement",
})  # fmt: skip
CLASS_TYPES = frozenset({
    "class_declaration", "class_definition", "class", "interface_declaration", "enum_declaration",
    "record_declaration",
})  # fmt: skip
ADD_METHODS = frozenset({
    "add", "put", "append", "push", "addAll", "putAll", "offer", "addFirst", "addLast", "set",
    "insert", "extend", "update", "setdefault", "appendChild", "write", "concat_into", "unshift",
    "putIfAbsent", "setProperty", "setAttribute_local",
})  # fmt: skip
OPERATOR_SOURCES = frozenset({"env", "cli_arg"})
SANITIZE_NAME = re.compile(r"(?i)sanitiz|escap|purif|neutraliz|allowlist|whitelist|validat")
THIS_NAMES = frozenset({"this", "self", "cls"})
GUARD = re.compile(
    r"\.(startswith|startsWith|endswith|endsWith|isalnum|isdigit|isnumeric|isalpha|matches|fullmatch"
    r"|contains|containsKey|includes|has)\(|\b(not\s+)?in\s+[A-Za-z_][\w.]*|\bre\.(match|fullmatch)\("
    r"|(allow|whitelist|valid|safe|trusted)\w*\(|\bnot in\b|\bPattern\.matches\(",
    re.IGNORECASE,
)
EXIT_CALL = re.compile(r"^\s*(abort|sys\.exit|exit|die|\w+\.(sendError|sendStatus|status))\b")
PARSE_CALL = re.compile(
    r"^\s*[\w.]*(urlparse|urlsplit|URL|URI|Path|realpath|normpath|abspath|resolve|parse)\("
)
QUOTED_LITERAL = re.compile(r"'(?:\\.|[^'\\])*'" + r'|"(?:\\.|[^"\\])*"')
BLOCKLIST_TEST = re.compile(r"\b(in|contains|includes|indexOf|find|startswith|startsWith)\b")
SAFE_FILTER = re.compile(r"\{\{\s*([A-Za-z_]\w*)[^}]*?\|\s*safe\b")
AUTOESCAPE_OFF = re.compile(
    r"\{%\s*autoescape\s+(?:off|false)\s*%\}(.*?)\{%\s*endautoescape\s*%\}", re.S
)
TEMPLATE_VAR = re.compile(r"\{\{\s*([A-Za-z_]\w*)")
CONSTANT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
NUMERIC_PARAM = re.compile(
    r"(^|[\s:])(int|long|short|byte|double|float|boolean|Integer|Long|Short|Double|Float|Boolean"
    r"|UUID|BigDecimal|BigInteger|bool|number)(\s+\w+\s*(=.*)?$|\s*(=.*)?$)"
)


@dataclass(frozen=True)
class Label:
    """One reason a value is considered attacker-controlled."""

    origin: tuple[Any, ...]  # ("src", kind, file, line, text) | ("param", index)
    cleaned: frozenset[str] = frozenset()
    path: tuple[str, ...] = field(
        default=(), compare=False
    )  # explanation only: never part of identity

    @property
    def is_src(self) -> bool:
        return bool(self.origin[0] == "src")


Taint = frozenset[Label]
EMPTY: Taint = frozenset()


@dataclass(frozen=True)
class SinkRef:
    """A sink reachable from a parameter (kept in summaries)."""

    param: int
    kind: str
    cwe: str
    severity: str
    title: str
    file: str
    line: int
    snippet: str
    steps: tuple[str, ...] = field(compare=False)


@dataclass
class Summary:
    ret: set[Label] = field(default_factory=set)
    sinks: set[SinkRef] = field(default_factory=set)

    def key(self) -> tuple[frozenset[Label], frozenset[SinkRef]]:
        return (frozenset(self.ret), frozenset(self.sinks))


@dataclass
class Fn:
    pf: ParsedFile
    model: Model
    node: Node
    name: str
    cls: str | None
    params: list[str]
    param_decls: list[str]
    summary: Summary = field(default_factory=Summary)

    @property
    def arity(self) -> int:
        return len(self.params)


@dataclass(frozen=True)
class Hit:
    """A source-to-sink path (one finding)."""

    kind: str
    cwe: str
    severity: str
    title: str
    file: str
    line: int
    snippet: str
    source_kind: str
    source_file: str
    source_line: int
    steps: tuple[str, ...]

    @property
    def cross_file(self) -> bool:
        return self.source_file != self.file or any(" in " in s and "(" in s for s in self.steps)


def _text(pf: ParsedFile, node: Node | None) -> str:
    return "" if node is None else pf.text(node)


def name_cleans(name: str) -> frozenset[str]:
    """What a project's own helper cleans, judged by its name: `escape_for_html` makes text safe
    for HTML, not for a shell or a deserializer; `validate`/`sanitize` with no context say all."""
    low = name.lower()
    kinds = {k for word, k in _NAME_CONTEXTS if word in low}
    if kinds:
        return frozenset(kinds)
    if re.search(r"escap|encod", low):
        return frozenset({"xss", "redirect"})  # bare escape(): an HTML escape
    return frozenset({"*"})


_NAME_CONTEXTS = (
    ("html", "xss"),
    ("xml", "xss"),
    ("js", "xss"),
    ("url", "redirect"),
    ("sql", "sql"),
    ("shell", "cmd"),
    ("cmd", "cmd"),
    ("command", "cmd"),
    ("path", "path"),
    ("file", "path"),
    ("ldap", "ldap"),
    ("xpath", "xpath"),
)


def _no_args(call: Node) -> bool:
    args = call.child_by_field_name("arguments")
    return args is None or not args.named_children


def _simple_type(text: str) -> str:
    """`java.util.List<String>[]` -> `List`."""
    return text.split("<")[0].split("[")[0].strip().rsplit(".", 1)[-1]


def _named_children(node: Node) -> list[Node]:
    return [
        c for c in node.named_children if c.type not in ("comment", "line_comment", "block_comment")
    ]


def _walk(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _enclosing_class(node: Node, pf: ParsedFile) -> str | None:
    p = node.parent
    while p is not None:
        if p.type in CLASS_TYPES:
            return _text(pf, p.child_by_field_name("name")) or None
        p = p.parent
    return None


def _fn_name(pf: ParsedFile, node: Node) -> str:
    n = node.child_by_field_name("name")
    if n is not None:
        return _text(pf, n)
    p = node.parent
    if p is not None:
        if p.type == "variable_declarator":
            return _text(pf, p.child_by_field_name("name"))
        if p.type in ASSIGN_TYPES:
            return _text(pf, p.child_by_field_name("left")).rsplit(".", 1)[-1]
        if p.type == "pair":
            return _text(pf, p.child_by_field_name("key"))
    return "<anonymous>"


def _param_nodes(pf: ParsedFile, node: Node) -> list[tuple[str, str]]:
    """(name, declaration text) per parameter, `self`/`cls` excluded."""
    plist = node.child_by_field_name("parameters")
    out: list[tuple[str, str]] = []
    if plist is None:
        single = node.child_by_field_name("parameter")
        if single is not None:
            out.append((_text(pf, single), _text(pf, single)))
        return out
    for i, c in enumerate(_named_children(plist)):
        decl = _text(pf, c)
        name = ""
        if c.type == "identifier":
            name = decl
        else:
            nm = c.child_by_field_name("name") or c.child_by_field_name("left")
            if nm is None:
                nm = next((x for x in c.named_children if x.type == "identifier"), None)
            name = _text(pf, nm) if nm is not None and nm.type == "identifier" else f"_p{i}"
        if name in ("self", "cls") and not out:
            continue
        out.append((name, decl))
    return out


def collect_functions(pf: ParsedFile, model: Model) -> list[Fn]:
    fns: list[Fn] = []
    if pf.language in ("python", "javascript", "typescript", "tsx"):  # script-level code
        fns.append(Fn(pf, model, pf.tree.root_node, "<module>", None, [], []))
    for n in _walk(pf.tree.root_node):
        if n.type not in FUNC_TYPES or n.type in ("lambda_expression", "lambda"):
            continue
        body = n.child_by_field_name("body")
        if body is None:
            continue
        pn = _param_nodes(pf, n)
        fns.append(Fn(pf, model, n, _fn_name(pf, n), _enclosing_class(n, pf),
                      [p[0] for p in pn], [p[1] for p in pn]))  # fmt: skip
    return fns


class Project:
    def __init__(self) -> None:
        self.fns: list[Fn] = []
        self.by_name: dict[str, list[Fn]] = {}
        self.fields: dict[tuple[str, str], set[Label]] = {}
        self.hits: dict[tuple[Any, ...], Hit] = {}
        self.changed = False
        self.skipped: set[str] = set()  # functions too complex to analyze (reported, not hidden)
        self.root: Path | None = None
        self._templates: dict[str, frozenset[str]] = {}
        self._template_files: list[Path] | None = None
        self.classes: set[str] = set()  # class names defined in the project (Java receiver typing)

    def unsafe_template_vars(self, name: str) -> frozenset[str]:
        """Variables a template prints without escaping (`|safe`, autoescape off)."""
        if name in self._templates:
            return self._templates[name]
        out: set[str] = set()
        if self.root is not None:
            if self._template_files is None:
                self._template_files = [
                    p
                    for ext in (
                        "*.html",
                        "*.htm",
                        "*.jinja",
                        "*.jinja2",
                        "*.j2",
                        "*.djhtml",
                        "*.txt",
                    )
                    for p in self.root.rglob(ext)
                    if not any(d in SKIP_DIRS_FOR_TAINT for d in p.parts)
                ]
            for p in self._template_files:
                if str(p).endswith("/" + name.lstrip("/")):
                    try:
                        text = p.read_text("utf-8", "replace")
                    except OSError:
                        continue
                    out |= set(SAFE_FILTER.findall(text))
                    for block in AUTOESCAPE_OFF.findall(text):
                        out |= set(TEMPLATE_VAR.findall(block))
        self._templates[name] = frozenset(out)
        return self._templates[name]

    def add(self, fn: Fn) -> None:
        self.fns.append(fn)
        if fn.name != "<module>":
            self.by_name.setdefault(fn.name, []).append(fn)

    def resolve(self, name: str, arity: int, cur: Fn) -> list[Fn]:
        cands = [f for f in self.by_name.get(name, []) if f.arity == arity]
        if not cands:
            return []
        if len(cands) > MAX_CANDIDATES:
            same = [f for f in cands if f.pf.path == cur.pf.path]
            cands = same or []
        else:
            same = [
                f
                for f in cands
                if f.cls is not None and f.cls == cur.cls and f.pf.path == cur.pf.path
            ]
            if same:
                cands = same
        return cands[:MAX_CANDIDATES]


class FnAnalysis:
    def __init__(self, project: Project, fn: Fn) -> None:
        self.p = project
        self.fn = fn
        self.pf = fn.pf
        self.m = fn.model
        self.env: dict[str, Taint] = {}
        self.ret: set[Label] = set()
        self.sinks: set[SinkRef] = set()
        # Precision state, only ever used when certain (otherwise the env union is the answer):
        self.consts: dict[str, Any] = {}  # local name -> compile-time constant
        self.lists: dict[str, list[Taint]] = {}  # local list/array -> taint per position
        self.maps: dict[str, dict[Any, Taint]] = {}  # local map/dict -> taint per literal key
        self.cur_branch = False
        self.steps = 0
        self.depth = 0  # how many undecided branches/loops enclose the current statement
        self.decl_depth: dict[str, int] = {}  # where a local was declared
        self.coll_depth: dict[str, int] = {}  # where a tracked collection was created
        self.types: dict[str, str] = {}  # Java local -> declared simple type name
        self.map_kind: dict[str, str] = {}  # "dict" or "config" (section, option keys)
        self.derived: dict[str, str] = {}  # `url = urlparse(bar)`: checking url checks bar
        self.is_handler = False

    # ---- helpers -------------------------------------------------------------------------
    def line(self, node: Node) -> int:
        return node.start_point[0] + 1

    def snippet(self, node: Node) -> str:
        i = node.start_point[0]
        return self.pf.lines[i].strip()[:200] if i < len(self.pf.lines) else ""

    def step(self, node: Node, msg: str) -> str:
        return f"{msg} at {self.pf.path}:{self.line(node)}"

    def add_step(self, t: Taint, s: str) -> Taint:
        return frozenset(Label(x.origin, x.cleaned, (x.path + (s,))[-MAX_PATH:]) for x in t)

    def source_label(self, kind: str, node: Node) -> Label:
        text = " ".join(_text(self.pf, node).split())[:80]
        origin = ("src", kind, self.pf.path, self.line(node), text)
        return Label(origin, frozenset(), (self.step(node, f"{kind} source `{text}`"),))

    # ---- entry ---------------------------------------------------------------------------
    def run(self) -> None:
        fn = self.fn
        header = " ".join(
            fn.pf.lines[
                fn.node.start_point[0] : (
                    fn.node.child_by_field_name("body") or fn.node
                ).start_point[0]
                + 1
            ]
        )
        decorated = fn.node.parent is not None and fn.node.parent.type == "decorated_definition"
        if decorated and fn.node.parent is not None:
            header = _text(self.pf, fn.node.parent)[:600]
        is_handler = any(h.search(header) for h in self.m.handlers)
        self.is_handler = is_handler
        for i, (name, decl) in enumerate(zip(fn.params, fn.param_decls, strict=False)):
            labels: set[Label] = {Label(("param", i))}
            spec = next((s for s in self.m.param_sources if s.pattern.search(decl)), None)
            kind = spec.kind if spec else None
            if kind is None and is_handler:
                kind = "http_param"
            if kind is not None and NUMERIC_PARAM.search(re.sub(r"@\w+(\([^)]*\))?", "", decl)):
                kind = None  # a number or boolean cannot carry an injection payload
            if kind is not None:
                labels.add(
                    self.source_label(kind, fn.node.child_by_field_name("parameters") or fn.node)
                )
            self.env[name] = frozenset(labels)
            if spec is not None and spec.safe_for:
                self.env[name] = self.clean(
                    self.env[name], Sanitizer(re.compile(""), spec.safe_for)
                )
            if fn.pf.language == "java":
                m = re.match(r"^(?:@\w+(?:\([^)]*\))?\s+|final\s+)*(.+?)\s+\w+$", decl.strip())
                if m:
                    self.types[name] = _simple_type(m.group(1))
        body = fn.node.child_by_field_name("body")
        if fn.node.type in ("program", "module"):
            self.walk(fn.node, False)
            return
        if body is None:
            return
        if body.type not in ("block", "statement_block", "constructor_body"):  # expression body
            self.ret |= self.eval(body)
        else:
            self.walk(body, False)

    # ---- statements ----------------------------------------------------------------------
    def walk(self, node: Node, branch: bool) -> None:
        t = node.type
        self.cur_branch = branch
        if t in FUNC_TYPES:
            return
        if t == "resource":  # try-with-resources: `Type name = value`
            name_n = node.child_by_field_name("name")
            if name_n is not None:
                self.decl_depth[_text(self.pf, name_n)] = self.depth
            self.assign(name_n, node.child_by_field_name("value"), branch, False)
            return
        if t in ("local_variable_declaration", "lexical_declaration", "variable_declaration"):
            ty = node.child_by_field_name("type")
            for d in node.named_children:
                if ty is not None and d.type == "variable_declarator":
                    nm = d.child_by_field_name("name")
                    if nm is not None:
                        self.types[_text(self.pf, nm)] = _simple_type(_text(self.pf, ty))
                if d.type == "variable_declarator":
                    name_n = d.child_by_field_name("name")
                    if name_n is not None and name_n.type == "identifier":
                        self.decl_depth[_text(self.pf, name_n)] = self.depth
                    self.assign(
                        d.child_by_field_name("name"), d.child_by_field_name("value"), branch, False
                    )
            return
        if t == "variable_declarator":
            name_n = node.child_by_field_name("name")
            if name_n is not None and name_n.type == "identifier":
                self.decl_depth[_text(self.pf, name_n)] = self.depth
            self.assign(
                node.child_by_field_name("name"), node.child_by_field_name("value"), branch, False
            )
            return
        if t in ASSIGN_TYPES:
            self.assign(
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
                branch,
                t.startswith("augmented") or "+=" in _text(self.pf, node)[:80].split("=")[0] + "=",
            )
            return
        if t == "return_statement":
            kids = _named_children(node)
            if kids:
                value = self.eval(kids[0])
                self.ret |= value
                if self.is_handler and self.m.return_sinks:
                    self.return_sink(kids[0], value)
            return
        if t in ("enhanced_for_statement", "for_statement", "for_in_statement"):
            target = node.child_by_field_name("name") or node.child_by_field_name("left")
            it = node.child_by_field_name("value") or node.child_by_field_name("right")
            if target is not None and it is not None:
                self.bind(target, self.eval(it), True)
            self.depth += 1
            for c in node.named_children:
                if c is not target and c is not it:
                    self.walk(c, True)
            self.depth -= 1
            return
        if t in ("if_statement", "elif_clause"):
            cond = node.child_by_field_name("condition")
            if cond is not None:
                self.eval(cond)
                decided = truth(fold(self.pf, cond, self.consts))
                if decided is not None:  # a constant condition: only one side ever runs
                    self.walk_taken_if(node, decided, branch)
                    return
            guarded = self.guarded_names(cond) if cond is not None else []
            cons = node.child_by_field_name("consequence")
            negated = cond is not None and self.is_negated(cond)
            saved: dict[str, Taint] = {}
            if guarded and not negated:  # `if valid(x) { use x }`: x is valid inside only
                saved = {n: self.env[n] for n in guarded if n in self.env}
                self.clean_names(guarded)
            self.depth += 1
            for c in node.named_children:
                if c is cond:
                    continue
                if saved and c is not cons:  # leaving the checked block: restore
                    for n, t0 in saved.items():
                        self.env[n] = self.env.get(n, EMPTY) | t0
                    saved = {}
                self.walk(c, True)
            self.depth -= 1
            for n, t0 in saved.items():
                self.env[n] = self.env.get(n, EMPTY) | t0
            if guarded and negated and cons is not None and self.exits(cons):
                self.clean_names(guarded)  # `if not valid(x): abort()`: x is valid from here on
            elif cond is not None and cons is not None and not negated and self.exits(cons):
                kinds = self.blocklist_kinds(cond)
                names = self.cond_names(cond)
                if kinds and names:  # `if '../' in name: return`: from here on name has no '../'
                    self.clean_names(names, kinds)
            return
        if t in ("switch_expression", "switch_statement") and self.walk_constant_switch(
            node, branch
        ):
            return
        if t == "match_statement" and self.walk_constant_match(node, branch):
            return
        if (
            t in BRANCH_TYPES
            or t in CONTAINER_TYPES
            or t.endswith("_statement")
            or t in ("program", "module")
        ):
            inner = branch or t in BRANCH_TYPES
            self.depth += t in BRANCH_TYPES
            for c in node.named_children:
                self.walk(c, inner)
            self.depth -= t in BRANCH_TYPES
            return
        self.eval(node)

    def walk_taken_if(self, node: Node, decided: bool, branch: bool) -> None:
        if decided:
            body = node.child_by_field_name("consequence")
            if body is not None:
                self.walk_unconditional(body, branch)
            return
        for alt in node.children_by_field_name("alternative"):
            if alt.type == "elif_clause":
                self.walk(alt, branch)
                return  # the elif decides the rest of the chain
            self.walk_unconditional(alt, branch)
            return

    def walk_unconditional(self, node: Node, branch: bool) -> None:
        """Walk a block that certainly runs (a decided branch): its assignments replace."""
        if node.type in ("else_clause", "block", "statement_block", "switch_block_statement_group"):
            for c in node.named_children:
                self.walk(c, branch)
        else:
            self.walk(node, branch)

    def walk_constant_match(self, node: Node, branch: bool) -> bool:
        """Python `match` on a constant: only the first matching `case` runs (no fall-through)."""
        subject = node.child_by_field_name("subject")
        body = node.child_by_field_name("body")
        val = fold(self.pf, subject, self.consts)
        if body is None or val is UNKNOWN:
            return False
        chosen: Node | None = None
        for case in (c for c in body.named_children if c.type == "case_clause"):
            pat = next((c for c in case.named_children if c.type == "case_pattern"), None)
            if pat is None or case.child_by_field_name("guard") is not None:
                return False
            if _text(self.pf, pat).strip() == "_":
                chosen = case
                break
            first = pat.named_children[0] if pat.named_children else None
            alts = (
                first.named_children
                if first is not None and first.type == "union_pattern"
                else pat.named_children
            )
            values = [fold(self.pf, a, self.consts) for a in alts]
            if not values or any(v is UNKNOWN for v in values):
                return False  # a capture or class pattern: cannot decide
            if val in values:
                chosen = case
                break
        if chosen is not None:
            cons = chosen.child_by_field_name("consequence")
            if cons is not None:
                self.walk_unconditional(cons, branch)
        return True

    def return_sink(self, expr: Node, value: Taint) -> None:
        inner = expr
        while inner.type == "parenthesized_expression" and inner.named_children:
            inner = inner.named_children[0]
        if inner.type in ("expression_list", "tuple") and inner.named_children:
            inner = inner.named_children[0]  # `return body, 200`
        if inner.type in ("dictionary", "list", "integer", "true", "false", "none"):
            return  # Flask serializes these as JSON or rejects them
        for rs in self.m.return_sinks:
            fn = inner.child_by_field_name("function") if inner.type == "call" else None
            if fn is not None and rs.safe_calls.search(_text(self.pf, fn)):
                continue
            self.hit_sink(value, rs.kind, rs.cwe, rs.severity, rs.title, expr)

    def walk_constant_switch(self, node: Node, branch: bool) -> bool:
        """`switch` on a constant: run the matching case (and fall through until `break`)."""
        cond = node.child_by_field_name("condition") or node.child_by_field_name("value")
        body = node.child_by_field_name("body")
        val = fold(self.pf, cond, self.consts)
        if body is None or val is UNKNOWN:
            return False
        if cond is not None:
            self.eval(cond)
        groups = [g for g in body.named_children if g.type in (
            "switch_block_statement_group", "switch_rule", "switch_case", "switch_default")]  # fmt: skip
        if not groups:
            return False

        def labels(g: Node) -> list[Any]:
            if g.type == "switch_default":
                return ["__default__"]
            if g.type == "switch_case":
                return [fold(self.pf, g.child_by_field_name("value"), self.consts)]
            out: list[Any] = []
            for lab in (c for c in g.named_children if c.type == "switch_label"):
                kids = lab.named_children
                out += [fold(self.pf, k, self.consts) for k in kids] if kids else ["__default__"]
            return out

        all_labels = [labels(g) for g in groups]
        if any(x is UNKNOWN for ls in all_labels for x in ls):
            return False  # a case we cannot evaluate: be conservative
        start = next((i for i, ls in enumerate(all_labels) if val in ls), None)
        if start is None:
            start = next((i for i, ls in enumerate(all_labels) if "__default__" in ls), None)
        if start is None:
            return True  # no case matches and no default: nothing runs
        for g in groups[start:]:
            stmts = [
                c
                for c in g.named_children
                if c.type not in ("switch_label",) and c is not g.child_by_field_name("value")
            ]
            stop = False
            for st in stmts:
                if st.type in ("break_statement", "return_statement", "throw_statement"):
                    if st.type != "break_statement":
                        self.walk(st, branch)
                    stop = True
                    break
                self.walk(st, branch)
            if stop or g.type == "switch_rule":
                break
        return True

    def targets(self, node: Node | None) -> list[str]:
        if node is None:
            return []
        t = node.type
        if t == "identifier" or t == "shorthand_property_identifier_pattern":
            return [_text(self.pf, node)]
        if t in MEMBER_TYPES or t in ("subscript", "subscript_expression", "array_access"):
            obj = node.child_by_field_name("object") or node.child_by_field_name("value")
            if obj is None and node.named_children:
                obj = node.named_children[0]
            names = self.targets(obj)
            txt = _text(self.pf, node)
            if obj is not None and _text(self.pf, obj) in THIS_NAMES and t in MEMBER_TYPES:
                attr = (
                    node.child_by_field_name("attribute")
                    or node.child_by_field_name("field")
                    or node.child_by_field_name("property")
                )
                if attr is not None:
                    return [f"this.{_text(self.pf, attr)}"]
            return names or ([txt] if txt else [])
        out: list[str] = []
        for c in node.named_children:
            out += self.targets(c)
        return out

    def bind(self, target: Node, taint: Taint, weak: bool) -> None:
        for name in self.targets(target):
            if name.startswith("this."):
                self.store_field(name[5:], taint)
            if weak:
                self.env[name] = self.env.get(name, EMPTY) | taint
            else:
                self.env[name] = taint

    def store_field(self, name: str, taint: Taint) -> None:
        cls = self.fn.cls
        if cls is None:
            return
        key = (cls, name)
        have = self.p.fields.setdefault(key, set())
        add = {x for x in taint if x.is_src} - have
        if add:
            have |= add
            self.p.changed = True

    def assign(self, left: Node | None, right: Node | None, branch: bool, compound: bool) -> Taint:
        """Bind `left = right` and return the assigned taint (the value of the expression)."""
        if left is None or right is None:
            return EMPTY
        taint = self.eval(right)
        ltxt = _text(self.pf, left)
        for sink in self.m.assign_sinks:
            if sink.target.search(ltxt):
                key_t = EMPTY
                if sink.key and left.type in ("subscript", "subscript_expression"):
                    key_t = self.eval(
                        left.child_by_field_name("subscript") or left.child_by_field_name("index")
                    )
                self.hit_sink(taint | key_t, sink.kind, sink.cwe, sink.severity, sink.title, left)
        if left.type == "identifier" and ltxt not in self.decl_depth and ltxt not in self.env:
            self.decl_depth[ltxt] = self.depth  # python/js: the first assignment declares it
        # A variable declared at this depth lives entirely in this block: plain assignments to it
        # are certain even inside a branch.
        scoped = left.type == "identifier" and self.decl_depth.get(ltxt) == self.depth
        certain = not compound and (not branch or scoped)
        if left.type == "identifier":
            self.track(ltxt, right, taint, certain=certain)
        elif left.type in ("subscript", "subscript_expression", "array_access"):
            self.store_element(left, taint, certain=certain)
        self.bind(left, taint, not certain or left.type not in ("identifier",))
        return taint

    def track(self, name: str, right: Node, taint: Taint, certain: bool) -> None:
        """Constants and collection shapes of a plain local assignment."""
        self.derived.pop(name, None)
        if right.type in CALL_TYPES and PARSE_CALL.search(_text(self.pf, right)[:120]):
            idents = {
                _text(self.pf, n)
                for n in _walk(right)
                if n.type == "identifier" and self.env.get(_text(self.pf, n))
            }
            if len(idents) == 1:
                self.derived[name] = next(iter(idents))
        self.consts.pop(name, None)
        self.lists.pop(name, None)
        self.maps.pop(name, None)
        if right.type == "identifier":  # aliasing: stop tracking the shared collection
            other = _text(self.pf, right)
            self.lists.pop(other, None)
            self.maps.pop(other, None)
        if not certain:
            return
        val = fold(self.pf, right, self.consts)
        if val is not UNKNOWN:
            self.consts[name] = val
        inner = right
        while (
            inner.type in ("cast_expression", "parenthesized_expression") and inner.named_children
        ):
            inner = inner.named_children[-1]
        txt = _text(self.pf, inner)[:200]
        if inner.type in ("list", "array", "array_initializer") or (
            inner.type in ("object_creation_expression", "array_creation_expression")
            and re.search(r"(List|Vector|Deque|\[\])", txt)
        ):
            elems = inner.named_children if inner.type != "array_creation_expression" else [
                c for c in inner.named_children if c.type == "array_initializer"]  # fmt: skip
            if inner.type == "array_creation_expression":
                elems = elems[0].named_children if elems else []
                if not elems and "{" not in txt:
                    return  # `new String[n]`: size only, contents unknown
            if inner.type == "object_creation_expression":
                args = inner.child_by_field_name("arguments")
                if args is not None and args.named_children:
                    return  # `new ArrayList<>(other)`: copies something we do not track
                elems = []
            self.lists[name] = [self.eval(e) for e in elems if e.type not in ("comment",)]
            self.coll_depth[name] = self.depth
        elif (
            inner.type == "call"
            and _no_args(inner)
            and re.search(
                r"(^|\.)(list|deque)$", _text(self.pf, inner.child_by_field_name("function"))
            )
        ):
            self.lists[name] = []
            self.coll_depth[name] = self.depth
        elif (
            inner.type == "call"
            and _no_args(inner)
            and re.search(
                r"(^|\.)(dict|OrderedDict|ConfigParser|RawConfigParser)$",
                _text(self.pf, inner.child_by_field_name("function")),
            )
        ):
            self.maps[name] = {}
            self.coll_depth[name] = self.depth
            self.map_kind[name] = "config" if "ConfigParser" in _text(self.pf, inner) else "dict"
        elif inner.type == "dictionary" or (
            inner.type == "object_creation_expression"
            and re.search(r"Map\b|Map<|Hashtable|Properties", txt)
        ):
            entries: dict[Any, Taint] = {}
            for pair in inner.named_children if inner.type == "dictionary" else []:
                if pair.type != "pair":
                    return
                key = fold(self.pf, pair.child_by_field_name("key"), self.consts)
                if key is UNKNOWN:
                    return
                entries[key] = self.eval(pair.child_by_field_name("value"))
            if inner.type == "object_creation_expression":
                args = inner.child_by_field_name("arguments")
                if args is not None and args.named_children:
                    return
            self.maps[name] = entries
            self.coll_depth[name] = self.depth

    def store_element(self, left: Node, taint: Taint, certain: bool) -> None:
        base = (
            left.child_by_field_name("value")
            or left.child_by_field_name("object")
            or left.child_by_field_name("array")
        )
        key_node = left.child_by_field_name("subscript") or left.child_by_field_name("index")
        if base is None or base.type != "identifier":
            return
        name = _text(self.pf, base)
        key = fold(self.pf, key_node, self.consts)
        if name in self.maps:
            if certain and key is not UNKNOWN:
                self.maps[name][key] = taint
            else:
                self.maps.pop(name)
        if name in self.lists:
            lst = self.lists[name]
            if certain and isinstance(key, int) and -len(lst) <= key < len(lst):
                lst[key] = taint
            else:
                self.lists.pop(name)

    # ---- expressions ---------------------------------------------------------------------
    def eval(self, node: Node | None) -> Taint:
        if node is None:
            return EMPTY
        self.steps += 1
        if self.steps > MAX_STEPS_PER_FUNCTION:
            raise BudgetExceeded
        t = node.type
        if t in LITERAL_TYPES or t in FUNC_TYPES:
            return EMPTY
        text = _text(self.pf, node) if node.end_byte - node.start_byte < 400 else ""
        if text and t not in (
            "identifier",
            "string",
            "template_string",
            "binary_expression",
            "binary_operator",
            "parenthesized_expression",
        ):
            for s in self.m.sources:
                if s.pattern.match(text):
                    return frozenset({self.source_label(s.kind, node)})
        if t == "identifier":
            return self.lookup(text)
        if t in CALL_TYPES:
            return self.call(node)
        if t in ASSIGN_TYPES:  # `a = b = x` as an expression: assign once, return the value
            return self.assign(
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
                self.cur_branch,
                t.startswith("augmented"),
            )
        if t in ("ternary_expression", "conditional_expression"):
            if t == "conditional_expression":  # python: a if cond else b
                kids = node.named_children
                cond_n, yes, no = (
                    (kids[1], kids[0], kids[2]) if len(kids) == 3 else (None, None, None)
                )
            else:
                cond_n = node.child_by_field_name("condition")
                yes = node.child_by_field_name("consequence")
                no = node.child_by_field_name("alternative")
            decided = truth(fold(self.pf, cond_n, self.consts)) if cond_n is not None else None
            if decided is not None:
                return self.eval(yes if decided else no)
        if t in ("subscript", "subscript_expression", "array_access"):
            b0 = (
                node.child_by_field_name("value")
                or node.child_by_field_name("object")
                or node.child_by_field_name("array")
            )
            k0 = node.child_by_field_name("subscript") or node.child_by_field_name("index")
            if b0 is not None and b0.type == "identifier":
                bn = _text(self.pf, b0)
                key = fold(self.pf, k0, self.consts)
                if bn in self.maps and key is not UNKNOWN:
                    self.eval(k0)
                    return self.maps[bn].get(key, EMPTY)
                if (
                    bn in self.lists
                    and isinstance(key, int)
                    and -len(self.lists[bn]) <= key < len(self.lists[bn])
                ):
                    return self.lists[bn][key]
        if t in ("subscript", "subscript_expression", "array_access"):
            base = (
                node.child_by_field_name("value")
                or node.child_by_field_name("object")
                or node.child_by_field_name("array")
            )
            if (
                base is not None
                and base.type == "identifier"
                and CONSTANT_NAME.match(_text(self.pf, base))
            ):
                return EMPTY  # key lookup in a constant table returns the table's values
        if t in MEMBER_TYPES:
            obj = node.child_by_field_name("object")
            if obj is not None and _text(self.pf, obj) in THIS_NAMES:
                attr = (
                    node.child_by_field_name("attribute")
                    or node.child_by_field_name("field")
                    or node.child_by_field_name("property")
                )
                return self.lookup_field(_text(self.pf, attr)) if attr is not None else EMPTY
            return self.eval(obj)
        if t == "keyword_argument":
            return self.eval(node.child_by_field_name("value"))
        if t in ("pair", "property_assignment"):
            return self.eval(node.child_by_field_name("value"))
        out: Taint = EMPTY
        for c in node.named_children:
            if c.type in (
                "type_identifier",
                "integral_type",
                "generic_type",
                "property_identifier",
                "comment",
            ):
                continue
            out = out | self.eval(c)
        return out

    def lookup(self, name: str) -> Taint:
        if name in self.env:
            return self.env[name]
        return self.lookup_field(name)

    def lookup_field(self, name: str) -> Taint:
        if self.fn.cls is None:
            return EMPTY
        have = self.p.fields.get((self.fn.cls, name))
        return frozenset(have) if have else EMPTY

    # ---- calls ---------------------------------------------------------------------------
    def call_parts(self, node: Node) -> tuple[str, str, Node | None, list[Node]]:
        """(callee text, simple name, receiver node, argument nodes)"""
        t = node.type
        args_node = node.child_by_field_name("arguments")
        args = _named_children(args_node) if args_node is not None else []
        if t == "method_invocation":
            obj = node.child_by_field_name("object")
            name = _text(self.pf, node.child_by_field_name("name"))
            callee = f"{_text(self.pf, obj)}.{name}" if obj is not None else name
            return callee, name, obj, args
        if t == "object_creation_expression":
            ty = _text(self.pf, node.child_by_field_name("type")).split("<")[0]
            return f"new {ty}", ty.rsplit(".", 1)[-1], None, args
        if t == "new_expression":
            ctor = node.child_by_field_name("constructor")
            ty = _text(self.pf, ctor)
            return f"new {ty}", ty.rsplit(".", 1)[-1], None, args
        fnode = node.child_by_field_name("function")
        callee = _text(self.pf, fnode)
        recv = None
        name = callee
        if fnode is not None and fnode.type in MEMBER_TYPES:
            recv = fnode.child_by_field_name("object")
            attr = fnode.child_by_field_name("attribute") or fnode.child_by_field_name("property")
            name = _text(self.pf, attr)
        return callee, name, recv, args

    def call(self, node: Node) -> Taint:
        callee, name, recv, args = self.call_parts(node)
        text = _text(self.pf, node) if node.end_byte - node.start_byte < 400 else ""
        for s in self.m.sources:
            if text and s.pattern.match(text):
                for a in args:
                    self.eval(a)
                return frozenset({self.source_label(s.kind, node)})
        arg_t = [self.eval(a) for a in args]
        recv_t = self.eval(recv) if recv is not None else EMPTY
        all_t: Taint = recv_t.union(*arg_t) if arg_t else recv_t
        precise = self.collection_call(recv, name, args, arg_t)
        if precise is not None:
            return precise
        for a in args:  # a tracked collection handed to other code may be changed there
            if a.type == "identifier":
                self.lists.pop(_text(self.pf, a), None)
                self.maps.pop(_text(self.pf, a), None)

        if (
            name in ("get", "getOrDefault", "pop")
            and recv is not None
            and recv.type == "identifier"
            and CONSTANT_NAME.match(_text(self.pf, recv))
        ):
            return EMPTY  # PAGES.get(user_value, "/"): the result comes from the constant table
        # 1. direct sinks
        for sink in self.m.sinks:
            if sink.callee.search(callee):
                if sink.unless and any(sink.unless.search(_text(self.pf, a)) for a in args):
                    continue  # e.g. res.sendFile(path, { root }) refuses paths outside root
                idxs = sink.args if sink.args is not None else tuple(range(len(args)))
                if sink.receiver and recv is not None:
                    self.hit_sink(recv_t, sink.kind, sink.cwe, sink.severity, sink.title, node)
                for i in idxs:
                    if i < len(arg_t):
                        t_i = arg_t[i]
                        if (
                            sink.kind == "xss"
                            and args[i].type == "tuple"
                            and args[i].named_children
                        ):
                            t_i = self.eval(args[i].named_children[0])  # (body, headers)
                        self.hit_sink(t_i, sink.kind, sink.cwe, sink.severity, sink.title, node)
        first = fold(self.pf, args[0], self.consts) if args else UNKNOWN
        if (
            name == "replace"
            and len(args) >= 2
            and isinstance(first, str)
            and set(first) & {"'", '"'}
        ):
            # replacing the quote character escapes a value for a quoted XPath string literal
            return self.clean(all_t, Sanitizer(re.compile(""), frozenset({"xpath"})))
        for ts in self.m.template_sinks:
            if ts.callee.search(callee):
                self.template_sink(ts, node, args)
        # 2. sanitizers (library knowledge first); every matching entry counts, so a call that is
        #    both a URL quote and a shell quote cleans both kinds of sink
        matched = [san for san in self.m.sanitizers if san.callee.search(callee)]
        if matched:
            cleans: frozenset[str] = frozenset().union(*(m.cleans for m in matched))
            return self.clean(all_t, Sanitizer(re.compile(""), cleans))
        # 3. user-defined functions (Java receivers are typed: a library object never resolves to
        #    a project method that merely shares its name)
        cands = self.candidates(recv, name, len(args))
        if cands:
            out = self.apply_summaries(cands, node, arg_t, name)
            if SANITIZE_NAME.search(name):  # a project's own sanitize/escape/validate helper
                return self.clean(out, Sanitizer(re.compile(""), name_cleans(name)))
            return out
        if any(d.search(callee) for d in self.m.deny):
            return EMPTY
        if SANITIZE_NAME.search(name):
            return self.clean(all_t, Sanitizer(re.compile(""), name_cleans(name)))
        # 4. collections and builders: the receiver variable absorbs what goes in
        root = self.root_ident(recv) if recv is not None else None
        if root is not None and name in ADD_METHODS:
            incoming: Taint = frozenset().union(*arg_t) if arg_t else EMPTY
            if recv is not None and re.search(r"(^|\.)searchParams$", _text(self.pf, recv)):
                # a query parameter cannot change the host or path of the URL it is added to
                incoming = self.clean(
                    incoming, Sanitizer(re.compile(""), frozenset({"ssrf", "redirect"}))
                )
            self.env[root] = self.env.get(root, EMPTY) | incoming
            return self.env[root]  # builders return themselves: `sb.append(a).toString()`
        # 5. unknown library call: text passes through
        return all_t

    def template_sink(self, ts: Any, node: Node, args: list[Node]) -> None:
        if ts.template_arg >= len(args):
            return
        name = fold(self.pf, args[ts.template_arg], self.consts)
        if not isinstance(name, str):
            return
        unsafe = self.p.unsafe_template_vars(name)
        if not unsafe:
            return
        context: dict[str, Taint] = {}
        if ts.context_arg is None:
            for a in args:
                if a.type == "keyword_argument":
                    key = a.child_by_field_name("name")
                    if key is not None:
                        context[_text(self.pf, key)] = self.eval(a.child_by_field_name("value"))
        elif ts.context_arg < len(args):
            ctx = args[ts.context_arg]
            if ctx.type == "dictionary":
                for pair in ctx.named_children:
                    if pair.type == "pair":
                        key = fold(self.pf, pair.child_by_field_name("key"), self.consts)
                        if isinstance(key, str):
                            context[key] = self.eval(pair.child_by_field_name("value"))
            elif ctx.type == "identifier" and _text(self.pf, ctx) in self.maps:
                context = {str(k): v for k, v in self.maps[_text(self.pf, ctx)].items()}
        for var in unsafe:
            if context.get(var):
                self.hit_sink(context[var], "xss", "CWE-79", "medium", "Cross-site scripting", node)

    def collection_call(
        self, recv: Node | None, name: str, args: list[Node], arg_t: list[Taint]
    ) -> Taint | None:
        """Exact answers for list/map calls on a tracked local collection, else None."""
        if recv is None or recv.type != "identifier":
            return None
        r = _text(self.pf, recv)
        keys = [fold(self.pf, a, self.consts) for a in args]
        if r in self.lists:
            lst = self.lists[r]
            incoming: Taint = frozenset().union(*arg_t) if arg_t else EMPTY
            if name in ("add", "append", "push", "addLast", "offer") and len(args) == 1:
                if self.depth != self.coll_depth.get(r, 0):
                    self.lists.pop(r)
                    return None
                lst.append(arg_t[0])
                self.env[r] = self.env.get(r, EMPTY) | arg_t[0]
                return EMPTY
            if (
                name in ("add", "insert")
                and len(args) == 2
                and isinstance(keys[0], int)
                and self.depth == self.coll_depth.get(r, 0)
            ):
                lst.insert(keys[0], arg_t[1])
                self.env[r] = self.env.get(r, EMPTY) | arg_t[1]
                return EMPTY
            if (
                name in ("remove", "pop")
                and len(args) == 1
                and isinstance(keys[0], int)
                and not isinstance(keys[0], bool)
            ):
                if self.depth != self.coll_depth.get(r, 0) or not -len(lst) <= keys[0] < len(lst):
                    self.lists.pop(r)
                    return None
                return lst.pop(keys[0])
            if name in ("get", "elementAt") and len(args) == 1 and isinstance(keys[0], int):
                return lst[keys[0]] if -len(lst) <= keys[0] < len(lst) else EMPTY
            if name in ("size", "length", "isEmpty", "contains", "indexOf"):
                return EMPTY
            self.lists.pop(r)  # anything else: stop being exact
            self.env[r] = self.env.get(r, EMPTY) | incoming
            return None
        if r in self.maps and self.map_kind.get(r) == "config":
            mp = self.maps[r]
            if name in ("add_section", "has_section", "has_option", "sections"):
                return EMPTY
            if name == "set" and len(args) == 3:
                if self.depth != self.coll_depth.get(r, 0) or UNKNOWN in (keys[0], keys[1]):
                    self.maps.pop(r)
                    self.env[r] = self.env.get(r, EMPTY) | arg_t[2]
                    return None
                mp[(keys[0], keys[1])] = arg_t[2]
                self.env[r] = self.env.get(r, EMPTY) | arg_t[2]
                return EMPTY
            if name == "get" and len(args) >= 2 and UNKNOWN not in (keys[0], keys[1]):
                return mp.get((keys[0], keys[1]), EMPTY)
            self.maps.pop(r)
            return None
        if r in self.maps:
            mp = self.maps[r]
            if name in ("put", "set", "setdefault", "putIfAbsent") and len(args) == 2:
                if self.depth != self.coll_depth.get(r, 0) or keys[0] is UNKNOWN:
                    self.maps.pop(r)
                    self.env[r] = self.env.get(r, EMPTY) | arg_t[1]
                    return None
                if name in ("put", "set") or keys[0] not in mp:
                    mp[keys[0]] = arg_t[1]
                self.env[r] = self.env.get(r, EMPTY) | arg_t[1]
                return EMPTY
            if name in ("get", "getOrDefault", "getProperty") and args and keys[0] is not UNKNOWN:
                default = arg_t[1] if len(args) > 1 else EMPTY
                return mp.get(keys[0], default)
            if name in ("containsKey", "size", "isEmpty", "has"):
                return EMPTY
            self.maps.pop(r)
            return None
        return None

    def candidates(self, recv: Node | None, name: str, arity: int) -> list[Fn]:
        if recv is None:
            return self.p.resolve(name, arity, self.fn)
        if self.pf.language != "java":
            rtext = _text(self.pf, recv)
            if recv.type == "identifier" and rtext in self.p.classes and rtext not in self.env:
                in_class = [f for f in self.p.by_name.get(name, []) if f.cls == rtext]
                if in_class:  # `Student.create(...)`: that class's method, not a namesake
                    return in_class[:MAX_CANDIDATES]
            return self.p.resolve(name, arity, self.fn)
        rtext = _text(self.pf, recv)
        if recv.type in ("this", "super") or rtext in THIS_NAMES:
            rtype: str | None = self.fn.cls
        elif recv.type == "identifier":
            if rtext in self.types:
                rtype = self.types[rtext]
            elif rtext in self.p.classes and rtext not in self.env:
                rtype = rtext  # a static call: `Utils.helper(x)`
            else:
                rtype = None
        elif recv.type == "object_creation_expression":
            rtype = _simple_type(_text(self.pf, recv.child_by_field_name("type")))
        else:
            return []  # the result of another call, a field chain...: treat as a library call
        if rtype is None:
            return self.p.resolve(name, arity, self.fn)
        if rtype not in self.p.classes:
            return []  # String, StringBuilder, List...: library semantics
        typed = [f for f in self.p.resolve(name, arity, self.fn) if f.cls == rtype]
        if typed:
            return typed
        return [f for f in self.p.by_name.get(name, []) if f.arity == arity and f.cls == rtype][
            :MAX_CANDIDATES
        ] or self.p.resolve(name, arity, self.fn)

    def guarded_names(self, cond: Node) -> list[str]:
        """Tainted variables checked by an allowlist-like test in `cond` (heuristic, see docs)."""
        text = _text(self.pf, cond)
        if len(text) > 300 or not GUARD.search(text):
            return []
        names = {_text(self.pf, n) for n in _walk(cond) if n.type == "identifier"}
        return sorted(n for n in names if self.env.get(n))

    def cond_names(self, cond: Node) -> list[str]:
        found = {_text(self.pf, n) for n in _walk(cond) if n.type == "identifier"}
        return sorted(n for n in found if self.env.get(n))

    def blocklist_kinds(self, cond: Node) -> frozenset[str]:
        """Sink kinds a "reject if it contains X" test protects against, from the literal X."""
        text = _text(self.pf, cond)
        if len(text) > 300 or not BLOCKLIST_TEST.search(text):
            return frozenset()
        kinds: set[str] = set()
        for lit in QUOTED_LITERAL.findall(text):
            body = lit[1:-1].replace("\\'", "'").replace('\\"', '"')
            if ".." in body:
                kinds.add("path")
            if "'" in body or '"' in body:
                kinds |= {"xpath", "sql"}  # no quote: cannot break out of a quoted literal
            if "<" in body or ">" in body:
                kinds.add("xss")
        return frozenset(kinds)

    def is_negated(self, cond: Node) -> bool:
        text = " ".join(_text(self.pf, cond).split())
        while text.startswith("(") and text.endswith(")"):
            text = text[1:-1].strip()
        return (
            text.startswith(("!", "not "))
            or " not in " in f" {text} "
            or "||" in text
            and "!" in text
        )

    def exits(self, block: Node) -> bool:
        for n in _walk(block):
            if n.type in (
                "return_statement",
                "throw_statement",
                "raise_statement",
                "continue_statement",
                "break_statement",
            ):
                return True
            if n.type in CALL_TYPES and EXIT_CALL.search(_text(self.pf, n)[:80]):
                return True
        return False

    def clean_names(self, names: list[str], kinds: frozenset[str] = frozenset({"*"})) -> None:
        names = names + [self.derived[n] for n in names if n in self.derived]
        for name in names:
            cur = self.env.get(name)
            if cur:
                self.env[name] = frozenset(Label(x.origin, x.cleaned | kinds, x.path) for x in cur)

    def root_ident(self, node: Node | None) -> str | None:
        """The variable at the start of a call chain: `sb.append(a).append(b)` -> `sb`."""
        while node is not None:
            if node.type == "identifier":
                return _text(self.pf, node)
            if node.type in CALL_TYPES:
                node = node.child_by_field_name("object") or (
                    (node.child_by_field_name("function") or node).child_by_field_name("object")
                    if node.child_by_field_name("function") is not None
                    else None
                )
            elif node.type in MEMBER_TYPES:
                node = node.child_by_field_name("object")
            else:
                return None
        return None

    def clean(self, t: Taint, san: Sanitizer) -> Taint:
        return frozenset(
            Label(
                x.origin,
                x.cleaned | (san.cleans if "*" not in san.cleans else frozenset({"*"})),
                x.path,
            )
            for x in t
        )

    @staticmethod
    def is_cleaned(label: Label, kind: str) -> bool:
        return "*" in label.cleaned or kind in label.cleaned

    def apply_summaries(self, cands: list[Fn], node: Node, arg_t: list[Taint], name: str) -> Taint:
        out: set[Label] = set()
        call_step = self.step(node, f"passed to `{name}()`")
        for f in cands:
            s = f.summary
            for lab in s.ret:
                if lab.is_src:
                    out.add(
                        Label(
                            lab.origin,
                            lab.cleaned,
                            (lab.path + (self.step(node, f"returned by `{name}()`"),))[-MAX_PATH:],
                        )
                    )
                else:
                    j = lab.origin[1]
                    if j < len(arg_t):
                        for a in arg_t[j]:
                            out.add(
                                Label(
                                    a.origin,
                                    a.cleaned | lab.cleaned,
                                    (a.path + (call_step,))[-MAX_PATH:],
                                )
                            )
            for ref in s.sinks:
                if ref.param < len(arg_t):
                    for a in arg_t[ref.param]:
                        if self.is_cleaned(a, ref.kind):
                            continue
                        steps = (a.path + (call_step,) + ref.steps)[-MAX_PATH - 2 :]
                        if a.is_src:
                            self.emit(
                                a,
                                ref.kind,
                                ref.cwe,
                                ref.severity,
                                ref.title,
                                ref.file,
                                ref.line,
                                ref.snippet,
                                steps,
                            )
                        else:
                            self.sinks.add(
                                SinkRef(
                                    a.origin[1],
                                    ref.kind,
                                    ref.cwe,
                                    ref.severity,
                                    ref.title,
                                    ref.file,
                                    ref.line,
                                    ref.snippet,
                                    steps,
                                )
                            )
        return frozenset(out)

    def hit_sink(self, taint: Taint, kind: str, cwe: str, sev: str, title: str, node: Node) -> None:
        for lab in taint:
            if self.is_cleaned(lab, kind):
                continue
            here = self.step(node, f"reaches {kind} sink `{self.snippet(node)[:70]}`")
            steps = (lab.path + (here,))[-MAX_PATH - 2 :]
            if lab.is_src:
                self.emit(
                    lab,
                    kind,
                    cwe,
                    sev,
                    title,
                    self.pf.path,
                    self.line(node),
                    self.snippet(node),
                    steps,
                )
            else:
                self.sinks.add(
                    SinkRef(
                        lab.origin[1],
                        kind,
                        cwe,
                        sev,
                        title,
                        self.pf.path,
                        self.line(node),
                        self.snippet(node),
                        steps,
                    )
                )

    def emit(
        self,
        lab: Label,
        kind: str,
        cwe: str,
        sev: str,
        title: str,
        file: str,
        line: int,
        snippet: str,
        steps: tuple[str, ...],
    ) -> None:
        _, skind, sfile, sline, _txt = lab.origin
        if skind in OPERATOR_SOURCES and kind in (
            "path",
            "ssrf",
            "xss",
            "redirect",
            "nosql",
            "xpath",
            "ldap",
        ):
            return  # configuration and CLI arguments are set by the operator, not an attacker
        key = (kind, file, line, sfile, sline)
        old = self.p.hits.get(key)
        if old is None or len(steps) < len(old.steps):
            self.p.hits[key] = Hit(
                kind, cwe, sev, title, file, line, snippet, skind, sfile, sline, steps
            )


def load_project(target: Path, max_files: int = MAX_FILES) -> Project:
    project = Project()
    project.root = target
    parsed: list[tuple[ParsedFile, str, str]] = []
    for pf, lang, text in _read_sources(target, max_files):
        parsed.append((pf, lang, text))
    active = project_frameworks([(lang, text) for _, lang, text in parsed])
    for pf, lang, _src in parsed:
        model = build_model(lang, "", active)
        for cn in _walk(pf.tree.root_node):
            if cn.type in CLASS_TYPES and (nm := cn.child_by_field_name("name")) is not None:
                project.classes.add(_text(pf, nm))
        for fn in collect_functions(pf, model):
            project.add(fn)
        if model.action_fields:
            _action_field_sources(project, pf, model)
    return project


def _action_field_sources(project: Project, pf: ParsedFile, model: Model) -> None:
    """Frameworks that bind request parameters to fields through setters (Struts 2): the field
    behind every setter of an action class is a source."""
    for cls in _walk(pf.tree.root_node):
        if cls.type != "class_declaration":
            continue
        name_n = cls.child_by_field_name("name")
        body = cls.child_by_field_name("body")
        if name_n is None or body is None:
            continue
        head = _text(pf, cls)[: (body.start_byte - cls.start_byte)]
        text = _text(pf, cls)
        for kind, test in model.action_fields:
            if not test.search(head) and not test.search(text):
                continue
            for m in re.finditer(
                r"public\s+void\s+set([A-Z]\w*)\s*\(\s*(?:final\s+)?([\w.<>\[\]]+)\s+\w+\s*\)", text
            ):
                if NUMERIC_PARAM.search(" " + m.group(2) + " x"):
                    continue  # numbers cannot carry an injection payload
                field_name = m.group(1)[0].lower() + m.group(1)[1:]
                line = pf.source[: cls.start_byte].count(b"\n") + text[: m.start()].count("\n") + 1
                origin = ("src", kind, pf.path, line, f"request parameter bound to {field_name}")
                label = Label(
                    origin,
                    frozenset(),
                    (f"{kind} source `{field_name}` (set by the framework) at {pf.path}:{line}",),
                )
                project.fields.setdefault((_text(pf, name_n), field_name), set()).add(label)


def _read_sources(target: Path, max_files: int) -> Iterator[tuple[ParsedFile, str, str]]:
    n = 0
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS_FOR_TAINT]
        for fname in sorted(files):
            lang = detect_language(fname)
            if lang not in ("java", "python", "javascript", "typescript", "tsx"):
                continue
            full = Path(root) / fname
            try:
                if full.stat().st_size > MAX_FILE_BYTES:
                    continue
                src = full.read_bytes()
            except OSError:
                continue
            rel = str(full.relative_to(target))
            try:
                pf = parse(rel, src, lang)
            except Exception:  # noqa: BLE001 - one bad file never stops the scan
                continue
            if pf is None:
                continue
            yield pf, lang, src.decode("utf-8", "replace")
            n += 1
            if n >= max_files:
                return


def analyze(project: Project) -> list[Hit]:
    """Run to a fixed point; return one hit per distinct (sink, source) pair."""
    for _ in range(MAX_PASSES):
        project.changed = False
        for fn in project.fns:
            a = FnAnalysis(project, fn)
            try:
                a.run()
            except (RecursionError, BudgetExceeded):
                if fn.name not in project.skipped:
                    log.warning("taint: skipped %s in %s (too complex)", fn.name, fn.pf.path)
                    project.skipped.add(fn.name)
                continue
            new = Summary(set(a.ret), set(a.sinks))
            if new.key() != fn.summary.key():
                fn.summary = new
                project.changed = True
        if not project.changed:
            break
    return sorted(project.hits.values(), key=lambda h: (h.file, h.line, h.kind))


def scan_dir(target: Path) -> list[Hit]:
    return analyze(load_project(target))


__all__ = ["Hit", "Project", "Sink", "analyze", "load_project", "scan_dir"]
