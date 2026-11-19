"""Parsing and scope lookup with tree-sitter for the supported target languages.

Hard rule #1: this only *parses* source text. Nothing from the scanned project is ever
executed, built or imported. Parsers are error-tolerant, so broken or partial files still
yield usable (if approximate) scopes.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import NamedTuple

from tree_sitter import Language, Node, Parser, Tree

_JS_FUNCS = frozenset({
    "function_declaration", "method_definition", "arrow_function", "function_expression",
    "generator_function_declaration",
})  # fmt: skip


class _Spec(NamedTuple):
    module: str
    func: str  # name of the language factory inside the module
    extensions: tuple[str, ...]
    function_types: frozenset[str]  # function-like nodes (Dart pairs signature + body instead)
    import_types: frozenset[str]


_SPECS: dict[str, _Spec] = {
    "python": _Spec("tree_sitter_python", "language", (".py",), frozenset({"function_definition"}),
                    frozenset({"import_statement", "import_from_statement"})),
    "javascript": _Spec("tree_sitter_javascript", "language", (".js", ".jsx", ".mjs", ".cjs"),
                        _JS_FUNCS, frozenset({"import_statement"})),
    "typescript": _Spec("tree_sitter_typescript", "language_typescript", (".ts", ".mts", ".cts"),
                        _JS_FUNCS, frozenset({"import_statement"})),
    "tsx": _Spec("tree_sitter_typescript", "language_tsx", (".tsx",), _JS_FUNCS,
                 frozenset({"import_statement"})),
    "java": _Spec("tree_sitter_java", "language", (".java",),
                  frozenset({"method_declaration", "constructor_declaration"}),
                  frozenset({"import_declaration"})),
    "kotlin": _Spec("tree_sitter_kotlin", "language", (".kt", ".kts"),
                    frozenset({"function_declaration"}), frozenset({"import"})),
    "go": _Spec("tree_sitter_go", "language", (".go",),
                frozenset({"function_declaration", "method_declaration"}),
                frozenset({"import_declaration"})),
    "swift": _Spec("tree_sitter_swift", "language", (".swift",),
                   frozenset({"function_declaration", "init_declaration"}),
                   frozenset({"import_declaration"})),
    "dart": _Spec("tree_sitter_dart", "language", (".dart",), frozenset(),
                  frozenset({"import_or_export"})),
}  # fmt: skip

# Languages whose callers can call each other (JS/TS/TSX share a module system).
FAMILIES = {"javascript": "js", "typescript": "js", "tsx": "js"}

EXTENSIONS: dict[str, str] = {ext: lang for lang, spec in _SPECS.items() for ext in spec.extensions}
_BODY_TYPES = frozenset({
    "block", "statement_block", "function_body", "class_body", "constructor_body", "body",
})  # fmt: skip


def family(language: str) -> str:
    return FAMILIES.get(language, language)


def detect_language(path: str | Path) -> str | None:
    return EXTENSIONS.get(Path(path).suffix.lower())


@cache
def _parser(language: str) -> Parser:
    spec = _SPECS[language]
    return Parser(Language(getattr(importlib.import_module(spec.module), spec.func)()))


@dataclass
class ParsedFile:
    path: str
    language: str
    source: bytes
    tree: Tree
    lines: list[str] = field(default_factory=list)

    def text(self, node: Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def parse(path: str, source: bytes, language: str | None = None) -> ParsedFile | None:
    language = language or detect_language(path)
    if language is None or language not in _SPECS:
        return None
    tree = _parser(language).parse(source)
    return ParsedFile(path, language, source, tree, source.decode("utf-8", "replace").splitlines())


@dataclass
class FunctionInfo:
    name: str
    qualified_name: str  # Class.method where a class encloses it
    start_line: int  # 1-based, inclusive (decorators/signature included)
    end_line: int
    signature: str
    body_start_line: int


def _walk(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _first(node: Node, types: set[str] | frozenset[str]) -> Node | None:
    return next((c for c in node.children if c.type in types), None)


_NAME_TYPES = frozenset(
    {"identifier", "simple_identifier", "property_identifier", "field_identifier"}
)


def _fn_name(pf: ParsedFile, node: Node) -> str:
    named = node.child_by_field_name("name")
    if named is None:
        named = _first(node, _NAME_TYPES)
    if named is None and node.type in ("arrow_function", "function_expression", "function"):
        parent = node.parent
        if parent is not None and parent.type in (
            "variable_declarator",
            "pair",
            "assignment_expression",
        ):
            named = parent.child_by_field_name("name") or parent.child_by_field_name("key") \
                or parent.child_by_field_name("left")  # fmt: skip
    return pf.text(named) if named is not None else "<anonymous>"


_CLASS_TYPES = frozenset({
    "class_definition", "class_declaration", "class", "interface_declaration", "struct_declaration",
    "enum_declaration", "object_declaration", "extension_declaration", "mixin_declaration",
})  # fmt: skip


def _class_name(pf: ParsedFile, node: Node) -> str | None:
    named = node.child_by_field_name("name") or _first(node, _NAME_TYPES | {"type_identifier"})
    return pf.text(named) if named is not None else None


def _qualify(pf: ParsedFile, node: Node, name: str) -> str:
    parts = []
    p = node.parent
    while p is not None:
        if p.type in _CLASS_TYPES and (cn := _class_name(pf, p)):
            parts.append(cn)
        p = p.parent
    return ".".join([*reversed(parts), name])


def _body_node(node: Node) -> Node | None:
    body = node.child_by_field_name("body")
    return body or _first(node, _BODY_TYPES)


def _make_info(pf: ParsedFile, node: Node, start: Node, body: Node | None) -> FunctionInfo:
    name = _fn_name(pf, node)
    sig_start = start.start_byte
    sig_end = body.start_byte if body is not None else node.end_byte
    sig = pf.source[sig_start:sig_end].decode("utf-8", "replace").strip()
    return FunctionInfo(
        name=name,
        qualified_name=_qualify(pf, node, name),
        start_line=start.start_point[0] + 1,
        end_line=(body or node).end_point[0] + 1,
        signature=sig[:300],
        body_start_line=(body.start_point[0] + 1) if body is not None else start.start_point[0] + 1,
    )


def functions(pf: ParsedFile) -> list[FunctionInfo]:
    """Every function/method defined in the file, outermost first."""
    out: list[FunctionInfo] = []
    fn_types = _SPECS[pf.language].function_types
    for node in _walk(pf.tree.root_node):
        if node.type in fn_types:
            # Python decorators live on the parent: keep them (they show routes/auth).
            start = (
                node.parent
                if node.parent is not None and node.parent.type == "decorated_definition"
                else node
            )
            out.append(_make_info(pf, node, start, _body_node(node)))
        elif pf.language == "dart" and node.type == "function_body":
            sig = node.prev_named_sibling
            while sig is not None and sig.type == "comment":
                sig = sig.prev_named_sibling
            if sig is not None and sig.type in ("function_signature", "method_signature"):
                info = _make_info(pf, sig, sig, node)
                info.end_line = node.end_point[0] + 1
                info.qualified_name = _qualify(pf, sig, _dart_name(pf, sig))
                info.name = _dart_name(pf, sig)
                out.append(info)
    return out


def _dart_name(pf: ParsedFile, sig: Node) -> str:
    for n in _walk(sig):
        if n.type == "identifier":
            return pf.text(n)
    return "<anonymous>"


def enclosing_function(pf: ParsedFile, line: int) -> FunctionInfo | None:
    """The innermost function containing the 1-based `line`, or None at module level."""
    best: FunctionInfo | None = None
    for fn in functions(pf):
        if fn.start_line <= line <= fn.end_line and (
            best is None or (fn.end_line - fn.start_line) <= (best.end_line - best.start_line)
        ):
            best = fn
    return best


def imports(pf: ParsedFile) -> list[str]:
    types = _SPECS[pf.language].import_types
    out = [pf.text(n).strip() for n in _walk(pf.tree.root_node) if n.type in types]
    if pf.language in ("javascript", "typescript", "tsx"):  # CommonJS require()
        out += [
            ln.strip()
            for ln in pf.lines
            if "require(" in ln and ln.lstrip().startswith(("const", "var", "let"))
        ]
    return out


@dataclass
class CallSite:
    name: str
    line: int  # 1-based
    text: str


def _last_name(pf: ParsedFile, node: Node | None) -> str | None:
    """Rightmost identifier of a (possibly dotted) callee expression."""
    if node is None:
        return None
    if node.type in _NAME_TYPES:
        return pf.text(node)
    for field_name in ("attribute", "property", "field", "name"):
        child = node.child_by_field_name(field_name)
        if child is not None:
            return _last_name(pf, child)
    ids = [c for c in node.children if c.type in _NAME_TYPES or c.type == "navigation_suffix"]
    return _last_name(pf, ids[-1]) if ids else None


def calls(pf: ParsedFile) -> list[CallSite]:
    """Call expressions with the called function/method name (receiver types not resolved)."""
    out: list[CallSite] = []
    lang = pf.language
    for node in _walk(pf.tree.root_node):
        name: str | None = None
        if (lang == "python" and node.type == "call") or (
            lang in ("javascript", "typescript", "tsx", "go") and node.type == "call_expression"
        ):
            name = _last_name(pf, node.child_by_field_name("function"))
        elif lang == "java" and node.type == "method_invocation":
            name = _last_name(pf, node.child_by_field_name("name"))
        elif lang in ("kotlin", "swift") and node.type == "call_expression" and node.children:
            name = _last_name(pf, node.children[0])
        elif lang == "dart" and node.type == "selector" and _first(node, {"argument_part"}):
            prev = node.prev_sibling
            if prev is not None and prev.type == "identifier":
                name = pf.text(prev)
            elif prev is not None and prev.type == "selector":
                name = _last_name(pf, _first(prev, {"unconditional_assignable_selector"}))
        if name:
            line = node.start_point[0] + 1
            out.append(
                CallSite(name, line, pf.lines[line - 1].strip() if line <= len(pf.lines) else "")
            )
    return out


def module_definitions(pf: ParsedFile) -> dict[str, tuple[int, int]]:
    """Top-level constant/variable definitions of a file: name -> (first line, last line), 1-based.

    These matter for review because allowlists, validators and base paths usually live at module
    level, outside the function a finding points into. Python, JavaScript/TypeScript and Go."""
    root = pf.tree.root_node
    out: dict[str, tuple[int, int]] = {}

    def add(name: str, node: Node) -> None:
        out.setdefault(name, (node.start_point[0] + 1, node.end_point[0] + 1))

    for node in root.children:
        if pf.language == "python" and node.type == "expression_statement":
            for child in node.children:
                if child.type == "assignment":
                    left = child.child_by_field_name("left")
                    if left is not None and left.type == "identifier":
                        add(pf.text(left), node)
        elif pf.language in ("javascript", "typescript", "tsx") and node.type in (
            "lexical_declaration", "variable_declaration",
        ):  # fmt: skip
            for decl in node.children:
                name = (
                    decl.child_by_field_name("name") if decl.type == "variable_declarator" else None
                )
                if name is not None and name.type == "identifier":
                    add(pf.text(name), node)
        elif pf.language == "go" and node.type in ("const_declaration", "var_declaration"):
            for spec in _walk(node):
                if spec.type in ("const_spec", "var_spec"):
                    name = spec.child_by_field_name("name")
                    if name is not None:
                        add(pf.text(name), node)
    return out


def class_ranges(pf: ParsedFile) -> list[tuple[str, int, int]]:
    """(name, first line, last line) for every class/interface/struct-like declaration."""
    out: list[tuple[str, int, int]] = []
    for node in _walk(pf.tree.root_node):
        if node.type in _CLASS_TYPES and (name := _class_name(pf, node)):
            out.append((name, node.start_point[0] + 1, node.end_point[0] + 1))
    return out
