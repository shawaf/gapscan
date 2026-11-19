"""Constant folding for conditions, switch selectors and collection keys.

The taint engine asks "is this expression a compile-time constant, and which?" so that it can skip
branches that never run (`if ((7 * 42) - num > 200)` with `num = 86`), pick the one `switch` case
that runs, and track collections by literal key or index. Only what is certain is folded: anything
unknown returns UNKNOWN and the engine falls back to the conservative path (both branches).

Java, Python and JavaScript/TypeScript node shapes. Text only, nothing is executed.
"""

from __future__ import annotations

import operator
from collections.abc import Callable, Mapping
from typing import Any

from tree_sitter import Node

from ..context.treesitter import ParsedFile


class _Unknown:
    def __repr__(self) -> str:
        return "UNKNOWN"


UNKNOWN: Any = _Unknown()

_INT_TYPES = frozenset({"decimal_integer_literal", "integer", "number"})
_STR_TYPES = frozenset({"string_literal", "string"})
_BIN_TYPES = frozenset(
    {"binary_expression", "binary_operator", "comparison_operator", "boolean_operator"}
)
_ARITH: dict[str, Callable[[Any, Any], Any]] = {
    "+": operator.add, "-": operator.sub, "*": operator.mul, "%": operator.mod,
    "==": operator.eq, "!=": operator.ne, "<": operator.lt, ">": operator.gt,
    "<=": operator.le, ">=": operator.ge, "===": operator.eq, "!==": operator.ne,
}  # fmt: skip
_MAX_STR = 10_000


def _text(pf: ParsedFile, n: Node) -> str:
    return pf.text(n)


def _string_value(pf: ParsedFile, n: Node) -> Any:
    """The value of a plain string literal, UNKNOWN for interpolated or prefixed ones."""
    parts: list[str] = []
    for c in n.named_children:
        if c.type in ("string_fragment", "string_content"):
            parts.append(_text(pf, c))
        elif c.type in ("string_start", "string_end"):
            if c.type == "string_start" and _text(pf, c).lower().strip("'\"") not in ("", "r", "u"):
                return UNKNOWN  # f-strings, bytes
        elif c.type == "escape_sequence":
            esc = _text(pf, c)
            parts.append(
                {"\\n": "\n", "\\t": "\t", "\\\\": "\\", "\\'": "'", '\\"': '"'}.get(esc, esc)
            )
        else:
            return UNKNOWN  # interpolation
    return "".join(parts)


def _char_value(text: str) -> Any:
    inner = text[1:-1]
    if len(inner) == 1:
        return inner
    return {"\\n": "\n", "\\t": "\t", "\\\\": "\\", "\\'": "'", '\\"': '"'}.get(inner, UNKNOWN)


def _binop(op: str, a: Any, b: Any) -> Any:
    if a is UNKNOWN or b is UNKNOWN:
        if op in ("&&", "and") and (a is False or b is False):
            return False
        if op in ("||", "or") and (a is True or b is True):
            return True
        return UNKNOWN
    try:
        if op in ("in", "not in") and isinstance(b, str) and isinstance(a, str):
            return (a in b) if op == "in" else (a not in b)
        if op in ("&&", "and"):
            return bool(a) and bool(b)
        if op in ("||", "or"):
            return bool(a) or bool(b)
        if op == "/":
            if isinstance(a, int) and isinstance(b, int):
                return UNKNOWN if b == 0 else int(a / b)  # Java/JS-like truncation for ints
            return a / b
        if op == "//":
            return a // b
        fn = _ARITH.get(op)
        if fn is None:
            return UNKNOWN
        if op == "+" and isinstance(a, str) != isinstance(b, str):
            return (
                str(a) + str(b) if not isinstance(a, bool) and not isinstance(b, bool) else UNKNOWN
            )
        out = fn(a, b)
        if isinstance(out, str) and len(out) > _MAX_STR:
            return UNKNOWN
        return out
    except (TypeError, ValueError, ZeroDivisionError, OverflowError):
        return UNKNOWN


def _method(name: str, recv: Any, args: list[Any]) -> Any:
    """String methods that are pure and common in conditions and selectors."""
    if not isinstance(recv, str) or any(a is UNKNOWN for a in args):
        return UNKNOWN
    try:
        if name == "charAt" and len(args) == 1 and isinstance(args[0], int):
            return recv[args[0]] if 0 <= args[0] < len(recv) else UNKNOWN
        if name == "length" and not args:
            return len(recv)
        if name in ("equals", "contentEquals") and len(args) == 1:
            return recv == args[0]
        if name == "equalsIgnoreCase" and len(args) == 1 and isinstance(args[0], str):
            return recv.lower() == args[0].lower()
        if name in ("startsWith", "startswith") and len(args) == 1:
            return recv.startswith(args[0])
        if name in ("endsWith", "endswith") and len(args) == 1:
            return recv.endswith(args[0])
        if name in ("toUpperCase", "upper") and not args:
            return recv.upper()
        if name in ("toLowerCase", "lower") and not args:
            return recv.lower()
        if name in ("trim", "strip") and not args:
            return recv.strip()
        if name in ("indexOf", "find") and len(args) == 1 and isinstance(args[0], str):
            return recv.find(args[0])
        if name == "substring" and 1 <= len(args) <= 2 and all(isinstance(a, int) for a in args):
            return recv[args[0] : args[1]] if len(args) == 2 else recv[args[0] :]
    except (IndexError, TypeError):
        return UNKNOWN
    return UNKNOWN


def fold(pf: ParsedFile, node: Node | None, consts: Mapping[str, Any]) -> Any:
    """The constant value of `node`, or UNKNOWN."""
    if node is None:
        return UNKNOWN
    t = node.type
    if t in _INT_TYPES:
        txt = _text(pf, node).rstrip("lL").replace("_", "")
        try:
            return (
                int(txt, 0)
                if not ("." in txt or "e" in txt.lower() and not txt.startswith("0x"))
                else float(txt)
            )
        except ValueError:
            return UNKNOWN
    if t in ("decimal_floating_point_literal", "float"):
        try:
            return float(_text(pf, node).rstrip("fFdD"))
        except ValueError:
            return UNKNOWN
    if t in ("hex_integer_literal",):
        try:
            return int(_text(pf, node).rstrip("lL"), 16)
        except ValueError:
            return UNKNOWN
    if t in _STR_TYPES:
        return _string_value(pf, node)
    if t == "character_literal":
        return _char_value(_text(pf, node))
    if t == "true":
        return True
    if t == "false":
        return False
    if t == "identifier":
        return consts.get(_text(pf, node), UNKNOWN)
    if t in ("parenthesized_expression", "cast_expression"):
        inner = node.child_by_field_name("value") or (
            node.named_children[-1] if node.named_children else None
        )
        return fold(pf, inner, consts)
    if t in _BIN_TYPES:
        kids = node.children
        if len(kids) == 3:
            op = " ".join(_text(pf, kids[1]).split())
            return _binop(op, fold(pf, kids[0], consts), fold(pf, kids[2], consts))
        return UNKNOWN
    if t in ("unary_expression", "not_operator", "unary_operator"):
        operand = node.child_by_field_name("operand") or node.child_by_field_name("argument")
        val = fold(pf, operand, consts)
        op = _text(pf, node.children[0]) if node.children else ""
        if val is UNKNOWN:
            return UNKNOWN
        if op in ("!", "not"):
            return not val
        if op == "-" and isinstance(val, int | float):
            return -val
        return UNKNOWN
    if t == "method_invocation":
        obj = node.child_by_field_name("object")
        name_node = node.child_by_field_name("name")
        name = _text(pf, name_node) if name_node is not None else ""
        args_node = node.child_by_field_name("arguments")
        args = [fold(pf, a, consts) for a in (args_node.named_children if args_node else [])]
        return _method(name, fold(pf, obj, consts), args)
    if t in ("call", "call_expression"):
        fn = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        args = [fold(pf, a, consts) for a in (args_node.named_children if args_node else [])]
        if fn is not None and fn.type in ("attribute", "member_expression"):
            obj = fn.child_by_field_name("object")
            attr = fn.child_by_field_name("attribute") or fn.child_by_field_name("property")
            return _method(_text(pf, attr) if attr else "", fold(pf, obj, consts), args)
        if (
            fn is not None
            and _text(pf, fn) == "len"
            and len(args) == 1
            and isinstance(args[0], str)
        ):
            return len(args[0])
        return UNKNOWN
    if t in ("subscript", "subscript_expression"):
        base = fold(
            pf, node.child_by_field_name("value") or node.child_by_field_name("object"), consts
        )
        idx = fold(
            pf, node.child_by_field_name("subscript") or node.child_by_field_name("index"), consts
        )
        if (
            isinstance(base, str)
            and isinstance(idx, int)
            and not isinstance(idx, bool)
            and -len(base) <= idx < len(base)
        ):
            return base[idx]
        return UNKNOWN
    if t in ("field_access", "member_expression", "attribute"):
        prop = node.child_by_field_name("field") or node.child_by_field_name("property")
        if prop is not None and _text(pf, prop) == "length":
            val = fold(pf, node.child_by_field_name("object"), consts)
            return len(val) if isinstance(val, str) else UNKNOWN
        return UNKNOWN
    return UNKNOWN


def truth(value: Any) -> bool | None:
    """True/False when a folded condition is decided, None when it is not."""
    if value is UNKNOWN or value is None:
        return None
    if isinstance(value, bool | int | float | str):
        return bool(value)
    return None
