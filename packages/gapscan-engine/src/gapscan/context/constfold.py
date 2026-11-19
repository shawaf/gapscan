"""Small, conservative constant reasoning for the data-flow tracer (context/flow.py).

Decides, from source text only, three things a reviewer works out by hand:
- whether a condition whose operands are all known is always true or always false
  (`(7 * 18) + num > 200` with `num = 106`), so only the branch that runs carries data;
- which branch of an `if`/`else` (block or one-line) an assignment sits in;
- which element of a list or map built in straight-line code a literal-index read returns
  (`lst = ['safe', param, 'x']; lst.pop(0); bar = lst[1]` reads 'x').

Every function answers None when it is not sure; callers then keep their old, broader behavior.
Nothing is executed: conditions are parsed with `ast` and only arithmetic, comparisons and boolean
operators on numeric or boolean literals are evaluated.
"""

from __future__ import annotations

import ast
import operator
import re
from collections.abc import Callable

Value = int | float | bool
_INT_DIVISION = {"java", "kotlin", "go", "csharp", "c", "cpp", "scala"}


# --------------------------------------------------------------------------- conditions

_IDENT = re.compile(r"(?<![\w$.'\"])([A-Za-z_$][\w$]*)(?![\w$(])")
_KEEP = {"and", "or", "not", "True", "False"}


def _python_syntax(cond: str) -> str:
    c = cond.replace("&&", " and ").replace("||", " or ")
    c = re.sub(r"!(?!=)", " not ", c)
    c = re.sub(r"\btrue\b", "True", c)
    return re.sub(r"\bfalse\b", "False", c)


_BIN: dict[type, Callable[[Value, Value], Value]] = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv,
}  # fmt: skip
_CMP: dict[type, Callable[[Value, Value], bool]] = {
    ast.Lt: operator.lt, ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
    ast.Eq: operator.eq, ast.NotEq: operator.ne,
}  # fmt: skip


def _evaluate(node: ast.AST, int_division: bool) -> Value:  # noqa: PLR0911
    if isinstance(node, ast.Expression):
        return _evaluate(node.body, int_division)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, bool)):
        return node.value
    if isinstance(node, ast.UnaryOp):
        v = _evaluate(node.operand, int_division)
        if isinstance(node.op, ast.Not):
            return not v
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.UAdd):
            return +v
    if isinstance(node, ast.BinOp):
        a, b = _evaluate(node.left, int_division), _evaluate(node.right, int_division)
        if isinstance(node.op, ast.Div):
            if b == 0:
                raise ValueError("division by zero")
            if int_division and isinstance(a, int) and isinstance(b, int):
                return int(a / b)  # Java-style: truncate toward zero
            return a / b
        if type(node.op) in _BIN:
            if isinstance(node.op, (ast.Mod, ast.FloorDiv)) and b == 0:
                raise ValueError("division by zero")
            return _BIN[type(node.op)](a, b)
    if isinstance(node, ast.BoolOp):
        values = [bool(_evaluate(v, int_division)) for v in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.Compare) and all(type(op) in _CMP for op in node.ops):
        left = _evaluate(node.left, int_division)
        for op, right_node in zip(node.ops, node.comparators, strict=True):
            right = _evaluate(right_node, int_division)
            if not _CMP[type(op)](left, right):
                return False
            left = right
        return True
    raise ValueError("not a constant expression")


def eval_condition(
    cond: str, language: str, value_of: Callable[[str], Value | None]
) -> bool | None:
    """True/False when every operand of `cond` is known, else None."""
    text = _python_syntax(cond.strip()).strip()
    if not text or len(text) > 200:
        return None
    unknown = False

    def substitute(m: re.Match[str]) -> str:
        nonlocal unknown
        name = m.group(1)
        if name in _KEEP:
            return name
        value = value_of(name)
        if value is None:
            unknown = True
            return name
        return repr(value)

    text = _IDENT.sub(substitute, text)
    if unknown:
        return None
    try:
        result = _evaluate(ast.parse(text, mode="eval"), language in _INT_DIVISION)
    except (SyntaxError, ValueError, TypeError, ZeroDivisionError, RecursionError):
        return None
    return bool(result)


_NUMBER = re.compile(r"^-?\d+(\.\d+)?[lLfFdD]?$")


def literal_number(text: str) -> Value | None:
    t = text.strip().rstrip(";").strip()
    if _NUMBER.match(t):
        t = t.rstrip("lLfFdD")
        return float(t) if "." in t else int(t)
    if t in ("true", "True"):
        return True
    if t in ("false", "False"):
        return False
    return None


# --------------------------------------------------------------------------- ternaries


def _top_level(text: str, char: str, start: int = 0) -> int:
    depth, quote = 0, ""
    i = start
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == char and depth == 0:
            return i
        i += 1
    return -1


def split_ternary(text: str, language: str) -> tuple[str, str, str] | None:
    """(condition, value if true, value if false) of a top-level conditional expression."""
    t = text.strip().rstrip(";").strip()
    if language == "python":
        m = re.match(r"^(?P<a>.+?)\s+if\s+(?P<c>.+?)\s+else\s+(?P<b>.+)$", t, re.S)
        if not m or not (_balanced(m.group("a")) and _balanced(m.group("c"))):
            return None
        return m.group("c"), m.group("a"), m.group("b")
    q = _top_level(t, "?")
    if q < 0 or t[q + 1 : q + 2] in ("?", ".", ":"):  # ?? and ?. are not ternaries
        return None
    colon = _top_level(t, ":", q + 1)
    if colon < 0:
        return None
    return t[:q], t[q + 1 : colon], t[colon + 1 :]


def _balanced(text: str) -> bool:
    return sum(text.count(c) for c in "([{") == sum(text.count(c) for c in ")]}")


# --------------------------------------------------------------------------- if / else branches


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _condition_after_if(text: str) -> str | None:
    """`if (cond) ...` -> cond (balanced parentheses)."""
    m = re.match(r"\s*(?:\}\s*)?if\s*\(", text)
    if not m:
        return None
    start = m.end() - 1
    depth = 0
    for i in range(start, len(text)):
        depth += {"(": 1, ")": -1}.get(text[i], 0)
        if depth == 0:
            return text[start + 1 : i]
    return None


def _skip(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith(("#", "//", "/*", "*"))


def branch_of(lines: list[str], n: int, lo: int) -> tuple[str, bool] | None:
    """The condition guarding line `n` (1-based) and whether the line runs when it is true
    (`then` branch) or false (`else` branch). None when unclear (elif chains, loops, switch...)."""
    line = lines[n - 1]
    stripped = line.strip()
    # One-line Java/JS forms: `if (c) x = ...;` and `else x = ...;`
    if re.match(r"(?:\}\s*)?if\s*\(", stripped):
        cond = _condition_after_if(stripped)
        rest = stripped[stripped.find(cond) + len(cond) + 1 :].strip() if cond is not None else ""
        return (cond, True) if cond is not None and rest and not rest.startswith("{") else None
    if re.match(r"(?:\}\s*)?else\b(?!\s*if\b)", stripped) and not stripped.rstrip().endswith(
        ("{", ":")
    ):
        for k in range(n - 1, lo - 1, -1):
            prev = lines[k - 1]
            if _skip(prev):
                continue
            cond = _condition_after_if(prev.strip())
            if cond is not None and _indent(prev) == _indent(line):
                return cond, False
            return None
        return None
    # Block forms: the nearest less-indented header above.
    me = _indent(line)
    for k in range(n - 1, lo - 1, -1):
        head = lines[k - 1]
        if _skip(head) or _indent(head) >= me:
            continue
        h = head.strip()
        if re.match(r"(?:\}\s*)?(else\s+if|elif)\b", h):
            return None
        if re.match(r"if\b", h) and h.endswith(":"):  # Python
            return h[2:-1].strip(), True
        if re.match(r"(?:\}\s*)?if\s*\(", h) and h.endswith("{"):
            cond = _condition_after_if(h)
            return (cond, True) if cond is not None else None
        if re.match(r"(?:\}\s*)?else\b", h) and h.endswith(("{", ":")):
            for j in range(k - 1, lo - 1, -1):
                prev = lines[j - 1]
                if _skip(prev) or _indent(prev) > _indent(head):
                    continue
                if _indent(prev) < _indent(head):
                    return None
                p = prev.strip()
                if re.match(r"(?:\}\s*)?(else\s+if|elif)\b", p):
                    return None
                if re.match(r"if\b", p) and p.endswith(":"):
                    return p[2:-1].strip(), False
                cond = _condition_after_if(p)
                if cond is not None:
                    return cond, False
                if p.startswith("}"):
                    continue  # the closing brace of the then-block
                return None
            return None
        return None  # a loop, try, switch, function header...: not an if/else we understand
    return None


# --------------------------------------------------------------------------- containers

_LIST_NEW = re.compile(
    r"^(\[\s*\]|list\(\s*\)|new\s+[\w.]*(ArrayList|LinkedList|Vector)\b.*\(\s*\))$"
)
_MAP_NEW = re.compile(
    r"^(\{\s*\}|dict\(\s*\)|new\s+[\w.]*(HashMap|LinkedHashMap|TreeMap|Hashtable)\b.*\(\s*\))$"
)
_LITERAL_KEY = re.compile(r"""^(-?\d+|"[^"\\]*"|'[^'\\]*')$""")


def _key(text: str) -> str | int | None:
    t = text.strip()
    if not _LITERAL_KEY.match(t):
        return None
    return int(t) if t.lstrip("-").isdigit() else t[1:-1]


def read_of(text: str) -> tuple[str, str | int] | None:
    """`name[KEY]` or `name.get(KEY)` with a literal key -> (name, key)."""
    t = text.strip().rstrip(";").strip()
    m = re.match(r"^([A-Za-z_$][\w$]*)\s*(?:\[(.+)\]|\.\s*get\s*\((.+)\))$", t)
    if not m:
        return None
    key = _key(m.group(2) if m.group(2) is not None else m.group(3))
    return (m.group(1), key) if key is not None else None


def _args(text: str) -> list[str]:
    out, depth, cur, quote = [], 0, "", ""
    for c in text:
        if quote:
            cur += c
            if c == quote:
                quote = ""
            continue
        if c in "\"'":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def element(
    lines: list[str], name: str, created_at: int, created_as: str, read_line: int, key: str | int,
    language: str,
) -> tuple[str, int] | None:  # fmt: skip
    """The expression stored at `key` when `name` is read on `read_line`, simulating the straight
    line code between its creation and the read. None at the first statement it does not model."""
    rhs = created_as.strip().rstrip(";").strip()
    items: list[tuple[str, int]]
    mapping: dict[str | int, tuple[str, int]] | None = None
    if _LIST_NEW.match(rhs):
        items = []
    elif rhs.startswith("[") and rhs.endswith("]") and _balanced(rhs):
        items = [(a, created_at) for a in _args(rhs[1:-1])]
    elif _MAP_NEW.match(rhs):
        items, mapping = [], {}
    else:
        return None
    indent = _indent(lines[created_at - 1])
    word = re.compile(rf"(?<![\w$.]){re.escape(name)}(?![\w$])")
    for n in range(created_at + 1, read_line):
        line = lines[n - 1]
        if _skip(line) or not word.search(line):
            continue
        if _indent(line) != indent:
            return None  # inside a branch or loop: the order of operations is not certain
        s = line.strip().rstrip(";").strip()
        call = re.match(rf"^{re.escape(name)}\s*\.\s*(\w+)\s*\((.*)\)$", s)
        store = re.match(rf"^{re.escape(name)}\s*\[(.+?)\]\s*=(?!=)\s*(.+)$", s)
        if mapping is not None:
            if call and call.group(1) == "put" and len(_args(call.group(2))) == 2:
                k, v = _args(call.group(2))
                if _key(k) is None:
                    return None
                mapping[_key(k)] = (v, n)  # type: ignore[index]
            elif store and _key(store.group(1)) is not None:
                mapping[_key(store.group(1))] = (store.group(2), n)  # type: ignore[index]
            elif call and call.group(1) == "clear" and not call.group(2).strip():
                mapping.clear()
            elif read_of(s.split("=", 1)[-1]) is not None:
                continue  # another read of the map
            else:
                return None
            continue
        if call:
            op, args = call.group(1), _args(call.group(2))
            if op in ("append", "add", "push") and len(args) == 1:
                items.append((args[0], n))
            elif op in ("insert", "add") and len(args) == 2 and isinstance(_key(args[0]), int):
                items.insert(int(_key(args[0])), (args[1], n))  # type: ignore[arg-type]
            elif op == "pop" and not args and items:
                items.pop()
            elif op in ("pop", "remove") and len(args) == 1 and isinstance(_key(args[0]), int):
                if op == "remove" and language == "python":
                    return None  # Python's list.remove() removes by value
                i = int(_key(args[0]))  # type: ignore[arg-type]
                if not -len(items) <= i < len(items):
                    return None
                items.pop(i)
            elif op == "clear" and not args:
                items.clear()
            else:
                return None
        elif read_of(s.split("=", 1)[-1]) is not None and not store:
            continue  # a read, e.g. `x = lst[0]`
        else:
            return None
    if mapping is not None:
        return mapping.get(key)
    if not isinstance(key, int) or not -len(items) <= key < len(items):
        return None
    return items[key]
