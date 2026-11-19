"""Heuristic marking of untrusted input sources inside a function (a hint for the model,
not a taint analysis)."""

from __future__ import annotations

import re

from ..models import UntrustedSource

_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("http_param", re.compile(
        r"request\.(args|form|json|data|values|files|cookies|headers|GET|POST|body|query_params|query_string|get_json|get_data)\b|"
        r"\breq\.(query|body|params|headers|cookies)\b|\bctx\.(query|request|params)\b|"
        r"getParameter\(|getHeader\(|getQueryString\(|@(RequestParam|PathVariable|RequestBody|RequestHeader)\b|"
        r"\.(FormValue|PostFormValue)\(|r\.URL\.Query\(|\.URL\.Query\(\)|c\.(Query|Param|PostForm)\(|"
        r"call\.(receive|parameters)\b|request\.(uri|url)\.query|queryParameters|request\.params\b|"
        r"\.getRequest\b|switchToHttp\(|\.(?:header|headers)\[|getRequestURI\(|getInputStream\(",
        re.IGNORECASE)),
    ("env", re.compile(
        r"os\.environ|os\.getenv|process\.env\b|System\.getenv\(|os\.Getenv\(|"
        r"ProcessInfo\.processInfo\.environment|Platform\.environment|\bgetenv\(")),
    ("cli_arg", re.compile(
        r"sys\.argv|argparse|process\.argv|\bos\.Args\b|CommandLine\.arguments|"
        r"\bargs\[\d+\]|main\(\s*(final\s+)?(List<String>|args)")),
    ("stdin", re.compile(
        r"\binput\(|sys\.stdin|readLine\(|readline\(|process\.stdin|bufio\.NewReader\(os\.Stdin")),
    ("file_read", re.compile(
        r"\bopen\([^)]*\)|\.read(Text|Bytes|AllBytes|Lines|File|FileSync)?\(|Files\.read|"
        r"os\.ReadFile|ioutil\.ReadFile|File\([^)]*\)\.(read|readAs)|fs\.read")),
]  # fmt: skip


def find_untrusted_sources(
    code_lines: list[tuple[int, str]], limit: int = 12
) -> list[UntrustedSource]:
    """`code_lines` is [(line_number, text)]. At most one hit per line per kind."""
    out: list[UntrustedSource] = []
    for number, text in code_lines:
        for kind, pattern in _RULES:
            if pattern.search(text):
                out.append(UntrustedSource(kind=kind, line=number, text=text.strip()[:160]))
        if len(out) >= limit:
            break
    return out[:limit]
