from __future__ import annotations

import json
from pathlib import Path

import pytest

from gapscan.context.budget import estimate_tokens, fit_to_budget
from gapscan.context.callgraph import find_callers
from gapscan.context.extract import build_context
from gapscan.context.sources import find_untrusted_sources
from gapscan.context.treesitter import (
    calls,
    detect_language,
    enclosing_function,
    imports,
    parse,
)
from gapscan.models import Category, CodeContext, Finding, Severity
from gapscan.scanners.sarif import parse_sarif

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "eval" / "fixtures" / "vuln-app"

# language -> (file name, source, line inside `target`, expected name, expected import fragment)
SAMPLES = {
    "python": ("a.py", "import os\nfrom x import y\n\n\nclass C:\n    @route('/p')\n    def target(self, q):\n        return run(q)\n\n\ndef other():\n    return C().target(1)\n", 8, "C.target", "import os"),
    "javascript": ("a.js", "import fs from 'fs';\nclass K {\n  target(q) {\n    return run(q);\n  }\n}\nconst other = () => new K().target(1);\n", 4, "K.target", "import fs"),
    "typescript": ("a.ts", "import { x } from './x';\nfunction target(q: string): string {\n  return run(q);\n}\nfunction other() { return target('a'); }\n", 3, "target", "import { x }"),
    "tsx": ("a.tsx", "import React from 'react';\nconst target = (q: string) => {\n  return run(q);\n};\nconst Other = () => <div>{target('a')}</div>;\n", 3, "target", "import React"),
    "java": ("A.java", "import java.io.File;\nclass A {\n  String target(String q) {\n    return run(q);\n  }\n  void other() { target(\"a\"); }\n}\n", 4, "A.target", "import java.io.File"),
    "kotlin": ("A.kt", "import java.io.File\n\nclass A {\n  fun target(q: String): String {\n    return run(q)\n  }\n  fun other() {\n    target(\"a\")\n  }\n}\n", 5, "A.target", "import"),
    "go": ("a.go", "package p\n\nimport \"os\"\n\nfunc (s S) target(q string) string {\n\treturn run(q)\n}\n\nfunc other() {\n\ts.target(\"a\")\n}\n", 6, "target", "import \"os\""),
    "swift": ("a.swift", "import Foundation\n\nclass A {\n  func target(q: String) -> String {\n    return run(q)\n  }\n  func other() {\n    target(q: \"a\")\n  }\n}\n", 5, "A.target", "import Foundation"),
    "dart": ("a.dart", "import 'dart:io';\n\nclass A {\n  String target(String q) {\n    return run(q);\n  }\n  void other() {\n    target('a');\n  }\n}\n", 5, "A.target", "import 'dart:io'"),
}  # fmt: skip


@pytest.mark.parametrize("lang", SAMPLES)
def test_scope_imports_and_calls_per_language(lang):
    name, src, line, qualified, imp = SAMPLES[lang]
    assert detect_language(name) == lang
    pf = parse(name, src.encode())
    assert pf is not None
    fn = enclosing_function(pf, line)
    assert fn is not None, lang
    assert fn.qualified_name.endswith(qualified) or fn.name == qualified.split(".")[-1], (lang, fn)
    assert fn.start_line <= line <= fn.end_line
    assert any(imp in i for i in imports(pf)), (lang, imports(pf))
    sites = {c.name for c in calls(pf)}
    assert {"run", "target"} <= sites, (lang, sites)


@pytest.mark.parametrize("lang", SAMPLES)
def test_callers_found_per_language(lang, tmp_path):
    name, src, line, _, _ = SAMPLES[lang]
    (tmp_path / name).write_text(src)
    pf = parse(name, src.encode())
    fn = enclosing_function(pf, line)
    callers = find_callers(
        tmp_path, fn.name, lang, name, exclude_lines=(fn.start_line, fn.end_line)
    )
    assert callers, lang
    assert callers[0].file == name and callers[0].function.lower().endswith("other"), (
        lang,
        callers,
    )


def test_python_signature_keeps_decorators():
    pf = parse("a.py", SAMPLES["python"][1].encode())
    fn = enclosing_function(pf, 8)
    assert "@route('/p')" in fn.signature and "def target(self, q)" in fn.signature
    assert enclosing_function(pf, 1) is None  # module level


def test_nested_function_picks_innermost():
    src = "def outer():\n    def inner():\n        return 1\n    return inner\n"
    pf = parse("a.py", src.encode())
    assert enclosing_function(pf, 3).name == "inner"
    assert enclosing_function(pf, 4).name == "outer"


def test_unknown_language_and_broken_files_do_not_crash():
    assert parse("README.md", b"# hi") is None
    pf = parse("bad.py", b"def (((:\n  x = \n")
    assert pf is not None  # tolerant parsing: broken files still parse, with errors


def test_callers_skip_recursion_vendor_and_respect_limit(tmp_path):
    (tmp_path / "a.py").write_text(
        "def f(n):\n    return f(n - 1)\n\n\ndef g():\n    f(1)\n    f(2)\n    f(3)\n"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.py").write_text("f(9)\n")
    callers = find_callers(tmp_path, "f", "python", "a.py", max_callers=2, exclude_lines=(1, 2))
    assert [c.line for c in callers] == [6, 7]  # not line 2 (recursion), not vendored, capped at 2
    assert find_callers(tmp_path, "nonexistent_fn", "python", "a.py") == []
    assert find_callers(tmp_path, "<anonymous>", "python", "a.py") == []


def test_callers_name_match_is_confirmed_by_syntax(tmp_path):
    # `f` appears in a string and a comment only: grep matches, tree-sitter must reject.
    (tmp_path / "a.py").write_text("# call f(1) later\nx = 'f(2)'\n")
    assert find_callers(tmp_path, "f", "python", "a.py") == []


def test_untrusted_sources():
    code = [
        (1, "name = request.args.get('name')"),
        (2, "token = os.environ['TOKEN']"),
        (3, "data = open(path).read()"),
        (4, "cmd = sys.argv[1]"),
        (5, "x = compute(1)"),
        (6, 'val := r.URL.Query().Get("q")'),
    ]
    kinds = [(u.line, u.kind) for u in find_untrusted_sources(code)]
    assert (1, "http_param") in kinds and (2, "env") in kinds and (3, "file_read") in kinds
    assert (4, "cli_arg") in kinds and (6, "http_param") in kinds and all(k[0] != 5 for k in kinds)


def _finding(file="app.py", start=32, end=32, **kw):
    return Finding(scanner="s", rule_id="r", title="t", severity=Severity.HIGH, category=Category.CODE,
                   file=file, start_line=start, end_line=end, **kw)  # fmt: skip


def test_done_when_vulnerable_function_and_a_caller_on_the_real_fixture():
    """Phase 3 'done when', using the real Semgrep finding for the weak MD5 hash."""
    data = json.loads((ROOT / "tests" / "data" / "semgrep.sarif").read_text())
    md5 = next(f for f in parse_sarif(data, FIXTURE, "semgrep") if "md5" in f.rule_id)
    ctx = build_context(md5, FIXTURE)
    assert ctx.language == "python" and ctx.function_name == "hash_password"
    assert "hashlib.md5" in ctx.code and f">>{md5.start_line:>5}" in ctx.code
    assert [c.function for c in ctx.callers] == ["register", "test_x"]  # non-test caller first
    assert "from flask import Flask, request" in ctx.imports[-1] or any(
        "hashlib" in i for i in ctx.imports
    )
    text = ctx.render()
    assert "ENCLOSING FUNCTION: def hash_password(pw)" in text and "register" in text


def test_context_for_route_handler_marks_untrusted_input():
    ctx = build_context(_finding(start=16, end=16), FIXTURE)
    assert ctx.function_name == "user"
    assert "@app.route" in (ctx.function_signature or "")
    assert [u.kind for u in ctx.untrusted_sources] == ["http_param"]


def test_context_without_location_or_unreadable_file():
    dep = Finding(scanner="osv", rule_id="x", title="t", severity=Severity.LOW,
                  category=Category.DEPENDENCY, package="p")  # fmt: skip
    assert "no code context" in build_context(dep, FIXTURE).note
    assert "not readable" in build_context(_finding(file="nope.py"), FIXTURE).note


def test_context_refuses_paths_outside_the_target(tmp_path):
    secret = tmp_path / "outside.py"
    secret.write_text("TOP = 'secret'\n")
    target = tmp_path / "t"
    target.mkdir()
    (target / "link.py").symlink_to(secret)
    assert "not readable" in build_context(_finding(file="link.py", start=1, end=1), target).note
    assert (
        "not readable" in build_context(_finding(file="../outside.py", start=1, end=1), target).note
    )


def test_large_function_is_shown_as_signature_plus_window(tmp_path):
    body = "".join(f"    x{i} = {i}\n" for i in range(200))
    (tmp_path / "big.py").write_text("def huge():\n" + body)
    ctx = build_context(_finding(file="big.py", start=100, end=100), tmp_path, window=3)
    assert "def huge():" in ctx.code and "..." in ctx.code
    assert ">>  100" in ctx.code and "x150" not in ctx.code
    assert ctx.function_name == "huge"


def test_budget_trims_in_priority_order_and_keeps_the_finding(tmp_path):
    body = "".join(f"    line_{i} = compute({i})\n" for i in range(70))
    src = "import os\nimport sys\n\n\ndef target():\n" + body + "\n\ndef caller():\n    target()\n"
    (tmp_path / "m.py").write_text(src)
    finding = _finding(file="m.py", start=40, end=40)
    full = build_context(finding, tmp_path, budget_tokens=100_000)
    assert not full.trimmed and full.callers
    small = build_context(finding, tmp_path, budget_tokens=300)
    assert (
        estimate_tokens(small.render()) <= 300 + 200
    )  # may overshoot only by the unremovable core
    assert small.trimmed and ">>   40 |" in small.code
    assert len(small.code) < len(full.code)
    order = small.trimmed
    assert order.index("imports") < order.index("function body")


def test_budget_noop_when_it_already_fits():
    ctx = CodeContext(finding_id="x", file="a.py", code=">>    1 | x = 1", start_line=1, end_line=1)
    assert fit_to_budget(ctx, 1000).trimmed == []


def test_secrets_never_reach_the_model_context():
    # the fixture's fake tokens, assembled here so this file holds no token-shaped literal
    fake = ("ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5", "AKIA" + "J3XK7QW2NMLPR5ZT")
    secret = Finding(scanner="gitleaks", rule_id="github-pat", title="t", severity=Severity.HIGH,
                     category=Category.SECRET, file="config.py", start_line=2, end_line=2)  # fmt: skip
    text = build_context(secret, FIXTURE).render()
    assert not any(s in text for s in fake) and "withheld" in text
    # A non-secret finding next to secrets: token-shaped strings are masked in the window.
    other = _finding(file="config.py", start=1, end=4)
    text = build_context(other, FIXTURE).render()
    assert not any(s in text for s in fake)


def test_module_level_definitions_are_found_per_language():
    from gapscan.context.treesitter import module_definitions

    py = parse(
        "a.py",
        b"import os\nALLOWED = {'a', 'b'}\nBASE = '/srv'\n\n\ndef f():\n    return ALLOWED\n",
    )
    assert module_definitions(py) == {"ALLOWED": (2, 2), "BASE": (3, 3)}
    js = parse(
        "a.js",
        b"const ROOT = path.resolve('/srv');\nlet counter = 0;\nfunction f() { return ROOT; }\n",
    )
    assert set(module_definitions(js)) == {"ROOT", "counter"}
    go = parse(
        "a.go",
        b'package p\n\nconst Base = "/srv"\n\nvar Allowed = map[string]bool{"a": true}\n\nfunc F() {}\n',
    )
    assert set(module_definitions(go)) == {"Base", "Allowed"}
    assert (
        module_definitions(parse("A.java", b"class A { static final int X = 1; }")) == {}
    )  # not supported yet


def test_context_shows_the_module_level_definitions_the_function_uses():
    f = _finding(file="python/sqli_allowlist.py", start=12, end=12)
    ctx = build_context(f, ROOT / "eval" / "fixtures" / "labeled")
    assert len(ctx.definitions) == 1 and "SORTABLE" in ctx.definitions[0]
    text = ctx.render()
    assert "MODULE-LEVEL DEFINITIONS" in text and '"price": "price"' in text
    # a function that uses no module-level name gets none, and imports are never listed as definitions
    plain = build_context(
        _finding(file="python/sqli_param.py", start=11, end=11),
        ROOT / "eval" / "fixtures" / "labeled",
    )
    assert plain.definitions == [] and "MODULE-LEVEL" not in plain.render()
    assert (
        "ALLOWED_HOSTS"
        in build_context(
            _finding(file="python/ssrf_allowlist.py", start=12, end=12),
            ROOT / "eval" / "fixtures" / "labeled",
        ).definitions[0]
    )


def test_definitions_are_trimmed_by_the_budget_before_the_finding_itself():
    ctx = CodeContext(finding_id="x", file="a.py", start_line=5, end_line=5, code=">>    5 | x",
                      definitions=[f"    {i} | CONST_{i} = 'x' * 50" for i in range(5)])  # fmt: skip
    fit_to_budget(ctx, 40)
    assert ctx.definitions == [] and ">>    5 | x" in ctx.code and "definitions" in ctx.trimmed


def test_same_file_helpers_called_by_the_function_are_included(tmp_path):
    (tmp_path / "H.java").write_text(
        "class H {\n"
        "  void doPost(String p) {\n"
        "    String bar = new Test().doSomething(p);\n"
        '    run("SELECT " + bar);\n'
        "  }\n"
        "  private class Test {\n"
        "    String doSomething(String param) {\n"
        '      String bar = "safe";\n'
        "      return bar;\n"
        "    }\n"
        "  }\n"
        "  void unrelated() { int x = 1; }\n"
        "}\n"
    )
    f = _finding(file="H.java", start=4, end=4)
    ctx = build_context(f, tmp_path)
    assert ctx.function_name and ctx.function_name.endswith("doPost")
    assert (
        len(ctx.helpers) == 1 and 'String bar = "safe";' in ctx.helpers[0]
    )  # the helper that decides the data flow
    assert "unrelated" not in ctx.render()
    assert "HELPER FUNCTIONS CALLED FROM HERE" in ctx.render()


def test_helpers_are_trimmed_by_the_budget_before_the_finding():
    ctx = CodeContext(finding_id="x", file="a.py", start_line=5, end_line=5, code=">>    5 | x",
                      helpers=[f"    {i} | def helper{i}(): return 'x' * 80" for i in range(3)])  # fmt: skip
    fit_to_budget(ctx, 40)
    assert ">>    5 | x" in ctx.code and len(ctx.helpers) < 3 and "helpers" in ctx.trimmed
