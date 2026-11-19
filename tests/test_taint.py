"""Taint engine: labeled corpora (caught sinks, no false alarms, safe flows stay clean), summaries
across files, framework models, and the scanner adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from gapscan.models import Category
from gapscan.taint.bench import score, score_labeled
from gapscan.taint.engine import scan_dir
from gapscan.taint.scanner import TaintScanner, hit_to_finding
from gapscan.taint.specs import build_model

CORPUS = Path(__file__).parent / "taint"
LABELED = Path(__file__).parent.parent / "eval" / "fixtures" / "labeled"


@pytest.mark.parametrize("lang", ["java", "python", "js"])
def test_corpus_recall_and_no_false_alarms(lang: str) -> None:
    sc = score(CORPUS / lang)
    assert sc.missed == [], sc.missed
    assert sc.false_alarms == [], sc.false_alarms
    assert sc.safe_flow_leaks == [], sc.safe_flow_leaks
    assert sc.expected >= 9


def test_independent_labeled_fixtures() -> None:
    r = score_labeled(LABELED)
    assert r["caught"] >= 21 and r["vulnerable"] == 22  # zip-slip reads archive data: out of scope
    assert r["bait_flagged"] == 0, r["flagged_bait"]


def test_cross_file_path_is_reported(tmp_path: Path) -> None:
    (tmp_path / "A.java").write_text(
        "import javax.servlet.http.*;\n"
        "class A { void f(HttpServletRequest r) throws Exception {\n"
        '  String v = r.getParameter("x");\n  B.go(Pass.id(v));\n} }\n'
    )
    (tmp_path / "B.java").write_text(
        "class B { static void go(String s) throws Exception {\n"
        "  Runtime.getRuntime().exec(s);\n} }\n"
    )
    (tmp_path / "Pass.java").write_text("class Pass { static String id(String s) { return s; } }\n")
    hits = scan_dir(tmp_path)
    assert [(h.kind, h.file, h.line) for h in hits] == [("cmd", "B.java", 2)]
    h = hits[0]
    assert h.source_file == "A.java" and h.cross_file
    assert any("Pass" in s or "id()" in s for s in h.steps) and "B.java:2" in h.steps[-1]


def test_sanitizer_and_cast_remove_taint(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os, subprocess\nfrom flask import request\n"
        "def a():\n    subprocess.run(int(request.args['n']))\n"
        "def b():\n    subprocess.run(os.path.basename(request.args['n']))\n"
        "def c():\n    subprocess.run(request.args['n'])\n"
    )
    assert [h.line for h in scan_dir(tmp_path)] == [8]


def test_branch_assignment_keeps_taint_but_top_level_overwrite_clears(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n"
        "def a(flag):\n    v = request.args['n']\n    if flag:\n        v = 'x'\n    os.system(v)\n"
        "def b():\n    v = request.args['n']\n    v = 'x'\n    os.system(v)\n"
    )
    assert [h.line for h in scan_dir(tmp_path)] == [7]


def test_framework_model_applies_only_when_imported() -> None:
    assert "python-flask" in build_model("python", "from flask import Flask").names
    assert "python-flask" not in build_model("python", "import os").names
    assert "java-spring" in build_model("java", "import org.springframework.web.bind;").names


def test_operator_sources_do_not_report_path_findings(tmp_path: Path) -> None:
    (tmp_path / "cfg.py").write_text(
        "import os\nopen(os.environ['CONF'])\nos.system(os.environ['C'])\n"
    )
    assert [h.kind for h in scan_dir(tmp_path)] == ["cmd"]


def test_scanner_adapter_makes_findings_with_evidence(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\nos.system(request.args['c'])\n"
    )
    s = TaintScanner()
    assert s.is_available()
    (f,) = s.run(tmp_path, tmp_path)
    assert f.scanner == "taint" and f.rule_id == "gapscan.taint.cmd"
    assert f.cwe == ["CWE-78"] and f.category == Category.CODE and f.file == "app.py"
    assert f.start_line == 3 and f.snippet and "taint_path" in f.raw
    assert "http_param" in f.message
    assert hit_to_finding(scan_dir(tmp_path)[0]).id == f.id  # stable ids


def test_broken_files_do_not_stop_the_scan(tmp_path: Path) -> None:
    (tmp_path / "bad.java").write_bytes(b"class {{{ \xff\xfe")
    (tmp_path / "ok.py").write_text(
        "import os\nfrom flask import request\nos.system(request.args['c'])\n"
    )
    assert len(scan_dir(tmp_path)) == 1


def test_every_matching_sanitizer_counts(tmp_path: Path) -> None:
    """`shlex.quote` also matches the generic URL/HTML `quote` entry: both must apply."""
    (tmp_path / "app.py").write_text(
        "import os, shlex\nfrom flask import request\nos.system('ping ' + shlex.quote(request.args['h']))\n"
    )
    assert scan_dir(tmp_path) == []


def test_merging_with_another_scanner_keeps_the_taint_path() -> None:
    """Semgrep and the taint engine often flag the same line: the data-flow evidence must survive."""
    from gapscan.models import Category, Finding, Severity
    from gapscan.normalize import deduplicate

    sg = Finding(
        scanner="semgrep",
        rule_id="x",
        title="t",
        severity=Severity.HIGH,
        category=Category.CODE,
        cwe=["CWE-78"],
        file="a.py",
        start_line=3,
        end_line=3,
        sources=["semgrep"],
    )
    tf = Finding(
        scanner="taint",
        rule_id="gapscan.taint.cmd",
        title="t",
        severity=Severity.CRITICAL,
        category=Category.CODE,
        cwe=["CWE-78"],
        file="a.py",
        start_line=3,
        end_line=3,
        sources=["taint"],
        raw={"taint_path": ["a at a.py:2", "b at a.py:3"], "cross_file": False},
    )
    (merged,) = deduplicate([sg, tf])
    assert merged.sources == ["semgrep", "taint"] and merged.severity == Severity.CRITICAL
    assert merged.raw["taint_path"] == ["a at a.py:2", "b at a.py:3"]


def test_chained_assignment_is_linear(tmp_path: Path) -> None:
    """`o1 = o2 = ... = o40 = source` once took 2^40 steps (each level was evaluated twice)."""
    import time

    names = ", ".join(f"o{i}" for i in range(1, 41))
    chain = " = ".join(f"o{i}" for i in range(1, 41))
    (tmp_path / "A.java").write_text(
        "import javax.servlet.http.*;\nclass A { void f(HttpServletRequest r, HttpServletResponse w) throws Exception {\n"
        f'  Object {names};\n  {chain} = r.getParameter("x");\n  w.getWriter().println(o37);\n}} }}\n'
    )
    t = time.monotonic()
    hits = scan_dir(tmp_path)
    assert time.monotonic() - t < 5
    assert [(h.kind, h.line) for h in hits] == [("xss", 5)]


def test_template_xss_only_where_the_template_prints_unescaped(tmp_path: Path) -> None:
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "page.html").write_text(
        "<p>{{ safe_q }}</p><p>{{ raw_q|safe }}</p>{% autoescape off %}{{ off_q }}{% endautoescape %}"
    )
    (tmp_path / "views.py").write_text(
        "from django.shortcuts import render\n"
        "def v(request):\n"
        "    q = request.GET.get('q')\n"
        "    return render(request, 'page.html', {'safe_q': q, 'raw_q': q, 'off_q': 'x'})\n"
        "def w(request):\n"
        "    q = request.GET.get('q')\n"
        "    return render(request, 'page.html', {'safe_q': q})\n"
    )
    assert [(h.kind, h.line) for h in scan_dir(tmp_path)] == [
        ("xss", 4)
    ]  # raw_q only; w() is escaped


def test_nestjs_decorated_parameters_are_sources(tmp_path: Path) -> None:
    (tmp_path / "users.controller.ts").write_text("""
import { Controller, Get, Query, Param, Body, Post, Res } from '@nestjs/common';
import { exec } from 'child_process';

@Controller('users')
export class UsersController {
  @Get('search')
  search(@Query('name') name: string) {
    return this.dataSource.query(`SELECT * FROM users WHERE name = '${name}'`);
  }
  @Post('ping')
  ping(@Body() body: { host: string }) {
    exec('ping -c 1 ' + body.host);
  }
  @Get(':id')
  byId(@Param('id') id: number) {
    return this.dataSource.query(`SELECT * FROM users WHERE id = ${id}`);
  }
  @Get(':slug')
  bySlug(@Param('slug') slug: string) {
    return this.articles.findOne({ slug });
  }
  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.users.findOne(dto);
  }
  @Get('f/:path')
  file(@Param('path') path: string, @Res() res) {
    return res.sendFile(path, { root: './files' });
  }
  @Get('raw/:path')
  raw(@Param('path') path: string, @Res() res) {
    return res.sendFile(path);
  }
  @Get('profile')
  async profile(@Query('token') token: string) {
    const url = new URL('https://graph.facebook.com/me');
    url.searchParams.set('access_token', token);
    return fetch(url.toString());
  }
}
""")
    hits = {(h.cwe, h.line) for h in scan_dir(tmp_path)}
    assert ("CWE-89", 9) in hits and ("CWE-78", 13) in hits  # query and body are sources
    assert not any(line == 17 for _, line in hits)  # a number cannot inject
    assert ("CWE-943", 21) not in hits  # a route parameter is a string, not an operator object
    assert ("CWE-943", 25) in hits  # the whole body as a query filter
    assert ("CWE-22", 29) not in hits and ("CWE-22", 33) in hits  # sendFile with root is safe
    assert not any(cwe == "CWE-918" for cwe, _ in hits)  # a query parameter cannot change the host
