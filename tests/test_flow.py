from __future__ import annotations

from pathlib import Path

from gapscan.agent.triage import apply_policy, build_verdict
from gapscan.context.extract import build_context
from gapscan.context.flow import call_args, idents, sink_values, split_top, trace_flow
from gapscan.context.treesitter import enclosing_function, parse
from gapscan.models import Category, Finding, Severity, TriageAnswer, Verdict, VerdictLabel


def flow_for(tmp_path: Path, rel: str, line: int, files: dict[str, str]):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    pf = parse(rel, (tmp_path / rel).read_bytes())
    fn = enclosing_function(pf, line)
    assert fn is not None
    return trace_flow(pf, fn, line, line, tmp_path)


def test_idents_skip_members_callees_keys_types_and_keywords():
    assert idents('cur.execute("SELECT " + name + f"{other}")') == ["cur", "name", "other"]
    assert idents("join(this.base, userId, { recursive: true })") == ["userId"]
    assert idents("Paths.get(root).resolve(child)") == ["root", "child"]
    assert idents("run(cmd, shell=True)") == ["cmd"]
    assert idents("send({ ...basePayload, ts: now })") == ["basePayload", "now"]
    assert idents("`/x/${userId}/${n}`") == ["userId", "n"]


def test_argument_helpers():
    assert split_top("a, f(b, c), [d, e], g<h, i>(j)") == ["a", "f(b, c)", "[d, e]", "g<h, i>(j)"]
    assert call_args("x = run(a, b(c, d), e)", "run") == ["a", "b(c, d)", "e"]
    assert call_args("nothing here", "run") is None
    assert sink_values(['    cur.execute("SELECT " + name)'], 1, 1) == ["name"]


def test_python_flow_reaches_the_request_through_a_caller(tmp_path):
    src = """from flask import Flask, request
app = Flask(__name__)

def run_query(db, term):
    return db.execute("SELECT * FROM t WHERE x = '" + term + "'")

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return str(run_query(app.db, q))
"""
    flow = flow_for(tmp_path, "app.py", 5, {"app.py": src})
    assert flow and flow.status == "request"
    text = "\n".join(flow.lines)
    assert "parameter 2 of `run_query`" in text and "called by `search`" in text
    assert "REQUEST INPUT" in text and "request.args" in text and "RESULT: request" in text


def test_literal_only_values_are_constant(tmp_path):
    src = """def lookup(db):
    table = "users"
    col = "email"
    return db.execute("SELECT " + col + " FROM " + table)
"""
    flow = flow_for(tmp_path, "a.py", 4, {"a.py": src})
    assert flow and flow.status == "constant" and "RESULT: every value" in flow.lines[-1]


def test_helper_that_returns_a_literal_makes_the_value_constant(tmp_path):
    src = """def pick(param):
    return "fixed"

def handler(request, cur):
    param = request.args.get("x")
    bar = pick(param)
    cur.execute("SELECT * FROM t WHERE a = '" + bar + "'")
"""
    flow = flow_for(tmp_path, "a.py", 7, {"a.py": src})
    assert flow and flow.status == "constant"
    assert any("always returns a literal" in line for line in flow.lines)


def test_a_sanitizer_on_the_path_is_reported_and_does_not_force_a_review(tmp_path):
    src = """import html
from flask import request, make_response

def page():
    name = html.escape(request.args.get("name", ""))
    return make_response("<p>" + name + "</p>")
"""
    flow = flow_for(tmp_path, "a.py", 6, {"a.py": src})
    assert flow and flow.status == "sanitized"
    assert any("SANITIZER" in line for line in flow.lines)


def test_typescript_closure_and_decorated_handler(tmp_path):
    controller = """import { Controller, Get, Param } from '@nestjs/common'
@Controller('logs')
export class LogsController {
  constructor(private readonly svc: LogsService) {}

  @Get(':userId/download')
  download(@Param('userId') userId: string) {
    return this.svc.read(userId)
  }
}
"""
    service = """import { readFile } from 'fs/promises'
import { join } from 'path'
export class LogsService {
  async read(userId: string) {
    const task = async () => {
      const file = join('/var/logs', userId)
      return readFile(file, 'utf8')
    }
    return task()
  }
}
"""
    files = {"logs.controller.ts": controller, "logs.service.ts": service}
    flow = flow_for(tmp_path, "logs.service.ts", 7, files)
    assert flow and flow.status == "request"
    text = "\n".join(flow.lines)
    assert "called by `LogsController.download`" in text and "@Param('userId')" in text


def test_java_servlet_parameters_are_request_input(tmp_path):
    src = """public class T extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getParameter("x");
        String sql = "SELECT * FROM t WHERE a='" + param + "'";
        stmt.executeQuery(sql);
    }
}
"""
    flow = flow_for(tmp_path, "T.java", 5, {"T.java": src})
    assert flow and flow.status == "request"


def test_untraceable_values_are_reported_as_unknown_and_failures_never_raise(tmp_path):
    src = """def f():
    return db.execute(build_query(some_global))
"""
    flow = flow_for(tmp_path, "a.py", 2, {"a.py": src})
    assert flow and flow.status == "unknown"
    pf = parse("a.py", b"def f(:\n  ???", "python")
    assert (
        pf is not None
        and trace_flow(pf, enclosing_function(pf, 1) or _dummy(), 1, 1, tmp_path) is None
    )


def _dummy():
    from gapscan.context.treesitter import FunctionInfo

    return FunctionInfo("f", "f", 1, 2, "def f(", 1)


def finding(path="a.py", line=5, category=Category.CODE):
    return Finding(scanner="semgrep", rule_id="x.sql", title="t", severity=Severity.HIGH,
                   category=category, cwe=["CWE-89"], file=path, start_line=line)  # fmt: skip


def verdict(label):
    return Verdict(finding_id="x", verdict=label, confidence=0.95, reasoning="r")


def test_policy_does_not_block_a_dismissal_just_because_request_input_reaches_the_line():
    f = finding()
    for status in ("", "unknown", "sanitized", "request"):
        v = apply_policy(f, verdict(VerdictLabel.FALSE_POSITIVE), flow_status=status)
        assert v.verdict == VerdictLabel.FALSE_POSITIVE and v.policy_notes == []


def test_policy_overrules_a_confirmation_when_every_value_is_a_literal():
    f = finding()
    v = apply_policy(f, verdict(VerdictLabel.TRUE_POSITIVE), flow_status="constant")
    assert v.verdict == VerdictLabel.FALSE_POSITIVE and v.confidence <= 0.7
    assert "literal" in v.policy_notes[-1]
    assert (
        apply_policy(f, verdict(VerdictLabel.TRUE_POSITIVE), flow_status="request").verdict
        == VerdictLabel.TRUE_POSITIVE
    )


def test_build_context_attaches_the_flow_and_renders_it(tmp_path):
    (tmp_path / "app.py").write_text("""from flask import request

def go(cur):
    term = request.args.get("q")
    cur.execute("SELECT * FROM t WHERE a = '" + term + "'")
""")
    ctx = build_context(finding("app.py", 5), tmp_path)
    assert ctx.flow_status == "request"
    rendered = ctx.render()
    assert "DATA FLOW TO THE FLAGGED LINE" in rendered and "RESULT: request" in rendered
    # weak-algorithm findings are judged by what is chosen, so no flow is traced for them
    weak = finding("app.py", 5).model_copy(update={"cwe": ["CWE-327"]})
    assert build_context(weak, tmp_path).flow == []


def test_build_verdict_passes_the_flow_status_to_the_policy():
    f = finding()
    answer = TriageAnswer(verdict=VerdictLabel.TRUE_POSITIVE, confidence=0.9, reasoning="real")
    v = build_verdict(f, answer, "p", "m", flow_status="constant")
    assert v.verdict == VerdictLabel.FALSE_POSITIVE


# --- found on BenchmarkPython (dev set): values that reach a sink through containers -----------


def test_a_list_filled_after_creation_is_not_a_constant(tmp_path):
    src = """from flask import request
import subprocess

def run():
    param = request.form.get("p")
    bar = param
    args = []
    args.append("sh")
    args.append(f"echo {bar}")
    return subprocess.run(args, capture_output=True)
"""
    flow = flow_for(tmp_path, "app.py", 10, {"app.py": src})
    assert flow is not None and flow.status == "request", flow.lines


def test_a_list_filled_only_with_literals_stays_constant(tmp_path):
    src = """import subprocess

def run():
    args = []
    args.append("ls")
    args.append("-l")
    return subprocess.run(args)
"""
    flow = flow_for(tmp_path, "app.py", 7, {"app.py": src})
    assert flow is not None and flow.status == "constant", flow.lines


def test_dict_items_and_fstrings_with_spaces_are_followed(tmp_path):
    src = """from flask import request
import os

def run():
    param = request.args.get("p")
    m = {}
    m["a"] = "fixed"
    m["b"] = param
    cmd = f"echo {m['b']} done"
    os.system(cmd)
"""
    flow = flow_for(tmp_path, "app.py", 10, {"app.py": src})
    assert flow is not None and flow.status == "request", flow.lines


def test_loop_variables_and_the_flask_request_object_are_traced(tmp_path):
    src = """from flask import request
import os

def run():
    name = ""
    for key in request.form.keys():
        name = key
    os.system("echo " + name)

def wrapped():
    w = make_wrapper(request)
    os.system("echo " + w)
"""
    assert flow_for(tmp_path, "app.py", 8, {"app.py": src}).status == "request"
    assert flow_for(tmp_path, "app.py", 12, {"app.py": src}).status == "request"


def test_fstring_fields_are_identifiers_and_escaped_braces_are_not():
    assert idents('f"echo {bar}"') == ["bar"]
    assert idents('f"{a}-{b.c!r:>10}"') == ["a", "b"]
    assert idents('f"literal {{braces}}"') == []
