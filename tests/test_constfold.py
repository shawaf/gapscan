"""Constant reasoning for the data-flow tracer: conditions, if/else branches, containers.

The rule throughout: answer only when certain; otherwise None, so the tracer keeps its broader
(safer) answer. A wrong "constant" is the costly mistake, because it can dismiss a real bug."""

from __future__ import annotations

from pathlib import Path

from gapscan.context import constfold as cf
from gapscan.context.flow import trace_flow
from gapscan.context.treesitter import enclosing_function, parse


def test_conditions_are_evaluated_only_when_every_operand_is_known():
    known = {"num": 106, "flag": True}.get
    assert cf.eval_condition("(7 * 18) + num > 200", "java", known) is True
    assert cf.eval_condition("(7 * 42) - num > 200", "python", known) is False
    assert cf.eval_condition("flag && num < 0", "java", known) is False
    assert cf.eval_condition("!(num == 106)", "javascript", known) is False
    assert cf.eval_condition("user > 200", "java", known) is None  # unknown operand
    assert cf.eval_condition("len(x) > 2", "python", known) is None  # calls are not evaluated
    assert cf.eval_condition("num / 0 > 1", "java", known) is None


def test_java_integer_division_truncates():
    assert cf.eval_condition("(500 / 42) + num > 200", "java", {"num": 189}.get) is False
    assert cf.eval_condition("(500 / 42) + num > 200", "python", {"num": 189}.get) is True


def test_ternaries_split_at_the_top_level_only():
    assert cf.split_ternary('c > 1 ? "a" : f(x ? 1 : 2)', "java") == (
        "c > 1 ",
        ' "a" ',
        " f(x ? 1 : 2)",
    )
    assert cf.split_ternary("'a' if n > 1 else b", "python") == ("n > 1", "'a'", "b")
    assert cf.split_ternary("a ?? b", "javascript") is None
    assert cf.split_ternary("obj?.field", "javascript") is None


def test_branches_of_block_and_one_line_ifs():
    py = ["def f():", "\tif 7 * 42 - num > 200:", "\t\tbar = 'x'", "\telse:", "\t\tbar = p"]
    assert cf.branch_of(py, 3, 1) == ("7 * 42 - num > 200", True)
    assert cf.branch_of(py, 5, 1) == ("7 * 42 - num > 200", False)
    java = ["void f() {", "  if ((500 / 42) + num > 200) bar = p;", '  else bar = "x";',
            "  if (a) {", "    y = 1;", "  } else if (b) {", "    y = 2;", "  }"]  # fmt: skip
    assert cf.branch_of(java, 2, 1) == ("(500 / 42) + num > 200", True)
    assert cf.branch_of(java, 3, 1) == ("(500 / 42) + num > 200", False)
    assert cf.branch_of(java, 5, 1) == ("a", True)
    assert cf.branch_of(java, 7, 1) is None  # else-if chains are not modeled


def test_containers_are_simulated_in_straight_line_code_only():
    lines = ["def f():", "\tlst = []", "\tlst.append('safe')", "\tlst.append(p)",
             "\tlst.append('more')", "\tlst.pop(0)", "\tbar = lst[1]"]  # fmt: skip
    assert cf.element(lines, "lst", 2, "[]", 7, 1, "python") == ("'more'", 5)
    assert cf.element(lines, "lst", 2, "[]", 7, 0, "python") == ("p", 4)
    branchy = ["def f():", "\tlst = []", "\tif x:", "\t\tlst.append(p)", "\tbar = lst[0]"]
    assert cf.element(branchy, "lst", 2, "[]", 5, 0, "python") is None
    passed = ["def f():", "\tlst = []", "\tlst.append('a')", "\tfill(lst)", "\tbar = lst[0]"]
    assert cf.element(passed, "lst", 2, "[]", 5, 0, "python") is None  # unknown use: give up
    by_value = ["def f():", "\tlst = ['a', p]", "\tlst.remove('a')", "\tbar = lst[0]"]
    assert cf.element(by_value, "lst", 2, "['a', p]", 4, 0, "python") is None
    java = ["void f() {", "  java.util.HashMap<String,Object> m = new java.util.HashMap<String,Object>();",
            '  m.put("keyA", "safe");', '  m.put("keyB", param);', '  bar = (String) m.get("keyA");']  # fmt: skip
    created = "new java.util.HashMap<String,Object>()"
    assert cf.element(java, "m", 2, created, 5, "keyA", "java") == ('"safe"', 3)
    assert cf.element(java, "m", 2, created, 5, "keyB", "java") == ("param", 4)


def _flow(tmp_path: Path, name: str, src: str, line: int):
    (tmp_path / name).write_text(src)
    pf = parse(name, (tmp_path / name).read_bytes())
    fn = enclosing_function(pf, line)
    assert fn is not None
    return trace_flow(pf, fn, line, line, tmp_path)


def test_a_branch_that_never_runs_carries_no_request_data(tmp_path):
    src = """from flask import request
import os

def run():
    param = request.args.get("p")
    num = 86
    if 7 * 42 - num > 200:
        bar = 'This_should_always_happen'
    else:
        bar = param
    os.system("echo " + bar)
"""
    flow = _flow(tmp_path, "a.py", src, 11)
    assert flow is not None and flow.status == "constant", flow.lines
    live = src.replace("num = 86", "num = 100")  # 294 - 100 > 200 is false: else runs
    assert _flow(tmp_path, "b.py", live, 11).status == "request"


def test_java_ternary_in_an_inner_class_helper(tmp_path):
    src = """class T {
  void doPost(HttpServletRequest request) {
    String param = request.getParameter("p");
    String bar = new Test().doSomething(request, param);
    Runtime.getRuntime().exec("echo " + bar);
  }
  private class Test {
    public String doSomething(HttpServletRequest request, String param) {
      String bar;
      int num = 106;
      bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
      return bar;
    }
  }
}
"""
    flow = _flow(tmp_path, "T.java", src, 5)
    assert flow is not None and flow.status == "constant", flow.lines
    unsafe = src.replace("int num = 106;", "int num = 6;")
    assert _flow(tmp_path, "U.java", unsafe, 5).status == "request"


def test_appending_to_a_string_is_not_an_overwrite(tmp_path):
    src = """from flask import request
import os

def run():
    param = request.args.get("p")
    s = 'help'
    s += param
    s += 'snapes on a plane'
    bar = s[4:-17]
    os.system("echo " + bar)
"""
    flow = _flow(tmp_path, "c.py", src, 10)
    assert flow is not None and flow.status == "request", flow.lines


def test_a_later_plain_assignment_replaces_the_value(tmp_path):
    src = """from flask import request
import os

def run():
    bar = request.args.get("p")
    bar = "fixed"
    os.system("echo " + bar)
"""
    flow = _flow(tmp_path, "d.py", src, 7)
    assert flow is not None and flow.status == "constant", flow.lines
