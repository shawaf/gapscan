from __future__ import annotations

from gapscan.fingerprint import assign_stable_ids, normalize_text
from gapscan.models import Category, Finding, ScanResult, Severity
from gapscan.normalize import normalize

CODE = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n    return 1\n"


def code(scanner="semgrep", rule="r", line=5, cwe=("CWE-78",), file="a.py", **kw):
    return Finding(scanner=scanner, rule_id=rule, title="t", severity=Severity.HIGH,
                   category=kw.pop("category", Category.CODE), cwe=list(cwe), file=file,
                   start_line=line, end_line=line, **kw)  # fmt: skip


def ids(findings, target):
    assign_stable_ids(findings, target)
    return [f.id for f in findings]


def test_id_survives_code_moving_down(tmp_path):
    (tmp_path / "a.py").write_text(CODE)
    before = ids([code(line=5)], tmp_path)
    (tmp_path / "a.py").write_text("# new header\n# more\n" + CODE)  # everything shifts by 2
    after = ids([code(line=7)], tmp_path)
    assert before == after


def test_id_survives_reformatting_but_not_a_code_change(tmp_path):
    (tmp_path / "a.py").write_text(CODE)
    base = ids([code()], tmp_path)
    (tmp_path / "a.py").write_text(CODE.replace("    os.system(cmd)", "        os.system(  cmd )"))
    assert ids([code()], tmp_path) == base
    (tmp_path / "a.py").write_text(CODE.replace("os.system(cmd)", "os.popen(cmd)"))
    assert ids([code()], tmp_path) != base


def test_merged_finding_id_does_not_depend_on_scanner_order(tmp_path):
    (tmp_path / "a.py").write_text(CODE)
    a, b = code("semgrep", "r1"), code("bandit", "B605")
    one = normalize(ScanResult(target="t", findings=[a, b]), tmp_path).findings
    two = normalize(ScanResult(target="t", findings=[b, a]), tmp_path).findings
    assert len(one) == len(two) == 1 and one[0].id == two[0].id
    assert set(one[0].sources) == {"semgrep", "bandit"}


def test_identical_issues_get_distinct_ids_that_keep_line_order(tmp_path):
    (tmp_path / "a.py").write_text("os.system(x)\nfoo()\nos.system(x)\n")
    first, second = code(line=1, rule="r"), code(line=3, rule="r")
    a = ids([first, second], tmp_path)
    assert a[0] != a[1]
    (tmp_path / "a.py").write_text("# top\nos.system(x)\nfoo()\nos.system(x)\n")
    b = ids([code(line=2, rule="r"), code(line=4, rule="r")], tmp_path)
    assert a == b  # same two issues, same order, same IDs after the shift


def test_different_files_and_rules_differ(tmp_path):
    (tmp_path / "a.py").write_text(CODE)
    (tmp_path / "b.py").write_text(CODE)
    assert (
        len(set(ids([code(file="a.py"), code(file="b.py"), code(cwe=("CWE-89",))], tmp_path))) == 3
    )


def test_secret_ids_never_depend_on_secret_content(tmp_path):
    (tmp_path / "c.py").write_text('TOKEN = "value-one"\n')
    s = lambda: Finding(scanner="gitleaks", rule_id="github-pat", title="t", severity=Severity.HIGH,  # noqa: E731
                        category=Category.SECRET, file="c.py", start_line=1, end_line=1, cwe=["CWE-798"])  # fmt: skip
    first = ids([s()], tmp_path)
    (tmp_path / "c.py").write_text('TOKEN = "a-different-value"\n')  # rotated secret, same issue
    assert ids([s()], tmp_path) == first


def test_dependency_ids_ignore_scanner_and_line(tmp_path):
    def dep(scanner, rule):
        return Finding(scanner=scanner, rule_id=rule, title="t", severity=Severity.HIGH,
                       category=Category.DEPENDENCY, package="django", version="3.0.0",
                       cve=["CVE-2021-1"], file="requirements.txt")  # fmt: skip

    assert ids([dep("osv", "GHSA-1")], tmp_path) == ids([dep("trivy", "CVE-2021-1")], tmp_path)
    other_version = dep("osv", "GHSA-1").model_copy(update={"version": "3.1.0"})
    assert ids([other_version], tmp_path) != ids([dep("osv", "GHSA-1")], tmp_path)


def test_normalize_text_drops_bandit_line_prefixes():
    assert (
        normalize_text("10 subprocess.call(cmd,   shell=True)\n11 x")
        == "subprocess.call(cmd,shell=True)x"
    )
