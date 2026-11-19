"""Diff-aware scanning, policy, the CI command, SCM comments, the MCP server, integration files."""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from gapscan.ci import render_comment, run_ci
from gapscan.cli import app
from gapscan.config import Config
from gapscan.diffscan import (
    branches,
    changes_since,
    head_info,
    introduced_by_changes,
    is_repo,
    parse_diff,
)
from gapscan.mcp_server import handle, serve
from gapscan.models import Category, Finding, Severity
from gapscan.policy import Policy, PolicyRule, evaluate, load_policy
from gapscan.scm import SCMError, build_request, post_comment

ROOT = Path(__file__).resolve().parent.parent
SAFE_APP = "from flask import Flask\napp = Flask(__name__)\n"
VULN_ROUTE = (
    "import os\nfrom flask import request\n\n@app.route('/p')\ndef p():\n"
    "    h = request.args.get('h')\n    os.system('ping ' + h)\n"
)


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=a@b.c", "-c", "user.name=t", *args],
        check=True, capture_output=True,
    )  # fmt: skip


def cfg() -> Config:
    c = Config()
    c.scanners.enabled = ["taint"]
    return c


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "old.py").write_text(
        "import os\nfrom flask import request\n\ndef legacy():\n    os.system('ls ' + request.args['x'])\n"
    )  # a pre-existing finding
    (tmp_path / "app.py").write_text(SAFE_APP)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def test_head_info_reports_branch_and_commit(repo: Path) -> None:
    info = head_info(repo)
    assert info.is_repo and info.branch == "main"
    assert len(info.commit) >= 7 and not info.dirty


def test_head_info_sees_uncommitted_changes(repo: Path) -> None:
    (repo / "app.py").write_text(SAFE_APP + "# edit\n")
    assert head_info(repo).dirty is True


def test_head_info_on_a_non_repo_is_empty(tmp_path: Path) -> None:
    info = head_info(tmp_path)
    assert not info.is_repo and info.branch == "" and info.commit == ""
    assert is_repo(tmp_path) is False


def test_head_info_detached_head_has_no_branch(repo: Path) -> None:
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    git(repo, "checkout", "-q", sha)
    info = head_info(repo)
    assert info.is_repo and info.branch == ""  # detached: a commit, not a branch


def test_branches_lists_local_and_remote_refs(repo: Path) -> None:
    git(repo, "branch", "feature/x")
    git(repo, "remote", "add", "origin", str(repo))
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    refs = branches(repo)
    assert "main" in refs and "feature/x" in refs and "origin/main" in refs
    assert "origin/HEAD" not in refs  # symbolic refs are left out


def test_parse_diff_collects_added_lines() -> None:
    diff = "+++ b/a.py\n@@ -1,0 +2,2 @@\n+x = 1\n+y = 2\n+++ b/gone.py\n@@ -1 +0,0 @@\n-z\n@@ -5,0 +9 @@\n+w\n"
    ch = parse_diff(diff)
    assert ch.lines["a.py"] == [(2, "x = 1"), (3, "y = 2")]
    assert ch.touches("a.py", 3, 3) and not ch.touches("a.py", 4, 9)


def test_only_what_the_change_introduced_is_reported(repo: Path) -> None:
    (repo / "app.py").write_text(SAFE_APP + VULN_ROUTE)  # uncommitted change
    res, scan = run_ci(cfg(), repo, Policy(), base_ref="main")
    assert scan.findings and len(scan.findings) == 2  # old.py and the new route
    assert res.scanned == 2 and res.considered == 1
    assert res.rows[0][0].file == "app.py" and "introduced since main" in res.mode


def test_taint_path_through_a_changed_line_counts_as_introduced(repo: Path) -> None:
    (repo / "sink.py").write_text("import os\n\ndef run(c):\n    os.system(c)\n")
    (repo / "route.py").write_text(
        "from flask import request\nimport sink\n\n@app.route('/')\ndef r():\n    sink.run('ls')\n"
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "second")
    (repo / "route.py").write_text(
        "from flask import request\nimport sink\n\n@app.route('/')\ndef r():\n    sink.run(request.args['c'])\n"
    )  # only the call site changes; the sink line is untouched
    res, _ = run_ci(cfg(), repo, Policy(), base_ref="HEAD")
    assert [f.file for f, _, _ in res.rows] == ["sink.py"]


def test_baseline_mode_uses_stable_ids(repo: Path, tmp_path: Path) -> None:
    _, before = run_ci(cfg(), repo, Policy())
    base = tmp_path / "base.json"
    base.write_text(before.model_dump_json())
    (repo / "app.py").write_text(SAFE_APP + VULN_ROUTE)
    res, _ = run_ci(cfg(), repo, Policy(), baseline=base)
    assert res.considered == 1 and "baseline" in res.mode


def test_staged_mode(repo: Path) -> None:
    (repo / "app.py").write_text(SAFE_APP + VULN_ROUTE)
    git(repo, "add", "app.py")
    res, _ = run_ci(cfg(), repo, Policy(), staged=True)
    assert [f.file for f, _, _ in res.rows] == ["app.py"]


def f(**kw: object) -> Finding:
    base = {
        "scanner": "s",
        "rule_id": "r.x",
        "title": "t",
        "severity": Severity.HIGH,
        "category": Category.CODE,
        "file": "a/b.py",
        "start_line": 1,
    }
    return Finding(**{**base, **kw})  # type: ignore[arg-type]


def test_policy_first_match_wins_and_dismissed_never_block() -> None:
    pol = Policy(
        default="monitor",
        rule=[
            PolicyRule(name="inj", cwe=["CWE-89"], action="block"),
            PolicyRule(name="crit", severity=Severity.CRITICAL, action="block"),
            PolicyRule(rule_id="gapscan.typo*", action="comment"),
            PolicyRule(path="tests/*", action="monitor"),
        ],
    )
    sqli, crit, typo, low = (
        f(cwe=["CWE-89"]),
        f(severity=Severity.CRITICAL, rule_id="z"),
        f(rule_id="gapscan.typosquat", severity=Severity.MEDIUM),
        f(severity=Severity.LOW, rule_id="q"),
    )
    rows = {r.rule_id + str(r.cwe): (a, n) for r, a, n in evaluate(pol, [sqli, crit, typo, low])}
    assert rows["r.x['CWE-89']"] == ("block", "inj") and rows["z[]"][0] == "block"
    assert rows["gapscan.typosquat[]"][0] == "comment" and rows["q[]"] == ("monitor", "default")
    assert evaluate(pol, [sqli], dismissed={sqli.id}) == []


def test_policy_file_loading(tmp_path: Path) -> None:
    (tmp_path / "gapscan.policy.toml").write_text(
        'default = "comment"\n[[rule]]\nseverity = "critical"\naction = "block"\n'
    )
    pol = load_policy(None, tmp_path)
    assert pol.default == "comment" and pol.rule[0].severity == Severity.CRITICAL
    assert load_policy(None, tmp_path / "missing").default == "monitor"


def test_ci_cli_exit_code_and_comment(repo: Path, tmp_path: Path) -> None:
    (repo / "app.py").write_text(SAFE_APP + VULN_ROUTE)
    (repo / "gapscan.policy.toml").write_text('[[rule]]\nseverity = "critical"\naction = "block"\n')
    conf = tmp_path / "c.toml"
    conf.write_text('[scanners]\nenabled = ["taint"]\n')
    out = tmp_path / "comment.md"
    r = CliRunner().invoke(
        app,
        ["ci", "run", str(repo), "--base", "main", "--comment", str(out), "--config", str(conf)],
    )
    assert r.exit_code == 1, r.output
    text = out.read_text()
    assert "Blocking findings" in text and "app.py" in text and "Data flow" in text
    r2 = CliRunner().invoke(
        app, ["ci", "run", str(repo), "--base", "nope-ref", "--config", str(conf)]
    )
    assert r2.exit_code == 2


def test_ci_run_writes_valid_sarif(repo: Path, tmp_path: Path) -> None:
    import json

    (repo / "app.py").write_text(SAFE_APP + VULN_ROUTE)
    conf = tmp_path / "c.toml"
    conf.write_text('[scanners]\nenabled = ["taint"]\n')
    sarif = tmp_path / "out.sarif"
    r = CliRunner().invoke(
        app,
        ["ci", "run", str(repo), "--base", "main", "--sarif", str(sarif), "--config", str(conf)],
    )
    assert r.exit_code in (0, 1), r.output
    data = json.loads(sarif.read_text())
    assert data["version"] == "2.1.0" and len(data["runs"]) == 1
    assert isinstance(data["runs"][0]["results"], list)


def test_comment_text_from_the_project_is_neutralized() -> None:
    from gapscan.ci import CIResult

    evil = f(title="x`<img src=x onerror=alert(1)>|\nrow", file="a|b.py")
    md = render_comment(CIResult(1, 1, [(evil, "block", "r")]))
    assert "<img" not in md and "onerror" in md and "\nrow" not in md.split("Severity")[1]


def test_scm_requests_per_provider_and_safety(monkeypatch: pytest.MonkeyPatch) -> None:
    url, payload = build_request("github", "https://ghe.example.com/api/v3", "o/r", "7", "hi")
    assert url == "https://ghe.example.com/api/v3/repos/o/r/issues/7/comments" and "hi" in str(
        payload["body"]
    )
    assert (
        "merge_requests/9/notes"
        in build_request("gitlab", "https://gl.example.com", "12", "9", "x")[0]
    )
    assert (
        "projects/P/repos/slug/pull-requests/3/comments"
        in build_request("bitbucket", "https://bb.example.com", "P/slug", "3", "x")[0]
    )
    assert (
        "_apis/git/repositories/R/pullRequests/4/threads"
        in build_request("azure", "https://dev.example.com/org", "Proj/R", "4", "x")[0]
    )
    with pytest.raises(SCMError, match="https"):
        build_request("github", "http://ghe.example.com/api/v3", "o/r", "1", "x")
    build_request("github", "http://localhost:8080/api", "o/r", "1", "x")  # local http is fine
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(201, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setenv("TOK", "secret-token")
    post_comment("gitlab", "https://gl.example.com", "12", "9", "body", "TOK", client)
    assert seen[0].headers["PRIVATE-TOKEN"] == "secret-token"
    monkeypatch.delenv("TOK")
    with pytest.raises(SCMError, match="TOK"):
        post_comment("github", "https://x.example.com", "o/r", "1", "b", "TOK", client)


def rpc(config: Config, root: Path, *msgs: dict[str, object]) -> list[dict[str, object]]:
    out = io.StringIO()
    serve(config, root, io.StringIO("\n".join(json.dumps(m) for m in msgs) + "\n"), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_mcp_server_lists_and_scans(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("x = 1\n")
    code = "import os\nfrom flask import request\nos.system(request.args['c'])\n"
    resp = rpc(
        cfg(), tmp_path,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "gapscan_scan_snippet", "arguments": {"language": "python", "code": code}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "gapscan_scan_file", "arguments": {"path": "../etc/passwd"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "nope"},
    )  # fmt: skip
    assert [r["id"] for r in resp] == [1, 2, 3, 4, 5]  # the notification got no answer
    assert resp[0]["result"]["serverInfo"]["name"] == "gapscan"  # type: ignore[index]
    assert {t["name"] for t in resp[1]["result"]["tools"]} == {
        "gapscan_scan_snippet",
        "gapscan_scan_file",
    }  # type: ignore[index]
    text = resp[2]["result"]["content"][0]["text"]  # type: ignore[index]
    assert "OS command injection" in text and "flow:" in text
    assert resp[3]["result"]["isError"] is True  # path escapes the root  # type: ignore[index]
    assert resp[4]["error"]["code"] == -32601  # type: ignore[index]


def test_mcp_scan_file_reports_flows_into_that_file(tmp_path: Path) -> None:
    (tmp_path / "sink.py").write_text("import os\n\ndef run(c):\n    os.system(c)\n")
    (tmp_path / "route.py").write_text(
        "from flask import request\nimport sink\nsink.run(request.args['c'])\n"
    )
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "gapscan_scan_file", "arguments": {"path": "sink.py"}},
    }
    assert "OS command injection" in handle(cfg(), tmp_path, msg)["result"]["content"][0]["text"]  # type: ignore[index]
    assert handle(cfg(), tmp_path, {"jsonrpc": "2.0", "method": "x"}) is None


def test_mcp_bad_json_is_a_parse_error(tmp_path: Path) -> None:
    out = io.StringIO()
    serve(cfg(), tmp_path, io.StringIO("not json\n"), out)
    assert json.loads(out.getvalue())["error"]["code"] == -32700


def test_integration_files_parse() -> None:
    yaml = pytest.importorskip("yaml")
    for name in ("github-actions.yml", "gitlab-ci.yml", "azure-pipelines.yml"):
        assert isinstance(
            yaml.safe_load((ROOT / "integrations" / "ci" / name).read_text()), dict
        ), name
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())
    assert hooks[0]["id"] == "gapscan" and "--staged" in hooks[0]["entry"]
    assert "gapscan ci run" in (ROOT / "integrations" / "ci" / "Jenkinsfile").read_text()
    ext = json.loads((ROOT / "integrations" / "vscode" / "package.json").read_text())
    assert ext["main"] == "./extension.js"
    assert changes_since and introduced_by_changes  # imported API stays public
