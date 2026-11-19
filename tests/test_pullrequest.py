"""`gapscan pr`: a real git repository with a bare remote. The branch is pushed with hooks disabled
(a project's pre-commit hook must never run), the user's branch is restored, a failed patch leaves
nothing behind, and the API request goes only where the user pointed it."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from gapscan.pullrequest import (
    PRError,
    PullRequestPlan,
    open_pull_request,
    pr_request,
    prepare,
    push_branch,
    repo_from_remote,
)
from gapscan.scm import SCMError

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

PATCH = """--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-requests==2.25.1
+requests==2.32.4
"""


def git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}  # fmt: skip
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for k, v in {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}.items():  # fmt: skip
        monkeypatch.setenv(k, v)
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
    work = tmp_path / "work"
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    (work / "requirements.txt").write_text("requests==2.25.1\n")
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "init")
    git(work, "remote", "add", "origin", str(remote))
    git(work, "push", "-q", "origin", "main")
    hook = work / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch {tmp_path / 'HOOK_RAN'}\nexit 1\n")
    hook.chmod(0o755)
    return work


def plan(repo: Path, **kw: str) -> PullRequestPlan:
    return PullRequestPlan(target=repo, patch=kw.pop("patch", PATCH), title="Upgrade requests",
                           body="CVE-2026-1", repo="acme/app", **kw)  # fmt: skip


def test_branch_is_pushed_without_running_hooks_and_the_user_branch_is_restored(
    repo, tmp_path
) -> None:
    p = prepare(plan(repo))
    assert (
        p.base == "main" and p.branch.startswith("gapscan/fix-") and p.files == ["requirements.txt"]
    )
    push_branch(p)
    assert not (tmp_path / "HOOK_RAN").exists()
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert (repo / "requirements.txt").read_text() == "requests==2.25.1\n"
    pushed = git(tmp_path / "remote.git", "show", f"{p.branch}:requirements.txt")
    assert pushed == "requests==2.32.4"
    assert git(tmp_path / "remote.git", "log", "-1", "--format=%s", p.branch) == "Upgrade requests"


def test_a_dirty_tree_is_refused(repo) -> None:
    (repo / "requirements.txt").write_text("requests==9\n")
    with pytest.raises(PRError, match="uncommitted"):
        prepare(plan(repo))


def test_a_patch_that_does_not_apply_is_refused_before_anything_changes(repo) -> None:
    with pytest.raises(PRError, match="does not apply"):
        prepare(plan(repo, patch=PATCH.replace("2.25.1", "1.0.0")))
    assert git(repo, "branch", "--list", "gapscan/*") == ""


def test_a_failed_push_leaves_no_branch(repo) -> None:
    p = prepare(plan(repo, remote="origin"))
    git(repo, "remote", "set-url", "origin", str(repo.parent / "missing.git"))
    with pytest.raises(PRError, match="push"):
        push_branch(p)
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(repo, "branch", "--list", p.branch) == ""
    assert git(repo, "status", "--porcelain") == ""


def test_bad_branch_names_and_plain_http_are_refused(repo) -> None:
    with pytest.raises(PRError, match="branch name"):
        prepare(plan(repo, branch="--upload-pack=evil"))
    with pytest.raises(SCMError, match="https"):
        prepare(plan(repo, api_url="http://example.com"))


def test_repo_from_remote() -> None:
    assert repo_from_remote("git@github.com:acme/app.git") == "acme/app"
    assert repo_from_remote("https://github.com/acme/app") == "acme/app"
    assert repo_from_remote("https://gitlab.com/group/sub/app.git") == "group/sub/app"
    assert repo_from_remote("/srv/git/app.git") == ""


def test_github_and_gitlab_requests() -> None:
    p = PullRequestPlan(target=Path("."), patch=PATCH, title="T", body="B", repo="acme/app",
                        base="main", branch="gapscan/fix-1", api_url="https://api.github.com")  # fmt: skip
    url, payload = pr_request(p)
    assert url == "https://api.github.com/repos/acme/app/pulls"
    assert payload == {"title": "T", "body": "B", "head": "gapscan/fix-1", "base": "main"}
    p.provider, p.api_url, p.repo = "gitlab", "https://gitlab.example.com", "group/app"
    url, payload = pr_request(p)
    assert url == "https://gitlab.example.com/api/v4/projects/group%2Fapp/merge_requests"
    assert payload["source_branch"] == "gapscan/fix-1" and payload["target_branch"] == "main"


def test_open_pull_request_uses_the_token_from_the_environment(monkeypatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"html_url": "https://github.com/acme/app/pull/7"})

    p = PullRequestPlan(target=Path("."), patch=PATCH, title="T", body="B", repo="acme/app",
                        base="main", branch="gapscan/fix-1", api_url="https://api.github.com")  # fmt: skip
    with pytest.raises(SCMError, match="GH_T"):
        open_pull_request(p, "GH_T")
    monkeypatch.setenv("GH_T", "secret-token")
    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert open_pull_request(p, "GH_T", client=client) == "https://github.com/acme/app/pull/7"
    assert seen[0].headers["Authorization"] == "Bearer secret-token"
    assert json.loads(seen[0].content)["head"] == "gapscan/fix-1"
