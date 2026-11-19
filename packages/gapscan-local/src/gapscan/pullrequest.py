"""Open a pull request with a fix: `gapscan pr`.

The user runs this on purpose, after reviewing the patch (`gapscan fix-deps` or `gapscan fix`), and
it is never part of `scan` (hard rule 2 is about scanning). Steps:

1. refuse unless the project is a git repository with a clean working tree;
2. create a branch, apply the patch, commit, and push the branch to the remote with the user's own
   git credentials;
3. switch back to the branch the user was on;
4. ask the SCM's API to open the pull request, with a token read from an environment variable.

The project's own code must never run (hard rule 1), and git can run project-controlled programs
through hooks and the fsmonitor setting. Every git call here therefore passes
`-c core.hooksPath=/dev/null -c core.fsmonitor=false`, and commit and push pass `--no-verify`.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from .scm import SCMError, _check_url, _headers

PR_PROVIDERS = ("github", "gitlab")
DEFAULT_API = {"github": "https://api.github.com", "gitlab": "https://gitlab.com"}
SAFE_GIT = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
_REMOTE = re.compile(r"(?:github\.com|gitlab\.com)[:/](?P<repo>[^\s]+?)(?:\.git)?/?$")

Git = Callable[..., subprocess.CompletedProcess[str]]


class PRError(RuntimeError):
    pass


@dataclass
class PullRequestPlan:
    target: Path
    patch: str
    title: str
    body: str
    provider: str = "github"
    api_url: str = ""
    repo: str = ""
    base: str = ""
    branch: str = ""
    remote: str = "origin"
    files: list[str] = field(default_factory=list)


def _git_runner(target: Path) -> Git:
    def run(*args: str, input: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *SAFE_GIT, "-C", str(target), *args],
            input=input, capture_output=True, text=True, timeout=120, check=False,
        )  # fmt: skip

    return run


def _ok(proc: subprocess.CompletedProcess[str], what: str) -> str:
    if proc.returncode != 0:
        raise PRError(f"git {what} failed: {(proc.stderr or proc.stdout).strip()[:300]}")
    return proc.stdout.strip()


def patch_files(patch: str) -> list[str]:
    """Files a unified diff changes (from its `+++ b/...` lines)."""
    return sorted({m.group(1) for m in re.finditer(r"^\+\+\+ b/(\S+)", patch, re.M)})


def repo_from_remote(url: str) -> str:
    m = _REMOTE.search(url.strip())
    return m.group("repo") if m else ""


def default_branch_name(patch: str) -> str:
    return "gapscan/fix-" + hashlib.sha256(patch.encode()).hexdigest()[:8]


def prepare(plan: PullRequestPlan, git: Git | None = None) -> PullRequestPlan:
    """Fill in what the user did not give (base, branch, repo, API URL) and check everything that
    can be checked before anything changes."""
    git = git or _git_runner(plan.target)
    if plan.provider not in PR_PROVIDERS:
        raise PRError(
            f"unknown provider {plan.provider!r}; choose one of {', '.join(PR_PROVIDERS)}"
        )
    if not plan.patch.strip():
        raise PRError("the patch is empty")
    plan.files = patch_files(plan.patch)
    if not plan.files:
        raise PRError("the patch changes no files (expected a unified diff with a/ and b/ paths)")
    if _ok(git("rev-parse", "--is-inside-work-tree"), "rev-parse") != "true":
        raise PRError(f"{plan.target} is not a git repository")
    if _ok(git("status", "--porcelain"), "status"):
        raise PRError("the working tree has uncommitted changes: commit or stash them first")
    if not plan.base:
        plan.base = _ok(git("rev-parse", "--abbrev-ref", "HEAD"), "rev-parse")
    plan.branch = plan.branch or default_branch_name(plan.patch)
    for name in (plan.base, plan.branch):
        if not _BRANCH.match(name) or ".." in name or name.startswith("-"):
            raise PRError(f"not a usable branch name: {name!r}")
    if not plan.repo:
        plan.repo = repo_from_remote(_ok(git("remote", "get-url", plan.remote), "remote get-url"))
        if not plan.repo:
            raise PRError(
                "could not tell the repository from the remote URL: pass --repo owner/name"
            )
    plan.api_url = _check_url(plan.api_url or DEFAULT_API[plan.provider])
    check = git("apply", "--check", "-", input=plan.patch)
    if check.returncode != 0:
        raise PRError(f"the patch does not apply: {check.stderr.strip()[:300]}")
    return plan


def push_branch(plan: PullRequestPlan, git: Git | None = None) -> None:
    """Branch, apply, commit and push, then switch back to the base branch. On a failure the new
    branch is removed again."""
    git = git or _git_runner(plan.target)
    _ok(git("checkout", "-b", plan.branch), "checkout -b")
    try:
        _ok(git("apply", "--index", "-", input=plan.patch), "apply")
        _ok(git("commit", "--no-verify", "-m", plan.title, "-m", plan.body), "commit")
        _ok(git("push", "--no-verify", "-u", plan.remote, plan.branch), "push")
    except PRError:
        # The tree was clean before: drop the half-made branch and leave nothing behind.
        git("reset", "--hard")
        git("checkout", plan.base)
        git("branch", "-D", plan.branch)
        raise
    git("checkout", plan.base)


def pr_request(plan: PullRequestPlan) -> tuple[str, dict[str, Any]]:
    if plan.provider == "github":
        return f"{plan.api_url}/repos/{plan.repo}/pulls", {
            "title": plan.title, "body": plan.body, "head": plan.branch, "base": plan.base,
        }  # fmt: skip
    return f"{plan.api_url}/api/v4/projects/{quote(plan.repo, safe='')}/merge_requests", {
        "title": plan.title, "description": plan.body,
        "source_branch": plan.branch, "target_branch": plan.base,
    }  # fmt: skip


def open_pull_request(
    plan: PullRequestPlan, token_env: str, client: httpx.Client | None = None
) -> str:
    """Ask the SCM to open the pull request; returns its web URL."""
    token = os.environ.get(token_env, "")
    if not token:
        raise SCMError(f"environment variable {token_env} is empty: set it to an access token")
    url, payload = pr_request(plan)
    own = client is None
    client = client or httpx.Client(timeout=30)
    try:
        resp = client.post(url, json=payload, headers=_headers(plan.provider, token))
        if resp.status_code >= 300:
            raise SCMError(f"{plan.provider} answered {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        return str(data.get("html_url") or data.get("web_url") or url)
    except httpx.HTTPError as exc:
        raise SCMError(f"could not reach {plan.provider}: {exc}") from exc
    finally:
        if own:
            client.close()
