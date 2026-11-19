"""Diff-aware scanning: report only what a change introduced.

Two ways to say "what was there before":

* **A git ref** (`--base origin/main`): `git diff -U0` gives the lines the change added or edited.
  A finding counts as introduced if its own lines, *or any step of its taint path*, touch those
  lines (a new call can create a source-to-sink path whose sink sits in untouched code), or, for a
  dependency finding, if its package name appears on an added line of its manifest or lockfile.
* **A baseline scan** (`--baseline old.json`): a finding is introduced if its stable id is not in
  the baseline (ids survive code moving, see `fingerprint.py`).

git is only asked questions (`diff`, `merge-base`, `rev-parse`); it never runs project code.
"""

from __future__ import annotations

import contextlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding

GIT_TIMEOUT_S = 60
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_STEP_LOC = re.compile(r"at (.+?):(\d+)$")


class GitError(RuntimeError):
    pass


def _git(repo: Path, *args: str) -> str:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, timeout=GIT_TIMEOUT_S, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"git failed: {exc}") from exc
    if proc.returncode != 0:
        raise GitError(
            f"git {' '.join(args[:2])} failed: {(proc.stderr or proc.stdout).strip()[:200]}"
        )
    return proc.stdout


@dataclass
class Changes:
    """Added or edited lines per file: {path: [(line number, text)]}."""

    lines: dict[str, list[tuple[int, str]]] = field(default_factory=dict)

    @property
    def files(self) -> set[str]:
        return set(self.lines)

    def touches(self, file: str | None, start: int, end: int) -> bool:
        return bool(file) and any(start <= n <= end for n, _ in self.lines.get(file or "", []))

    def added_text(self, file: str | None) -> str:
        return "\n".join(t for _, t in self.lines.get(file or "", []))


def parse_diff(diff: str) -> Changes:
    ch = Changes()
    current: str | None = None
    new_line = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            current = None if path == "/dev/null" else path.removeprefix("b/")
            if current is not None:
                ch.lines.setdefault(current, [])
        elif raw.startswith("@@"):
            m = _HUNK.match(raw)
            new_line = int(m.group(1)) if m else 0
        elif current is not None and raw.startswith("+") and not raw.startswith("+++"):
            ch.lines[current].append((new_line, raw[1:]))
            new_line += 1
        elif current is not None and raw.startswith(" "):
            new_line += 1
    return ch


@dataclass
class HeadInfo:
    """What is checked out in a repository's working tree, read without changing anything.

    `branch` is empty when the HEAD is detached (no branch) or the folder is not a git repo;
    `commit` is the short hash, empty when there are no commits yet. `dirty` is True when the
    working tree has uncommitted changes. GapScan never checks out, fetches or pulls: it reports
    what the user already has on disk, which is exactly what a scan reads.
    """

    is_repo: bool = False
    branch: str = ""
    commit: str = ""
    dirty: bool = False


def is_repo(repo: Path) -> bool:
    """True if `repo` is inside a git working tree. Asks git a question; runs no project code."""
    try:
        return _git(repo, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except GitError:
        return False


def head_info(repo: Path) -> HeadInfo:
    """The branch, commit and dirty state of the working tree GapScan is about to scan.

    Read-only (`rev-parse`, `status`). Never raises: a folder that is not a repo, or a repo with
    no commits, comes back as `HeadInfo()` with empty fields so a scan can record "no branch".
    """
    if not is_repo(repo):
        return HeadInfo()
    info = HeadInfo(is_repo=True)
    with contextlib.suppress(GitError):
        branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
        info.branch = "" if branch == "HEAD" else branch  # "HEAD" means a detached checkout
    with contextlib.suppress(GitError):  # a repo with no commits yet has no HEAD
        info.commit = _git(repo, "rev-parse", "--short", "HEAD").strip()
    with contextlib.suppress(GitError):
        info.dirty = bool(_git(repo, "status", "--porcelain").strip())
    return info


def branches(repo: Path) -> list[str]:
    """Local branches and remote-tracking refs, for choosing a base to diff against. Read-only;
    returns [] for a non-repo. GapScan never fetches, so remote refs are as last fetched by the
    user. `origin/HEAD` and other symbolic refs are left out."""
    try:
        out = _git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads", "refs/remotes")
    except GitError:
        return []
    seen: list[str] = []
    for line in out.splitlines():
        ref = line.strip()
        if ref and not ref.endswith("/HEAD") and ref not in seen:
            seen.append(ref)
    return seen


def changes_since(repo: Path, base_ref: str) -> Changes:
    """Lines added or edited between the merge-base with `base_ref` and the working tree."""
    base = _git(repo, "merge-base", base_ref, "HEAD").strip()
    return parse_diff(
        _git(repo, "diff", "-U0", "--no-color", "--no-ext-diff", "--no-renames", base)
    )


def staged_changes(repo: Path) -> Changes:
    return parse_diff(
        _git(repo, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--no-renames")
    )


def _locations(f: Finding) -> list[tuple[str, int, int]]:
    locs: list[tuple[str, int, int]] = []
    if f.file and f.start_line:
        locs.append((f.file, f.start_line, f.end_line or f.start_line))
    for step in f.raw.get("taint_path", []) or []:
        m = _STEP_LOC.search(str(step))
        if m:
            locs.append((m.group(1), int(m.group(2)), int(m.group(2))))
    return locs


def introduced_by_changes(findings: list[Finding], ch: Changes) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        if f.package and f.file:
            text = ch.added_text(f.file).lower()
            if f.package.lower() in text:
                out.append(f)
            continue
        if any(ch.touches(file, a, b) for file, a, b in _locations(f)):
            out.append(f)
    return out


def introduced_by_baseline(findings: list[Finding], baseline_ids: set[str]) -> list[Finding]:
    return [f for f in findings if f.id not in baseline_ids]
