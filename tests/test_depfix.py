"""Dependency fixes: one bump per package to the highest fixed version, the project's own operator
kept, lockfiles flagged for regeneration (never regenerated), transitive packages explained, and a
rescan on a copy decides whether a fix is verified."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from gapscan.depfix import combined_diff, plan_upgrades, propose_dependency_fixes
from gapscan.models import Category, Finding, Severity


def dep(package: str, version: str, fixed: str, eco: str, cve: str, file: str = "") -> Finding:
    return Finding(
        scanner="osv", rule_id=f"GHSA-{cve}", title=cve, severity=Severity.HIGH,
        category=Category.DEPENDENCY, file=file or None, package=package, version=version,
        fixed_version=fixed, cve=[f"CVE-{cve}"], raw={"ecosystem": eco},
    )  # fmt: skip


def test_one_upgrade_per_package_to_the_highest_fix() -> None:
    plans = plan_upgrades([
        dep("requests", "2.25.1", "2.31.0", "PyPI", "1"),
        dep("requests", "2.25.1", "2.32.4", "PyPI", "2"),
        dep("left-pad", "1.0.0", "", "npm", "3"),  # no known fix: left out
    ])  # fmt: skip
    assert [(p.package, p.target, p.advisories) for p in plans] == [
        ("requests", "2.32.4", ["CVE-1", "CVE-2"])
    ]


def test_requirements_pin_is_raised_and_verified_by_a_rescan(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\nrequests==2.25.1  # http\n")
    seen: list[str] = []

    def rescan(copy: Path) -> list[Finding]:
        seen.append((copy / "requirements.txt").read_text())
        return []  # the advisory is gone

    fixes = propose_dependency_fixes(
        tmp_path, [dep("requests", "2.25.1", "2.32.4", "PyPI", "1")], rescan=rescan
    )
    (fix,) = fixes
    assert fix.edits[0].after == "requests==2.32.4  # http" and fix.edits[0].line == 2
    assert "-requests==2.25.1  # http\n+requests==2.32.4  # http" in fix.diff
    assert fix.verified is True and "requests==2.32.4" in seen[0]
    assert (tmp_path / "requirements.txt").read_text().startswith("flask==2.0.0\nrequests==2.25.1")


def test_a_rescan_that_still_finds_it_is_not_verified(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.25.1\n")
    f = dep("requests", "2.25.1", "2.32.4", "PyPI", "1")
    (fix,) = propose_dependency_fixes(tmp_path, [f], rescan=lambda copy: [f])
    assert fix.verified is False and any("still reports" in n for n in fix.notes)


def test_package_json_keeps_the_caret_and_flags_the_lockfile(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.17.1", "lodash": "^4.17.15"}}, indent=2)
    )
    (tmp_path / "package-lock.json").write_text("{}")
    called: list[Path] = []
    (fix,) = propose_dependency_fixes(
        tmp_path, [dep("lodash", "4.17.15", "4.17.21", "npm", "9")],
        rescan=lambda copy: called.append(copy) or [],
    )  # fmt: skip
    assert fix.edits[0].after.strip() == '"lodash": "^4.17.21"'
    assert fix.lockfiles == ["package-lock.json"] and fix.verified is None
    assert called == []  # the lockfile decides the version: a rescan could not see the edit
    assert any("does not run package managers" in n for n in fix.notes)


def test_go_mod_keeps_the_v_prefix(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\nrequire (\n\tgolang.org/x/net v0.7.0\n)\n"
    )
    (fix,) = propose_dependency_fixes(
        tmp_path, [dep("golang.org/x/net", "0.7.0", "0.23.0", "Go", "5")]
    )
    assert fix.edits[0].after == "\tgolang.org/x/net v0.23.0"


def test_pom_version_below_the_dependency_line(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies>\n  <dependency>\n    <groupId>org.yaml</groupId>\n"
        "    <artifactId>snakeyaml</artifactId>\n    <version>1.33</version>\n  </dependency>\n"
        "</dependencies></project>\n"
    )
    (fix,) = propose_dependency_fixes(
        tmp_path, [dep("org.yaml:snakeyaml", "1.33", "2.0", "Maven", "7")]
    )
    assert fix.edits and fix.edits[0].after == "    <version>2.0</version>"


def test_a_transitive_package_is_explained_not_guessed(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
    (fix,) = propose_dependency_fixes(tmp_path, [dep("urllib3", "1.26.0", "1.26.18", "PyPI", "4")])
    assert fix.edits == [] and fix.diff == ""
    assert "transitive" in fix.notes[0] and "1.26.18" in fix.notes[0]


def test_an_unpinned_requirement_asks_for_a_manual_bump(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests\n")
    (fix,) = propose_dependency_fixes(tmp_path, [dep("requests", "2.25.1", "2.32.4", "PyPI", "1")])
    assert fix.edits == [] and "without a literal version" in fix.notes[0]


def test_two_fixes_in_one_file_make_one_patch_that_applies(tmp_path: Path) -> None:
    """Each fix's own diff is against the original file; concatenated, the second hunk no longer
    applies. The combined patch applies every kept edit to the same file."""
    (tmp_path / "requirements.txt").write_text("django==3.0.0\nrequests==2.19.0\nflask==1.0\n")
    fixes = propose_dependency_fixes(tmp_path, [
        dep("django", "3.0.0", "5.2.17", "PyPI", "1"),
        dep("requests", "2.19.0", "2.33.0", "PyPI", "2"),
        dep("flask", "1.0", "3.1.3", "PyPI", "3"),
    ], rescan=lambda copy: [])  # fmt: skip
    patch = combined_diff(tmp_path, fixes)
    assert patch.count("+++ b/requirements.txt") == 1
    for line in ("+django==5.2.17", "+requests==2.33.0", "+flask==3.1.3"):
        assert line in patch
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, timeout=30)
    subprocess.run(
        ["git", "apply", "-"], cwd=tmp_path, input=patch, text=True, check=True, timeout=30
    )
    assert (
        tmp_path / "requirements.txt"
    ).read_text() == "django==5.2.17\nrequests==2.33.0\nflask==3.1.3\n"


def test_combined_patch_leaves_out_fixes_a_rescan_rejected(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("django==3.0.0\nrequests==2.19.0\n")
    still = dep("requests", "2.19.0", "2.33.0", "PyPI", "2")
    fixes = propose_dependency_fixes(
        tmp_path,
        [dep("django", "3.0.0", "5.2.17", "PyPI", "1"), still],
        rescan=lambda copy: [still],
    )
    patch = combined_diff(tmp_path, fixes)
    assert "+django==5.2.17" in patch and "+requests" not in patch
