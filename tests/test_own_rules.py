"""GapScan's own Semgrep rules (Kotlin, Swift, Dart, Python, JavaScript/TypeScript, Java, Go, C#, PHP) against their vulnerable and safe cases."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from gapscan.models import Category, Finding, Severity
from gapscan.scanners.semgrep import OWN_RULES, own_rule_configs, postprocess

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


LANGUAGES = ["kotlin", "swift", "dart", "python", "javascript", "java", "go", "csharp", "php"]
MOBILE = {"kotlin", "swift", "dart"}


@pytest.mark.parametrize("language", LANGUAGES)
def test_every_rule_catches_its_bad_case_and_ignores_its_safe_case(language):
    proc = subprocess.run(  # noqa: S603 - fixed argument list
        ["semgrep", "--test", "--config", str(OWN_RULES / language), str(ROOT / "tests" / "rules" / language),
         "--metrics=off", "--disable-version-check"],
        capture_output=True, text=True, timeout=300, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout[-1500:] + proc.stderr[-500:]
    assert "All tests passed" in proc.stdout


def test_the_rule_folders_are_found_and_every_rule_has_a_cwe_tag_and_mobile_rules_a_masvs_tag():
    import yaml

    folders = own_rule_configs()
    assert {p.name for p in folders} == set(LANGUAGES)
    ids = []
    for folder in folders:
        for file in folder.glob("*.yaml"):
            for rule in yaml.safe_load(file.read_text())["rules"]:
                ids.append(rule["id"])
                assert rule["id"].startswith(f"gapscan.{folder.name}."), rule["id"]
                meta = rule["metadata"]
                assert meta["cwe"] and meta["confidence"] in ("HIGH", "MEDIUM", "LOW")
                if folder.name in MOBILE:
                    assert meta["masvs"], rule["id"]
                assert rule["message"].strip() and rule["severity"] in ("ERROR", "WARNING", "INFO")
    assert len(ids) == len(set(ids)) >= 150


def test_own_rule_ids_are_kept_clean_whatever_path_semgrep_prefixes_them_with():
    f = Finding(scanner="semgrep", rule_id="Users.me.CyberSecAgent.src.gapscan.rules.semgrep.dart.gapscan.dart.weak-crypto",
                title="t", severity=Severity.HIGH, category=Category.CODE, cwe=["CWE-327"])  # fmt: skip
    assert postprocess([f])[0].rule_id == "gapscan.dart.weak-crypto"
    for lang in ("csharp", "php"):  # every language folder, not a fixed list
        g = Finding(scanner="semgrep", rule_id=f"src.gapscan.rules.semgrep.{lang}.gapscan.{lang}.taint-sqli",
                    title="t", severity=Severity.HIGH, category=Category.CODE, cwe=["CWE-89"])  # fmt: skip
        assert postprocess([g])[0].rule_id == f"gapscan.{lang}.taint-sqli"
    other = Finding(scanner="semgrep", rule_id="x.semgrep-rules.python.lang.foo", title="t",
                    severity=Severity.LOW, category=Category.CODE)  # fmt: skip
    assert postprocess([other])[0].rule_id == "python.lang.foo"


def test_every_own_rule_id_is_kept_clean():
    for language in ("python", "javascript", "java", "go"):
        f = Finding(scanner="semgrep", rule_id=f"tmp.rules.semgrep.{language}.gapscan.{language}.taint-sqli",
                    title="t", severity=Severity.HIGH, category=Category.CODE, cwe=["CWE-89"])  # fmt: skip
        assert postprocess([f])[0].rule_id == f"gapscan.{language}.taint-sqli"


def test_every_rule_message_says_how_to_fix_it():
    """The message is what a developer reads in the report, the IDE and the PR comment: it must name
    the problem and the fix, not only the rule."""
    import re

    import yaml

    fix = re.compile(
        r"\b(use|keep|leave|set|remove|avoid|never|pass|load|read|check|validate|enable|escape|encode|"
        r"turn|move|replace|store|generate|add|allow|restrict|require|pin|disable|map|list|limit|only|"
        r"prefer|run|call|rotate|delete|return|mark|declare|do not|make|give|switch|verify|wrap|derive|"
        r"compare|sanitize|bind|apply|put)\b",
        re.I,
    )
    missing = [
        rule["id"]
        for folder in own_rule_configs()
        for file in folder.glob("*.yaml")
        for rule in yaml.safe_load(file.read_text())["rules"]
        if not fix.search(" ".join(rule["message"].split()))
    ]
    assert missing == []
