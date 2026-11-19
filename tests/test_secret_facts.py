"""Facts about secrets computed from their value, which is never kept or shown to the model."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from gapscan.agent.triage import apply_policy
from gapscan.models import Category, Finding, Severity, Verdict, VerdictLabel
from gapscan.secret_facts import annotate_secrets, describe

PAT = "ghp_" + "Qx7Lm2Vz9Tk4Rw1Hy8Pd3Nf6Js0Bc5Gu2Ea9"
GOOGLE_KEY = "AIza" + "SyD3x4mpl3K3yW1thTh1rtyF1v3Ch4rsXyZ0"
MAPTILER = "abCd3fGhij" + "K1mN0pQr5t"  # a placeholder-looking key, assembled at runtime


def secret(file: str, line: int = 1, rule: str = "generic-api-key") -> Finding:
    return Finding(scanner="gitleaks", rule_id=rule, title="Secret", severity=Severity.HIGH,
                   category=Category.SECRET, file=file, start_line=line)  # fmt: skip


def test_facts_describe_the_value_without_containing_it():
    real = describe(f"github.token={PAT}")
    assert (
        real["format"] == "GitHub token"
        and not real["placeholder"]
        and real["randomness"] == "high"
    )
    assert PAT not in repr(real)
    assert describe('MIXPANEL_TOKEN = "your_mixpanel_token_here"')["placeholder"]
    assert describe("api_key: ${API_KEY}")["placeholder"]
    assert describe("password = process.env.DB_PASSWORD")["env_reference"]
    assert describe("-----BEGIN PRIVATE KEY-----")["format"] == "private key (PEM)"


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_annotate_marks_gitignored_files_and_collapses_firebase_keys(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("secrets.properties\n")
    (tmp_path / "secrets.properties").write_text(f"gh={PAT}\n")
    (tmp_path / "Fastfile").write_text(f"token = '{PAT}'\n")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "google-services.json").write_text(
        "\n".join(f'  "current_key": "{GOOGLE_KEY}",' for _ in range(3))
    )
    fs = [
        secret("secrets.properties"),
        secret("Fastfile"),
        *[secret("app/google-services.json", i, "gcp-api-key") for i in (1, 2, 3)],
    ]
    out = annotate_secrets(fs, tmp_path)
    assert len(out) == 3  # three Firebase hits in one file become one
    props, fast, firebase = out
    assert props.raw["secret_facts"]["gitignored"] and props.severity == Severity.MEDIUM
    assert not fast.raw["secret_facts"]["gitignored"] and fast.severity == Severity.HIGH
    assert firebase.severity == Severity.INFO and "public by design" in firebase.title
    assert PAT not in repr([f.raw for f in out]) and GOOGLE_KEY not in repr([f.raw for f in out])


def _verdict(label: VerdictLabel) -> Verdict:
    return Verdict(finding_id="x", verdict=label, confidence=0.5, reasoning="r",
                   evidence_refs=["a:1"])  # fmt: skip


def test_policy_decides_secrets_from_the_facts():
    f = secret("Fastfile")
    f.raw["secret_facts"] = {"format": "GitHub token", "placeholder": False, "randomness": "high",
                             "length": 40, "gitignored": False, "shipped_in_app": False}  # fmt: skip
    v = apply_policy(f, _verdict(VerdictLabel.NEEDS_REVIEW))
    assert v.verdict == VerdictLabel.LIKELY_TRUE_POSITIVE and "rotate" in v.policy_notes[-1]
    f.raw["secret_facts"] = {"format": "unrecognized", "placeholder": True, "randomness": "low",
                             "length": 24, "gitignored": False}  # fmt: skip
    assert (
        apply_policy(f, _verdict(VerdictLabel.FALSE_POSITIVE)).verdict
        == VerdictLabel.FALSE_POSITIVE
    )
    f.raw["secret_facts"] = {"format": "private key (PEM)", "placeholder": False,
                             "randomness": "high", "shipped_in_app": True}  # fmt: skip
    assert (
        apply_policy(f, _verdict(VerdictLabel.NEEDS_REVIEW)).verdict == VerdictLabel.TRUE_POSITIVE
    )
    # no decisive fact: a model dismissal of a real-looking secret still goes to a person
    f.raw["secret_facts"] = {"format": "unrecognized", "placeholder": False, "randomness": "high"}
    assert (
        apply_policy(f, _verdict(VerdictLabel.FALSE_POSITIVE)).verdict == VerdictLabel.NEEDS_REVIEW
    )


def test_code_references_doc_examples_and_public_keys_are_recognized():
    assert describe("    bgCriticalHovered = DarkColorTokens.colorRed300,")["code_reference"]
    assert not describe(f'token = "{PAT}"')["code_reference"]
    assert describe(f"services.maptiler.apikey={MAPTILER}")["placeholder"]
    assert not describe(f"key={GOOGLE_KEY}")["placeholder"]
    posthog = describe('apiKey = "phc_' + "Jz8sKq2Lm4Np6Rt0Vx3Yb5Cd7Fg9Hj1" + '"')
    assert posthog["public_client_key"] and posthog["format"].startswith("PostHog")


def test_firebase_values_in_android_resources_collapse(tmp_path: Path):
    res = tmp_path / "push/src/main/res/values"
    res.mkdir(parents=True)
    (res / "firebase.xml").write_text(
        "<resources>\n"
        '  <string name="default_web_client_id">912-abc.apps.googleusercontent.com</string>\n'
        f'  <string name="google_api_key">{GOOGLE_KEY}</string>\n'
        f'  <string name="google_crash_reporting_api_key">{GOOGLE_KEY}</string>\n'
        "</resources>\n"
    )
    rel = "push/src/main/res/values/firebase.xml"
    out = annotate_secrets(
        [secret(rel, 2, "google-oauth"), secret(rel, 3), secret(rel, 4)], tmp_path
    )
    assert len(out) == 1 and out[0].severity == Severity.INFO


def test_placeholders_drop_to_low_but_known_formats_never_do(tmp_path: Path):
    (tmp_path / "maps.md").write_text(f"maptiler.apikey={MAPTILER}\n")
    (tmp_path / "ci.env").write_text(f"GH_TOKEN={PAT}  # example\n")
    docs, ci = annotate_secrets([secret("maps.md"), secret("ci.env")], tmp_path)
    assert docs.severity == Severity.LOW and ci.severity == Severity.HIGH
