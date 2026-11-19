from __future__ import annotations

from gapscan.models import Category, Finding, Severity
from gapscan.redact import PLACEHOLDER, SNIPPET_PLACEHOLDER, mask, redact_findings

GHP = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"
AWS = "AKIA" + "JKQW2XM7LPR5ZT3N"


def f(cat=Category.CODE, line=2, end=None, snippet="", file="config.py", **kw):
    return Finding(scanner="s", rule_id="r", title="t", severity=Severity.LOW, category=cat,
                   file=file, start_line=line, end_line=end or line, snippet=snippet, **kw)  # fmt: skip


def test_mask_tokens_and_assignments():
    assert GHP not in mask(f'GITHUB_TOKEN = "{GHP}"') and AWS not in mask(f"id={AWS}")
    out = mask('password = "hunter2hunter2"')
    assert "hunter2" not in out and out.startswith("password = ")
    assert "BEGIN" not in mask(
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    )
    assert mask('name = "alice"') == 'name = "alice"'  # ordinary code untouched


def test_snippet_on_secret_line_is_withheld_entirely():
    secret = f(Category.SECRET, line=2, snippet=PLACEHOLDER)
    other = f(Category.CODE, line=1, end=3, snippet='1 # x\n2 TOKEN = "weird-format-value"\n3 y')
    elsewhere = f(Category.CODE, line=40, snippet="print('hi')")
    redact_findings([secret, other, elsewhere])
    assert other.snippet == SNIPPET_PLACEHOLDER and elsewhere.snippet == "print('hi')"


def test_messages_are_masked_too():
    x = f(snippet="", message=f"found {GHP} in code")
    redact_findings([x])
    assert GHP not in x.message
