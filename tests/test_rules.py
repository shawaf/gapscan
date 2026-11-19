from __future__ import annotations

from gapscan.agent.review import triage_top_findings
from gapscan.agent.rules import (
    deterministic_verdict,
    noise_verdict,
    purpose_of,
    purpose_verdict,
    words,
)
from gapscan.config import Config
from gapscan.evaluation.metrics import wilson
from gapscan.models import Category, CodeContext, Finding, ScanResult, Severity, VerdictLabel

MANIFEST = """<manifest>
  <application>
    <activity android:name=".Settings" android:exported="true">
    </activity>
    <activity
        android:name=".MainActivity"
        android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
    </activity>
  </application>
</manifest>
"""


def finding(rule="python.lang.best-practice.open-never-closed", file="a.py", line=3,
            cwe=(), category=Category.CODE, **kw):  # fmt: skip
    return Finding(scanner="semgrep", rule_id=rule, title="t", severity=Severity.MEDIUM,
                   category=category, cwe=list(cwe), file=file, start_line=line, **kw)  # fmt: skip


def ctx(code="", signature=None):
    return CodeContext(finding_id="x", file="a.py", code=code, function_signature=signature)


def test_noise_rules_dismiss_only_what_is_provably_not_a_weakness(tmp_path):
    v = noise_verdict(finding(), tmp_path)
    assert v and v.verdict == VerdictLabel.FALSE_POSITIVE and v.model == "gapscan-rules"
    assert (
        "noise.code-quality-hint" in v.policy_notes[-1] and "not by the model" in v.policy_notes[-1]
    )
    for tail in ("unspecified-open-encoding", "use-raise-for-status"):
        assert noise_verdict(finding(rule=f"python.x.{tail}"), tmp_path)
    for tail in ("no-domain", "no-path", "no-expires", "default-name"):
        assert noise_verdict(
            finding(rule=f"javascript.audit.express-cookie-session-{tail}"), tmp_path
        )
    # a real injection rule is never noise
    assert noise_verdict(finding(rule="python.flask.security.injection.sql"), tmp_path) is None


def test_exported_activity_is_noise_only_for_the_launcher(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(MANIFEST)
    rule = "java.android.security.exported_activity.exported_activity"
    other = finding(rule=rule, file="AndroidManifest.xml", line=3)
    launcher = finding(rule=rule, file="AndroidManifest.xml", line=6)
    assert noise_verdict(other, tmp_path) is None  # exported, but not the launcher
    v = noise_verdict(launcher, tmp_path)
    assert v and "launcher" in v.reasoning
    # missing file, escape attempts and non-xml never match
    assert (
        noise_verdict(finding(rule=rule, file="../AndroidManifest.xml", line=6), tmp_path) is None
    )
    assert noise_verdict(finding(rule=rule, file="nope.xml", line=6), tmp_path) is None
    assert noise_verdict(finding(rule=rule, file="a.py", line=6), tmp_path) is None


def test_words_split_camel_and_snake_case():
    assert words("newSessionToken hash_password MD5Digest") >= {
        "new",
        "session",
        "token",
        "hash",
        "password",
        "digest",
    }


def test_purpose_sensitive_beats_benign_and_path_is_ignored():
    f = finding(
        rule="x.md5", cwe=("CWE-327",), file="src/test/cache/Foo.java"
    )  # "test" and "cache" in the path
    assert purpose_of(f, ctx("def hash_password(pw):\n    return md5(pw)"))[0] == "sensitive"
    assert purpose_of(f, ctx("def etag(body):\n    return md5(body)"))[0] == "benign"
    assert (
        purpose_of(f, ctx("def etag_for_password_reset(x):\n    return md5(x)"))[0] == "sensitive"
    )
    assert (
        purpose_of(f, ctx("def foo(x):\n    return md5(x)"))[0] == "unknown"
    )  # the path says nothing
    assert purpose_of(f, ctx("hashlib.md5(x, usedforsecurity=False)"))[0] == "benign"


def test_package_names_and_test_words_never_excuse_a_weak_algorithm():
    f = finding(rule="x.random", cwe=("CWE-330",), file="benchmark/BenchmarkTest00067.java")
    code = (
        "import org.owasp.benchmark.helpers.Utils;\npackage org.owasp.benchmark.testcode;\n"
        "void doPost(Request r) {\n    int v = new java.util.Random().nextInt();\n}"
    )
    assert purpose_of(f, ctx(code))[0] == "unknown"
    v = purpose_verdict(f, ctx(code))
    assert v and v.verdict == VerdictLabel.LIKELY_TRUE_POSITIVE
    # the same words in the logic still count when they are real names there
    assert purpose_of(f, ctx("def cache_slot(u):\n    return random.randint(0, 9)"))[0] == "benign"
    assert (
        purpose_of(f, ctx("# demo sample mock example test\nx = random.random()"))[0] == "unknown"
    )


def test_purpose_verdicts_confirm_dismiss_or_keep():
    f = finding(rule="x.md5", cwe=("CWE-327",))
    sensitive = purpose_verdict(f, ctx("def login_hash(pw):\n    md5(pw)"))
    assert (
        sensitive
        and sensitive.verdict == VerdictLabel.TRUE_POSITIVE
        and "login" in sensitive.reasoning
    )
    benign = purpose_verdict(f, ctx("def cache_key(u):\n    md5(u)"))
    assert benign and benign.verdict == VerdictLabel.FALSE_POSITIVE
    unclear = purpose_verdict(f, ctx("def f(x):\n    md5(x)"))
    assert (
        unclear
        and unclear.verdict == VerdictLabel.LIKELY_TRUE_POSITIVE
        and unclear.confidence <= 0.6
    )
    assert (
        purpose_verdict(finding(rule="x.sql", cwe=("CWE-89",)), ctx("x")) is None
    )  # not a weak algorithm
    assert purpose_verdict(finding(cwe=("CWE-327",), category=Category.CONFIG), ctx("x")) is None
    assert (
        deterministic_verdict(
            finding(rule="x.sql", cwe=("CWE-89",)), ctx("x"), __import__("pathlib").Path(".")
        )
        is None
    )


def test_pipeline_uses_rules_without_calling_the_model(tmp_path):
    (tmp_path / "a.py").write_text("def etag(b):\n    return md5(b)\n\nopen('x')\n")

    class NoModel:
        def __getattr__(self, name):
            raise AssertionError("the model must not be called for rule-decided findings")

    weak = finding(rule="x.md5", cwe=("CWE-327",), file="a.py", line=2)
    noise = finding(rule="python.best-practice.open-never-closed", file="a.py", line=4)
    cfg = Config(data={"dir": str(tmp_path)})
    out = triage_top_findings(cfg, ScanResult(target=str(tmp_path), findings=[weak, noise]), tmp_path,
                              limit=5, client=NoModel(), kb=None)  # fmt: skip
    assert [v.verdict for v in out] == [VerdictLabel.FALSE_POSITIVE, VerdictLabel.FALSE_POSITIVE]
    assert {v.model for v in out} == {"gapscan-rules"} and all(v.tokens == 0 for v in out)


def test_wilson_interval_shows_how_little_a_small_sample_proves():
    assert wilson(0, 0) is None
    lo, hi = wilson(0, 13)
    assert lo == 0.0 and 0.2 < hi < 0.3  # "0 of 13 dismissed" could be a true rate near 25%
    lo, hi = wilson(80, 80)
    assert hi == 1.0 and 0.9 < lo < 1.0
    lo, hi = wilson(50, 100)
    assert 0.39 < lo < 0.41 and 0.59 < hi < 0.61
