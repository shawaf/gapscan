"""Scanner adapters are tested against REAL tool output recorded from the fixture in
eval/fixtures/vuln-app (semgrep 1.176.0, bandit 1.9.4, gitleaks 8.30.1, checkov 3.3.20,
osv-scanner 2.6.0, trivy 0.74.0), trimmed and sanitized. CI needs no binaries."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from gapscan.models import Category, Finding, ScannerRun, Severity
from gapscan.scanners.bandit import parse_bandit
from gapscan.scanners.base import ScannerError, pick_fix, run_all
from gapscan.scanners.checkov import parse_checkov
from gapscan.scanners.gitleaks import parse_gitleaks
from gapscan.scanners.osv import parse_osv
from gapscan.scanners.sarif import SarifIngest, parse_sarif
from gapscan.scanners.semgrep import check_sarif_errors, rule_configs
from gapscan.scanners.trivy import parse_trivy

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
TARGET = ROOT / "eval" / "fixtures" / "vuln-app"


@pytest.fixture(autouse=True)
def _cwd_is_repo_root(monkeypatch):
    # Semgrep reports paths relative to the directory it ran in (the repo root).
    monkeypatch.chdir(ROOT)


def load(name: str):
    return json.loads((DATA / name).read_text().replace("TARGET", str(TARGET)))


def by_rule(findings, suffix, line=None):
    return next(
        f for f in findings if f.rule_id.endswith(suffix) and (line is None or f.start_line == line)
    )


def test_semgrep_sarif():
    fs = parse_sarif(load("semgrep.sarif"), TARGET, "semgrep")
    assert len(fs) == 10 and all(f.file == "app.py" for f in fs)
    sqli = by_rule(fs, "sqlalchemy-execute-raw-query")
    assert sqli.cwe == ["CWE-89"] and sqli.severity == Severity.HIGH and sqli.start_line == 16
    assert by_rule(fs, "insecure-hash-algorithm-md5").severity == Severity.MEDIUM
    assert all(f.category == Category.CODE for f in fs)


def test_semgrep_titles_use_the_message_not_the_rule_id():
    sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "x.y.z", "shortDescription": {"text": "Semgrep Finding: x.y.z"}}]}},
                       "results": [{"ruleId": "x.y.z", "message": {"text": "User input reaches a SQL string.\nMore detail."},
                                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 3}}}]}]}]}  # fmt: skip
    (f,) = parse_sarif(sarif, TARGET, "semgrep")
    assert f.title == "User input reaches a SQL string."
    from gapscan.scanners.sarif import _title

    long_message = (
        "Avoiding SQL string concatenation: untrusted input can result in SQL Injection. "
        + "More detail. " * 30
    )
    assert (
        _title("", long_message)
        == "Avoiding SQL string concatenation: untrusted input can result in SQL Injection."
    )
    assert (
        _title("A rule description", long_message) == "A rule description"
    )  # a real short description wins
    assert len(_title("", "x" * 400)) == 160 and _title("", "x" * 400).endswith("...")


def test_semgrep_rule_packs_and_error_detection(tmp_path):
    (tmp_path / "python").mkdir()
    (tmp_path / ".github").mkdir()  # non-rule folders must not be passed to semgrep
    assert rule_configs(tmp_path) == [tmp_path / "python"]
    assert rule_configs(tmp_path / "custom") == [tmp_path / "custom"]
    bad = {"runs": [{"invocations": [{"toolExecutionNotifications": [
        {"level": "error", "message": {"text": "invalid configuration file"}}]}]}]}  # fmt: skip
    with pytest.raises(ScannerError, match="invalid configuration"):
        check_sarif_errors(bad)
    check_sarif_errors(json.loads((DATA / "semgrep.sarif").read_text()))  # real output is clean


def test_sarif_ingest_wrapper(tmp_path):
    ingest = SarifIngest(DATA / "semgrep.sarif")
    assert ingest.is_available() and len(ingest.run(TARGET, tmp_path)) == 10


def test_bandit():
    fs = parse_bandit(load("bandit.json"), TARGET)
    shell = next(f for f in fs if f.rule_id == "B602")
    assert shell.cwe == ["CWE-78"] and shell.file == "app.py" and shell.severity == Severity.HIGH
    # Hardcoded password strings are secrets, so they merge with gitleaks findings later.
    assert {f.category for f in fs if f.rule_id == "B105"} == {Category.SECRET}
    assert next(f for f in fs if f.rule_id == "B403").severity == Severity.LOW


def test_gitleaks_real_output_is_redacted():
    raw = (DATA / "gitleaks.json").read_text()
    assert "ghp_" not in raw and "AKIA" not in raw  # recorded with --redact
    fs = parse_gitleaks(load("gitleaks.json"), TARGET)
    assert {f.rule_id for f in fs} == {"github-pat", "aws-access-token", "generic-api-key"}
    assert all(f.category == Category.SECRET and f.cwe == ["CWE-798"] for f in fs)
    assert all(f.file == "config.py" and f.snippet == "[REDACTED SECRET]" for f in fs)


def test_gitleaks_never_stores_secret_values_even_if_the_tool_leaks_them():
    leaky = [{"RuleID": "x", "File": str(TARGET / "a.py"), "StartLine": 1, "EndLine": 1,
              "Match": "LEAKED-VALUE", "Secret": "LEAKED-VALUE"}]  # fmt: skip
    (f,) = parse_gitleaks(leaky, TARGET)
    assert "LEAKED-VALUE" not in f.model_dump_json()


def test_gitleaks_empty():
    assert parse_gitleaks(None, TARGET) == []


def test_checkov():
    fs = parse_checkov(load("checkov.json"), TARGET)
    assert {f.rule_id for f in fs} == {"CKV_DOCKER_2", "CKV_DOCKER_3"}
    assert all(f.category == Category.CONFIG and f.file == "Dockerfile" for f in fs)
    assert len(parse_checkov([load("checkov.json")], TARGET)) == 2  # list form (multi-framework)


def test_osv():
    fs = parse_osv(load("osv.json"), TARGET)
    assert {f.package for f in fs} == {"lodash", "django", "flask", "requests"}
    lodash = next(f for f in fs if f.rule_id == "GHSA-35jh-r3h4-6jhm")
    assert (lodash.version, lodash.fixed_version) == ("4.17.10", "4.17.21")
    assert "CVE-2021-23337" in lodash.cve
    assert lodash.category == Category.DEPENDENCY and lodash.file == "package-lock.json"
    # Git commit hashes are not versions: fixed_version must never be a SHA.
    assert all(len(f.fixed_version or "") < 20 for f in fs)
    django = next(f for f in fs if f.package == "django")
    assert django.fixed_version and django.fixed_version >= "3.0.0"[:1]


def test_trivy():
    fs = parse_trivy(load("trivy.json"))
    vulns = [f for f in fs if f.category == Category.DEPENDENCY]
    cfg = [f for f in fs if f.category == Category.CONFIG]
    lodash = next(f for f in vulns if f.cve == ["CVE-2019-10744"])
    assert lodash.package == "lodash" and lodash.fixed_version == "4.17.12"
    django = next(f for f in vulns if f.cve == ["CVE-2019-19844"])
    assert django.fixed_version == "3.0.1"  # lowest fix at/above installed 3.0.0, not the list
    assert {f.rule_id for f in cfg} == {"DS-0002", "DS-0026"} and all(
        f.file == "Dockerfile" for f in cfg
    )


def test_trivy_never_phones_home(tmp_path, monkeypatch):
    """Trivy's version check and telemetry (check.trivy.dev) are a network call: every Trivy run
    GapScan makes must switch both off."""
    from gapscan.scanners.trivy import TrivyImageScanner, TrivyScanner

    seen: list[dict[str, str]] = []

    def fake_run(argv, **kw):
        seen.append(kw["env"])
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    for s in (TrivyScanner(tmp_path), TrivyImageScanner(tmp_path)):
        s._exec(["trivy", "fs", "."])
    assert len(seen) == 2
    for env in seen:
        assert env["TRIVY_SKIP_VERSION_CHECK"] == "true"
        assert env["TRIVY_DISABLE_TELEMETRY"] == "true"


def test_pick_fix():
    assert pick_fix("3.0.0", "1.11.27, 2.2.9, 3.0.1") == "3.0.1"
    assert pick_fix("4.17.10", ">=4.17.11") == "4.17.11"
    assert pick_fix("5.0", "1.0, 2.0") == "2.0"  # nothing above installed: take the highest
    assert pick_fix("1.0", None) is None and pick_fix(None, "2.0, 3.0") == "3.0"


def test_finding_id_is_deterministic_and_distinct():
    kw: dict = {
        "scanner": "x",
        "rule_id": "r",
        "title": "t",
        "severity": Severity.LOW,
        "category": Category.CODE,
        "file": "a",
    }
    a, b = Finding(**kw, start_line=1), Finding(**kw, start_line=1)
    assert a.id == b.id and a.id != Finding(**kw, start_line=2).id


class _Fake:
    def __init__(self, name, mode):
        self.name, self.mode = name, mode

    def is_available(self):
        return self.mode != "missing"

    def version(self):
        return "1.0"

    def run(self, target, workdir):
        if self.mode == "boom":
            raise RuntimeError("scanner exploded")
        return [
            Finding(
                scanner=self.name,
                rule_id="r",
                title="t",
                severity=Severity.LOW,
                category=Category.CODE,
            )
        ]


def test_one_failing_scanner_does_not_fail_the_run(tmp_path):
    scanners = [_Fake("good", "ok"), _Fake("bad", "boom"), _Fake("gone", "missing")]
    findings, runs = run_all(scanners, tmp_path, tmp_path / "w")
    assert [f.scanner for f in findings] == ["good"]
    assert {r.scanner: r.status for r in runs} == {
        "good": "ok",
        "bad": "failed",
        "gone": "unavailable",
    }
    assert isinstance(runs[0], ScannerRun)
    assert "exploded" in next(r for r in runs if r.scanner == "bad").error


def test_semgrep_postprocess_categories_and_ids():
    from gapscan.scanners.semgrep import postprocess

    def f(rule, cwe=()):
        return Finding(scanner="semgrep", rule_id=rule, title="t", severity=Severity.HIGH,
                       category=Category.CODE, cwe=list(cwe), file="x")  # fmt: skip

    fs = postprocess([
        f("data.semgrep-rules.dockerfile.security.missing-user.missing-user", ["CWE-250"]),
        f("data.semgrep-rules.terraform.aws.security.public-bucket"),
        f("python.lang.security.audit.subprocess-shell-true", ["CWE-78"]),
        f("generic.secrets.security.detected-aws-access-key-id-value", ["CWE-798"]),
    ])  # fmt: skip
    assert [x.category for x in fs] == [
        Category.CONFIG,
        Category.CONFIG,
        Category.CODE,
        Category.SECRET,
    ]
    assert fs[0].rule_id == "dockerfile.security.missing-user.missing-user"


def test_osv_with_no_manifests_is_an_empty_result_not_a_failure(tmp_path, monkeypatch):
    import subprocess

    from gapscan.scanners.osv import OSVScanner

    (tmp_path / "db" / "osv-scalibr" / "npm").mkdir(parents=True)
    (tmp_path / "db" / "osv-scalibr" / "npm" / "all.zip").write_bytes(b"")
    scanner = OSVScanner(tmp_path / "db")
    assert scanner.run(tmp_path, tmp_path) == []  # no lockfiles: osv-scanner is not even started
    (tmp_path / "package-lock.json").write_text("{}")
    done = subprocess.CompletedProcess(
        [], 128, stdout="", stderr="No package sources found, --help for usage information.\n"
    )
    monkeypatch.setattr(scanner, "_exec", lambda argv, timeout_s=None: done)
    assert scanner.run(tmp_path, tmp_path) == []
    other = subprocess.CompletedProcess([], 128, stdout="", stderr="something else broke")
    monkeypatch.setattr(scanner, "_exec", lambda argv, timeout_s=None: other)
    with pytest.raises(ScannerError, match="exited 128"):
        scanner.run(tmp_path, tmp_path)


def test_a_slow_version_probe_does_not_cost_the_scan(tmp_path, monkeypatch):
    """Checkov can take over 15 s to print its version on a busy machine; the scan must still run."""
    import subprocess

    from gapscan.scanners.base import CommandScanner, run_all

    class Slow(CommandScanner):
        name = "slow"
        binary = "slow"

        def is_available(self):
            return True

        def _exec(self, argv, timeout_s=None):
            if "--version" in argv:
                raise subprocess.TimeoutExpired(argv, timeout_s or 0)
            raise AssertionError("not used")

        def run(self, target, workdir):
            return [
                Finding(scanner="slow", rule_id="r", title="t", severity=Severity.LOW,
                        category=Category.CODE, file="a.py", start_line=1)
            ]  # fmt: skip

    findings, runs = run_all([Slow()], tmp_path, tmp_path)
    assert runs[0].status == "ok" and runs[0].version == "unknown" and len(findings) == 1


def test_image_findings_are_tagged_and_carry_no_local_path(tmp_path):
    import json
    import subprocess

    from gapscan.scanners.trivy import TrivyImageScanner

    archive = tmp_path / "secret-dir" / "app.tar"
    archive.parent.mkdir()
    archive.write_bytes(b"")
    recorded = load("trivy.json")
    recorded["Results"][0]["Target"] = f"{archive} (debian 12.15)"  # what Trivy writes for the OS

    class Fake(TrivyImageScanner):
        def _exec(self, argv, timeout_s=None):
            out = Path(argv[argv.index("--output") + 1])
            out.write_text(json.dumps(recorded))
            return subprocess.CompletedProcess(argv, 0, "", "")

    fs = Fake(tmp_path).run(archive, tmp_path)
    assert fs and all(f.raw["asset"] == "image" and f.scanner == "trivy-image" for f in fs)
    assert all(f.file and f.file.startswith("image:app.tar > ") for f in fs)
    assert "image:app.tar > app.tar (debian 12.15)" in {f.file for f in fs}
    assert not any("secret-dir" in (f.file or "") for f in fs)


def test_osv_checks_gradle_libraries_and_skips_only_ecosystems_without_a_database(
    tmp_path, monkeypatch
):
    """An Android repo: libraries in a version catalog (no lockfile) and fastlane's Gemfile.lock,
    with no RubyGems database installed. Before, the whole dependency check failed."""
    import json
    import subprocess

    from gapscan.scanners.osv import OSVScanner

    proj = tmp_path / "app"
    (proj / "gradle").mkdir(parents=True)
    (proj / "gradle" / "libs.versions.toml").write_text(
        '[versions]\nokhttp = "3.12.0"\n\n[libraries]\n'
        'okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }\n'
        'junit = "junit:junit:4.12"\n'
    )
    (proj / "app").mkdir()
    (proj / "app" / "build.gradle.kts").write_text(
        'val gsonVersion = "2.8.5"\ndependencies {\n'
        '    implementation("com.google.code.gson:gson:$gsonVersion")\n'
        '    testImplementation("org.mockito:mockito-core:5.0.0")\n}\n'
    )
    (proj / "Gemfile.lock").write_text("GEM\n  specs:\n    rexml (3.2.5)\n")
    (proj / "app" / "build" / "generated").mkdir(parents=True)
    (proj / "app" / "build" / "generated" / "package-lock.json").write_text("{}")  # build output
    db = tmp_path / "db" / "osv-scalibr" / "Maven"
    db.mkdir(parents=True)
    (db / "all.zip").write_bytes(b"")
    seen: list[list[str]] = []

    def fake(argv, timeout_s=None):
        seen.append(argv)
        lock = next(argv[i + 1] for i, a in enumerate(argv) if a == "-L")
        out = argv[argv.index("--output") + 1]
        Path(out).write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "source": {"path": lock},
                            "packages": [
                                {
                                    "package": {
                                        "name": "com.squareup.okhttp3:okhttp",
                                        "version": "3.12.0",
                                        "ecosystem": "Maven",
                                    },
                                    "vulnerabilities": [
                                        {"id": "GHSA-x", "summary": "s", "aliases": ["CVE-1"]}
                                    ],
                                }
                            ],
                        }
                    ]
                }
            )
        )
        return subprocess.CompletedProcess(argv, 1, "", "")

    scanner = OSVScanner(tmp_path / "db")
    monkeypatch.setattr(scanner, "_exec", fake)
    fs = scanner.run(proj, tmp_path / "work")
    args = seen[0]
    locks = [args[i + 1] for i, a in enumerate(args) if a == "-L"]
    assert len(locks) == 1 and locks[0].endswith(
        "gradle.lockfile"
    )  # Gemfile.lock and build/ skipped
    text = Path(locks[0]).read_text()
    assert "com.squareup.okhttp3:okhttp:3.12.0=releaseRuntimeClasspath" in text
    assert "com.google.code.gson:gson:2.8.5=releaseRuntimeClasspath" in text  # $variable resolved
    assert (
        "org.mockito:mockito-core:5.0.0=testRuntimeClasspath" in text and "junit:junit:4.12" in text
    )
    assert "RubyGems" in scanner.note
    assert [(f.file, f.start_line) for f in fs] == [
        ("gradle/libs.versions.toml", 5)
    ]  # declaring line


def test_declared_gradle_dependencies_join_the_sbom():
    from gapscan.manifests import Dep, add_declared_to_sbom
    from gapscan.report.sbom import sbom_rows

    deps = [Dep("Maven", "com.squareup.okhttp3:okhttp", "4.9.0", "gradle/libs.versions.toml", 5),
            Dep("Maven", "io.example:bom", None, "app/build.gradle.kts", 3),
            Dep("npm", "left-pad", "1.0.0", "package.json", 2)]  # fmt: skip
    sbom = add_declared_to_sbom(None, deps)
    rows = sbom_rows(sbom, {("com.squareup.okhttp3:okhttp", "4.9.0")})
    assert [(r.name, r.version, r.ecosystem, r.direct, r.vulnerable) for r in rows] == [
        ("com.squareup.okhttp3:okhttp", "4.9.0", "maven", True, True)
    ]
    assert add_declared_to_sbom(sbom, deps)["components"] == sbom["components"]  # no duplicates


def test_gitleaks_ignores_the_scanned_projects_own_config(tmp_path, monkeypatch):
    """A scanned repo's .gitleaks.toml / .gitleaksignore must not be able to hide its secrets."""
    from gapscan.scanners.gitleaks import GitleaksScanner

    target, work = tmp_path / "repo", tmp_path / "work"
    target.mkdir()
    work.mkdir()
    (target / ".gitleaks.toml").write_text('[[allowlists]]\npaths = [".*"]\n')
    (target / ".gitleaksignore").write_text("*\n")
    seen: list[list[str]] = []

    def fake_exec(argv, timeout_s=None):
        seen.append(argv)
        (work / "gitleaks.json").write_text("[]")
        return subprocess.CompletedProcess(argv, 0, "", "")

    scanner = GitleaksScanner()
    monkeypatch.setattr(scanner, "_exec", fake_exec)
    scanner.run(target, work)
    argv = seen[0]
    config = Path(argv[argv.index("--config") + 1])
    ignore = Path(argv[argv.index("--gitleaks-ignore-path") + 1])
    assert config.parent == work and "useDefault = true" in config.read_text()
    assert "allowlist" not in config.read_text()
    assert ignore.is_relative_to(work) and not (ignore / ".gitleaksignore").exists()


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_gitleaks_binary_still_finds_secrets_a_target_config_tries_to_hide(tmp_path):
    from gapscan.scanners.gitleaks import GitleaksScanner

    target, work = tmp_path / "repo", tmp_path / "work"
    target.mkdir()
    work.mkdir()
    fake = "sk_" + "live_9f8e7d6c5b4a39281706f5e4d3c2b1a0"  # assembled: no literal in this file
    (target / "app.py").write_text(f'API_KEY = "{fake}"\n')
    (target / ".gitleaks.toml").write_text(
        '[extend]\nuseDefault = true\n[[allowlists]]\npaths = [".*"]\n'
    )
    findings = GitleaksScanner().run(target, work)
    assert findings and all(fake not in (f.snippet or "") for f in findings)


def test_the_semgrep_version_probe_never_asks_the_network(tmp_path, monkeypatch):
    """`semgrep --version` checks semgrep.dev for a newer release unless told not to."""
    from gapscan.scanners.semgrep import SemgrepScanner

    seen: list[tuple[list[str], dict[str, str]]] = []
    scanner = SemgrepScanner(tmp_path)

    def fake(argv, timeout_s=None):
        seen.append((argv, scanner.env()))
        return subprocess.CompletedProcess(argv, 0, "1.176.0\n", "")

    monkeypatch.setattr(scanner, "_exec", fake)
    assert scanner.version() == "1.176.0"
    argv, env = seen[0]
    assert "--disable-version-check" in argv
    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert env["SEMGREP_SEND_METRICS"] == "off"
