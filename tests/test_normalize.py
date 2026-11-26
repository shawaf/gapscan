from __future__ import annotations

import json

from gapscan.enrich import Enrichment, load_enrichment
from gapscan.models import Category, Finding, ScanResult, Severity
from gapscan.normalize import (
    apply_llm_cap,
    classify_context,
    deduplicate,
    load_ignore_rules,
    normalize,
    score,
)
from gapscan.registry import registry
from gapscan.security_pack import VulnEnrichment


def code(
    scanner="semgrep",
    rule="r1",
    file="app/db.py",
    start=10,
    end=12,
    cwe=("CWE-89",),
    sev=Severity.MEDIUM,
    **kw,
):
    return Finding(scanner=scanner, rule_id=rule, title="t", severity=sev, category=Category.CODE,
                   file=file, start_line=start, end_line=end, cwe=list(cwe), **kw)  # fmt: skip


def dep(
    scanner="osv",
    rule="GHSA-1",
    cve=("CVE-2021-1",),
    pkg="django",
    ver="3.0.0",
    fixed=None,
    sev=Severity.HIGH,
):
    return Finding(scanner=scanner, rule_id=rule, title="t", severity=sev, category=Category.DEPENDENCY,
                   package=pkg, version=ver, cve=list(cve), fixed_version=fixed, file="requirements.txt")  # fmt: skip


def test_dedupe_merges_same_cwe_overlapping_lines_across_scanners():
    out = deduplicate(
        [
            code("semgrep", sev=Severity.MEDIUM),
            code("bandit", "B608", start=11, end=11, sev=Severity.HIGH),
        ]
    )
    assert len(out) == 1
    assert out[0].sources == ["semgrep", "bandit"] and out[0].severity == Severity.HIGH


def test_dedupe_keeps_distinct_issues():
    out = deduplicate([
        code(),
        code("bandit", "B1", start=50, end=50),  # different lines
        code("bandit", "B2", cwe=("CWE-78",)),  # different CWE
        code("bandit", "B3", file="other.py"),  # different file
    ])  # fmt: skip
    assert len(out) == 4


def test_dedupe_does_not_merge_cweless_findings_across_scanners():
    assert len(deduplicate([code(cwe=()), code("bandit", "B1", cwe=())])) == 2


def test_dedupe_merges_dependency_findings_from_osv_and_trivy():
    out = deduplicate(
        [
            dep("osv", fixed="3.0.14"),
            dep("trivy", "CVE-2021-1", cve=("CVE-2021-1",), sev=Severity.CRITICAL),
        ]
    )
    assert (
        len(out) == 1 and out[0].severity == Severity.CRITICAL and out[0].fixed_version == "3.0.14"
    )
    assert set(out[0].sources) == {"osv", "trivy"}


def test_dedupe_does_not_mutate_inputs():
    a, b = code(), code("bandit", "B1")
    deduplicate([a, b])
    assert a.sources == ["semgrep"]


def test_context_classification():
    f = code(file="src/test/java/FooTest.java")
    classify_context(f)
    assert f.is_test_code and not f.is_vendor_code
    v = code(file="node_modules/x/index.js")
    classify_context(v)
    assert v.is_vendor_code
    for vendored in ("sqli/static/js/jquery-3.2.1.min.js", "static/js/libs/jquery-2.1.4.min.js",
                     "public/bower_components/a/a.js", "static/app-min.css"):  # fmt: skip
        m = code(file=vendored)
        classify_context(m)
        assert m.is_vendor_code, vendored
    own = code(file="src/admin.js")
    classify_context(own)
    assert not own.is_vendor_code
    g = code(file="testdata/certificate/key.pem")
    classify_context(g)
    assert g.is_test_code  # Go's convention for test inputs
    r = code(file="app/views.py", snippet="@app.route('/x')\ndef x(): ...")
    classify_context(r)
    assert r.internet_facing


def test_score_ordering_and_kev():
    base = code(sev=Severity.HIGH)
    exposed = code(sev=Severity.HIGH, snippet="@app.get('/a')")
    classify_context(exposed)
    test_only = code(sev=Severity.HIGH, file="tests/test_a.py")
    classify_context(test_only)
    assert score(exposed) > score(base) > score(test_only)
    kev = dep(sev=Severity.LOW)
    kev.kev = True
    assert score(kev) == 100.0
    low_epss, high_epss = dep(), dep()
    low_epss.epss, high_epss.epss = 0.01, 0.9
    assert score(high_epss) > score(low_epss)


def test_kev_and_epss_loading_and_grouping(tmp_path):
    (tmp_path / "kev.json").write_text(
        json.dumps(
            {"dateReleased": "2026-09-30T00:00:00Z", "vulnerabilities": [{"cveID": "CVE-2021-2"}]}
        )
    )
    (tmp_path / "epss.csv").write_text(
        "#model_version:v2025.03.14,score_date:2026-09-30T00:00:00Z\ncve,epss,percentile\nCVE-2021-1,0.5,0.9\nCVE-2021-2,0.1,0.5\n"
    )
    enr = load_enrichment(tmp_path)
    assert enr.dates == {"cisa_kev": "2026-09-30", "epss": "2026-09-30"}
    result = ScanResult(target="t", findings=[
        dep(rule="A", cve=("CVE-2021-1",), fixed="3.0.14"),
        dep(rule="B", cve=("CVE-2021-2",), fixed="3.1.2", sev=Severity.LOW),
        dep(rule="C", pkg="flask", ver="1.0", cve=("CVE-2020-9",), sev=Severity.LOW),
    ])  # fmt: skip
    out = normalize(result, tmp_path, [*registry().annotators_for(None), VulnEnrichment(enr)])
    assert out.findings[0].kev and out.findings[0].priority == 100.0  # KEV on top
    django = next(g for g in out.package_groups if g.package == "django")
    assert (
        django.fixed_version == "3.1.2"
        and django.kev
        and django.max_epss == 0.5
        and len(django.finding_ids) == 2
    )
    assert out.vuln_data["epss"] == "2026-09-30"


def test_missing_enrichment_files_are_tolerated(tmp_path):
    enr = load_enrichment(tmp_path / "nope")
    assert enr == Enrichment()


def test_ignore_rules(tmp_path):
    (tmp_path / ".gapscanignore").write_text("# comment\nlegacy/\n*.min.js\nrule:B101\n")
    globs, rules = load_ignore_rules(tmp_path)
    assert globs == ["legacy/", "*.min.js"] and rules == {"B101"}
    result = ScanResult(target="t", findings=[
        code(file="legacy/a.py"), code(file="src/legacy/b.py", rule="r2"), code(file="web/app.min.js", rule="r3"),
        code(file="src/ok.py", rule="B101", cwe=("CWE-1",)), code(file="src/keep.py", rule="r4"),
    ])  # fmt: skip
    out = normalize(result, tmp_path)
    assert [f.file for f in out.findings] == ["src/keep.py"] and out.ignored_count == 4


def test_llm_cap_keeps_highest_priority():
    fs = [
        code(file=f"f{i}.py", sev=s)
        for i, s in enumerate([Severity.LOW, Severity.CRITICAL, Severity.HIGH])
    ]
    for f in fs:
        f.priority = score(f)
    apply_llm_cap(fs, 2)
    assert [f.llm_triage for f in fs] == [False, True, True]


def test_normalize_is_deterministic(tmp_path):
    result = ScanResult(target="t", findings=[code(), code("bandit", "B1"), dep()])
    a, b = normalize(result, tmp_path), normalize(result, tmp_path)
    assert [f.id for f in a.findings] == [f.id for f in b.findings]


def test_build_and_install_output_is_dropped_but_shipped_assets_are_raised():
    """Paths from a real Android app and a NestJS backend scan."""
    from gapscan.normalize import drop_generated

    def sec(path, rule="private-key"):
        return Finding(scanner="gitleaks", rule_id=rule, title="Private key", severity=Severity.HIGH,
                       category=Category.SECRET, file=path, start_line=5)  # fmt: skip

    fs = [
        sec(
            "app/build/intermediates/assets/prodDebug/mergeProdDebugAssets/google_cloud_credentials.json"
        ),
        sec(
            "app/build/intermediates/assets/devDebug/mergeDevDebugAssets/google_cloud_credentials.json"
        ),
        sec(
            "app/build/intermediates/assets/prodRelease/mergeProdReleaseAssets/google_cloud_credentials.json"
        ),
        sec(
            "app/build/generated/source/buildConfig/prod/debug/com/x/BuildConfig.java",
            "generic-api-key",
        ),
        sec("node_modules/bcrypt/test/key.pem"),
        sec("dist/modules/auth/auth.service.js", "generic-api-key"),
        sec("secrets.properties", "github-pat"),
        sec("src/main/assets/config.json"),
        sec("tools/build/release.sh", "generic-api-key"),  # a source folder named build is kept
    ]
    kept, dropped = drop_generated(fs)
    assert dropped == 4
    assert [f.file for f in kept] == [fs[0].file, fs[3].file, "secrets.properties", "src/main/assets/config.json",
                                      "tools/build/release.sh"]  # fmt: skip
    shipped = kept[0]
    assert shipped.raw["shipped_in_app"] and shipped.severity == Severity.CRITICAL
    assert "packaged inside the app" in shipped.title


def test_build_and_developer_scripts_rank_below_app_code():
    from gapscan.normalize import classify_context, score

    def code(path: str) -> Finding:
        f = Finding(scanner="semgrep", rule_id="r", title="t", severity=Severity.HIGH,
                    category=Category.CODE, file=path, start_line=1)  # fmt: skip
        classify_context(f)
        return f

    app = code("app/src/main/kotlin/Login.kt")
    tool, ci = code("tools/localazy/download.py"), code(".github/workflows/build.yml")
    assert tool.is_tooling_code and not app.is_tooling_code and not ci.is_tooling_code
    assert score(tool) < score(app) == score(ci)
    assert (
        code("fastlane/Fastfile").is_tooling_code and code("app/build.gradle.kts").is_tooling_code
    )
