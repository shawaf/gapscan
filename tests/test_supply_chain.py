"""Manifests, dependency reachability, malicious/typosquat packages, image findings, assets."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from gapscan.malware import MalwareScanner, edit_distance, load_malicious, typosquat_findings
from gapscan.manifests import Dep, canonical, declared_dependencies
from gapscan.models import Category, Finding, ScanResult, Severity
from gapscan.normalize import normalize, score
from gapscan.reachability import annotate
from gapscan.scanners.trivy import parse_trivy


def dep_finding(pkg: str, cve: str, eco: str, file: str, sev: Severity = Severity.HIGH) -> Finding:
    return Finding(
        scanner="osv", rule_id=cve, title=cve, severity=sev, category=Category.DEPENDENCY,
        file=file, package=pkg, version="1.0", cve=[cve], raw={"ecosystem": eco},
    )  # fmt: skip


def test_manifest_parsing_covers_the_main_ecosystems(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("# c\nRequests==2.31.0\nflask[async]>=2\n-e .\n")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"jest": "29"}})
    )
    (tmp_path / "go.mod").write_text(
        "module x\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n)\n"
    )
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>org.x</groupId>"
        "<artifactId>y</artifactId><version>1.0</version></dependency></dependencies></project>"
    )
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["httpx>=0.2"]\n')
    got = {
        (d.ecosystem, canonical(d.ecosystem, d.name)): d for d in declared_dependencies(tmp_path)
    }
    assert ("PyPI", "requests") in got and got[("PyPI", "requests")].version == "2.31.0"
    assert ("PyPI", "flask") in got and ("PyPI", "httpx") in got
    assert ("npm", "lodash") in got and got[("npm", "jest")].dev
    assert ("Go", "github.com/a/b") in got and ("Maven", "org.x:y") in got


def test_reachability_statuses(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("pyyaml==5.1\nrequests==2.0\nunused-lib==1\n")
    (tmp_path / "app.py").write_text("import yaml\nimport requests\ncfg = yaml.load(open('x'))\n")
    (tmp_path / "other.py").write_text("import requests\nrequests.get('u')\n")
    fs = [
        dep_finding("pyyaml", "CVE-2020-1747", "PyPI", "requirements.txt"),  # curated hint: load()
        dep_finding("requests", "CVE-2099-1", "PyPI", "requirements.txt"),  # no symbol data
        dep_finding("unused-lib", "CVE-2099-2", "PyPI", "requirements.txt"),  # declared, unused
        dep_finding("deep-dep", "CVE-2099-3", "PyPI", "requirements.txt"),  # transitive
    ]
    annotate(fs, tmp_path)
    by = {f.package: f for f in fs}
    assert by["pyyaml"].reachability == "reachable"
    assert "app.py:3" in " ".join(by["pyyaml"].reachability_evidence)
    assert by["requests"].reachability == "imported"
    assert by["unused-lib"].reachability == "not_imported"
    assert by["deep-dep"].reachability == "transitive"


def test_advisory_symbols_make_unused_function_not_reachable(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("libx==1\n")
    (tmp_path / "a.py").write_text("import libx\nlibx.safe_call()\n")
    f = dep_finding("libx", "CVE-2099-9", "PyPI", "requirements.txt")
    f.raw["symbols"] = ["dangerous_call"]
    annotate([f], tmp_path)
    assert f.reachability == "not_reachable"
    (tmp_path / "a.py").write_text("import libx\nlibx.dangerous_call(1)\n")
    annotate([f], tmp_path)
    assert f.reachability == "reachable"


def test_reachability_changes_priority_but_kev_stays_on_top() -> None:
    base = dep_finding("p", "CVE-1", "PyPI", "r.txt")
    r, n, i = (
        base.model_copy(update={"reachability": s})
        for s in ("reachable", "not_reachable", "not_imported")
    )
    assert score(r) > score(base) > score(i) > score(n)
    kev = base.model_copy(update={"kev": True, "reachability": "not_reachable"})
    assert score(kev) == 100.0


def test_normalize_sets_reachability_and_asset(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("libx==1\n")
    res = ScanResult(
        target=str(tmp_path),
        findings=[
            dep_finding("libx", "CVE-2099-1", "PyPI", "requirements.txt"),
            Finding(scanner="checkov", rule_id="CKV", title="t", severity=Severity.LOW, category=Category.CONFIG, file="main.tf", start_line=1),
        ],
    )  # fmt: skip
    out = normalize(res, tmp_path)
    assert {f.rule_id: f.asset for f in out.findings} == {"CVE-2099-1": "dependency", "CKV": "iac"}
    assert next(f for f in out.findings if f.package).reachability == "not_imported"


def make_osv_db(root: Path) -> Path:
    z = root / "osv-scalibr" / "PyPI"
    z.mkdir(parents=True)
    with zipfile.ZipFile(z / "all.zip", "w") as zf:
        zf.writestr("PYSEC-1.json", json.dumps({"id": "PYSEC-1", "affected": []}))
        zf.writestr(
            "MAL-2024-1.json",
            json.dumps({"id": "MAL-2024-1", "summary": "steals env", "affected": [
                {"package": {"ecosystem": "PyPI", "name": "Evil_Pkg"}, "versions": ["1.0.0"]}]}),
        )  # fmt: skip
    return root


def test_known_malicious_package_is_critical(tmp_path: Path) -> None:
    db = make_osv_db(tmp_path / "db")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("evil-pkg==1.0.0\nrequests==2.0\n")
    assert ("PyPI", "evil-pkg") in load_malicious(db)
    (f,) = MalwareScanner(db).run(proj, tmp_path)
    assert f.severity == Severity.CRITICAL and f.rule_id == "MAL-2024-1" and f.cwe == ["CWE-506"]
    assert f.file == "requirements.txt" and f.start_line == 1
    (proj / "requirements.txt").write_text("evil-pkg==2.0.0\n")  # a version the advisory omits
    assert MalwareScanner(db).run(proj, tmp_path) == []


def test_typosquat_heuristic() -> None:
    def names(*pairs: tuple[str, str]) -> list[str]:
        deps = [Dep(e, n, None, "f", 1) for e, n in pairs]
        return [f.raw["similar_to"] for f in typosquat_findings(deps)]

    assert names(("PyPI", "reqeusts")) == ["requests"]  # swapped letters
    assert names(("npm", "lodahs")) == ["lodash"]
    assert (
        names(("PyPI", "requests"), ("npm", "react"), ("PyPI", "mylib")) == []
    )  # popular/unrelated
    assert names(("npm", "@scope/reactt")) == []  # scoped names are not squatting a bare name
    assert edit_distance("abc", "acb") == 1 and edit_distance("abc", "xyz") == 3


def test_image_findings_parse_like_trivy_and_asset_is_image() -> None:
    data = json.loads((Path(__file__).parent / "data" / "trivy.json").read_text())
    fs = parse_trivy(data)
    assert fs
    for f in fs:
        f.raw["asset"] = "image"
    from gapscan.normalize import classify_asset

    classify_asset(fs[0])
    assert fs[0].asset == "image"


def test_malicious_release_of_a_real_package_respects_the_declared_range(tmp_path: Path) -> None:
    """ng2-file-upload had compromised 7.x-9.x releases in 2025; `^10.0.0` cannot install them."""
    from gapscan.malware import malicious_findings

    z = tmp_path / "db" / "osv-scalibr" / "npm"
    z.mkdir(parents=True)
    bad = ["7.0.2", "7.0.3", "8.0.1", "8.0.2", "8.0.3", "9.0.1"]
    with zipfile.ZipFile(z / "all.zip", "w") as zf:
        zf.writestr("MAL-2025-47196.json", json.dumps({"id": "MAL-2025-47196", "affected": [
            {"package": {"ecosystem": "npm", "name": "ng2-file-upload"}, "versions": bad}]}))  # fmt: skip

    def hits(spec: str | None) -> int:
        dep = Dep("npm", "ng2-file-upload", spec, "package.json", 1)
        return len(malicious_findings([dep], tmp_path / "db"))

    assert hits("^10.0.0") == 0 and hits("~9.0.2") == 0
    assert hits("^8.0.0") == 1 and hits("~7.0.1") == 1 and hits("9.0.1") == 1
    assert hits(">=6") == 1 and hits(None) == 1  # anything we cannot rule out stays reported
