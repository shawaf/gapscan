"""Zero-day watch: a saved scan's SBOM is re-checked offline, only advisories the scan did not
know are reported, ranked KEV > reachable > EPSS > severity, and notifications cannot be used to run
AppleScript. osv-scanner itself is replaced by a recorded answer (CI needs no binaries)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from gapscan.enrich import Enrichment
from gapscan.models import Category, Finding, ScanResult, Severity
from gapscan.notify import desktop_notify, notify_command
from gapscan.scanners.osv import OSVScanner
from gapscan.watch import SBOM_NAME, WatchAlert, alert_line, priority, purl_ecosystem, watch_scan

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.25.1",
            "purl": "pkg:pypi/requests@2.25.1",
        },
        {
            "type": "library",
            "name": "yamlparse",
            "version": "1.0.0",
            "purl": "pkg:pypi/yamlparse@1.0.0",
        },
        {
            "type": "library",
            "name": "left-pad",
            "version": "1.0.0",
            "purl": "pkg:npm/left-pad@1.0.0",
        },
        {"type": "library", "name": "rexml", "version": "3.2.5", "purl": "pkg:gem/rexml@3.2.5"},
        {"type": "application", "name": "project"},
    ],
}


def vuln(vid: str, cve: str, fixed: str, summary: str = "s") -> dict[str, Any]:
    return {
        "id": vid,
        "summary": summary,
        "aliases": [cve],
        "affected": [
            {
                "package": {"name": "x"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": fixed}]}],
            }
        ],
    }


def osv_answer(sbom_path: str) -> dict[str, Any]:
    def pkg(name: str, version: str, eco: str, vulns: list[dict[str, Any]]) -> dict[str, Any]:
        for v in vulns:
            v["affected"][0]["package"]["name"] = name
        return {
            "package": {"name": name, "version": version, "ecosystem": eco},
            "vulnerabilities": vulns,
        }

    return {
        "results": [
            {
                "source": {"path": sbom_path},
                "packages": [
                    # known: the saved scan already reported it
                    pkg(
                        "requests", "2.25.1", "PyPI", [vuln("GHSA-old", "CVE-2023-0001", "2.31.0")]
                    ),
                    # new, exploited in the wild
                    pkg(
                        "requests", "2.25.1", "PyPI", [vuln("GHSA-new", "CVE-2026-1111", "2.32.4")]
                    ),
                    # new, and the project calls the vulnerable function; OSV has it twice
                    # (PYSEC and GHSA, same CVE): one alert, the GitHub advisory
                    pkg(
                        "yamlparse",
                        "1.0.0",
                        "PyPI",
                        [
                            vuln("PYSEC-2026-9", "CVE-2026-2222", "1.0.3"),
                            vuln("GHSA-yaml", "CVE-2026-2222", "1.0.3"),
                        ],
                    ),
                ],
            }
        ]
    }


@pytest.fixture
def scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[OSVScanner, list[list[str]]]:
    for eco in ("PyPI", "npm"):
        d = tmp_path / "db" / "osv-scalibr" / eco
        d.mkdir(parents=True)
        (d / "all.zip").write_bytes(b"")
    s = OSVScanner(tmp_path / "db")
    seen: list[list[str]] = []

    def fake(argv: list[str], timeout_s: int | None = None) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        lock = argv[argv.index("-L") + 1]
        out = argv[argv.index("--output") + 1]
        Path(out).write_text(json.dumps(osv_answer(lock)), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 1, "", "")

    monkeypatch.setattr(s, "_exec", fake)
    return s, seen


def saved_scan() -> ScanResult:
    old = Finding(
        scanner="osv", rule_id="GHSA-old", title="old", severity=Severity.HIGH,
        category=Category.DEPENDENCY, file="requirements.txt", package="requests",
        version="2.25.1", cve=["CVE-2023-0001"],
    )  # fmt: skip
    return ScanResult(target="/work/payments-api", created_at="2026-11-01T00:00:00+00:00",
                      findings=[old], sbom=json.loads(json.dumps(SBOM)))  # fmt: skip


@pytest.fixture
def project(tmp_path: Path) -> Path:
    p = tmp_path / "payments-api"
    (p / "api").mkdir(parents=True)
    (p / "requirements.txt").write_text("requests==2.25.1\nyamlparse==1.0.0\n")
    (p / "api" / "client.py").write_text(
        "import requests\nimport yamlparse\n\ndoc = yamlparse.load(data)\n"
    )
    return p


def test_only_new_advisories_are_reported_and_ranked(
    scanner, tmp_path, project, monkeypatch
) -> None:
    s, seen = scanner
    monkeypatch.setattr(
        "gapscan.reachability.symbols_for",
        lambda f, eco: ["load"] if f.package == "yamlparse" else [],
    )
    enrich = Enrichment(
        kev={"CVE-2026-1111"}, epss={"CVE-2026-2222": 0.4}, dates={"kev": "2026-11-19"}
    )
    report = watch_scan(
        saved_scan(), "payments-api", s, tmp_path / "work", enrichment=enrich, target=project
    )

    argv = seen[0]
    assert "--offline" in argv and argv[argv.index("-L") + 1].endswith(SBOM_NAME)
    checked = json.loads((tmp_path / "work" / SBOM_NAME).read_text())["components"]
    assert [c["name"] for c in checked] == ["requests", "yamlparse", "left-pad"]  # no gem database
    assert report.skipped_ecosystems == ["RubyGems"]
    assert report.components == 3 and report.known == 1
    assert [a.advisory for a in report.alerts] == ["GHSA-new", "GHSA-yaml"]
    kev, reach = report.alerts
    assert kev.kev and kev.fixed_version == "2.32.4" and kev.declared_in == "requirements.txt"
    assert reach.reachability == "reachable" and reach.epss == 0.4
    assert "api/client.py:4" in reach.reachability_evidence[0]
    assert kev.priority > reach.priority
    assert report.vuln_data == {"kev": "2026-11-19"}


def test_without_an_sbom_the_watch_says_how_to_get_one(scanner, tmp_path) -> None:
    s, seen = scanner
    report = watch_scan(ScanResult(target="x"), "x", s, tmp_path / "w")
    assert report.alerts == [] and "SBOM" in report.note and seen == []


def test_priority_order() -> None:
    base = {"project": "p", "advisory": "a", "package": "x"}
    kev = WatchAlert(**base, severity=Severity.LOW, kev=True)
    reachable = WatchAlert(**base, severity=Severity.MEDIUM, reachability="reachable", epss=0.9)
    critical = WatchAlert(**base, severity=Severity.CRITICAL, reachability="not_reachable")
    assert priority(kev) > priority(reachable) > priority(critical)


def test_purl_ecosystems() -> None:
    assert purl_ecosystem("pkg:pypi/requests@1") == "PyPI"
    assert purl_ecosystem("pkg:maven/org.x/y@1") == "Maven"
    assert purl_ecosystem("pkg:unknown/x@1") is None and purl_ecosystem("requests") is None


def test_alert_line_names_the_proof() -> None:
    a = WatchAlert(project="payments-api", advisory="GHSA-1", cve=["CVE-2026-1"], package="yamlparse",
                   version="1.0.0", severity=Severity.HIGH, kev=True, reachability="reachable",
                   reachability_evidence=["vulnerable function called at api/client.py:4: x"],
                   fixed_version="1.0.3")  # fmt: skip
    line = alert_line(a)
    assert line.startswith("yamlparse 1.0.0 in payments-api: CVE-2026-1")
    assert "CISA KEV" in line and "api/client.py:4" in line and "fixed in 1.0.3" in line


def test_notification_text_is_an_argument_not_applescript() -> None:
    evil = 'pkg"\ndo shell script "rm -rf ~"'
    args = notify_command("GapScan", evil, platform="darwin")
    assert args is not None and args[0] == "osascript"
    assert all(evil not in a for a in args[:-2])  # the script lines never contain the text
    assert args[-1] == 'pkg" do shell script "rm -rf ~"'  # control characters removed


def test_notify_never_raises() -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise OSError("no osascript")

    assert desktop_notify("t", "b", runner=boom, platform="darwin") is False
    assert notify_command("t", "b", platform="win32") is None


def test_cli_watch_writes_alerts_and_fails_on_alert(scanner, tmp_path, monkeypatch) -> None:
    from gapscan.cli import app

    s, _ = scanner
    monkeypatch.setattr("gapscan.scanners.osv.OSVScanner.is_available", lambda self: True)
    monkeypatch.setattr(
        "gapscan.scanners.osv.OSVScanner._exec", lambda self, argv, timeout_s=None: s._exec(argv)
    )
    monkeypatch.setattr(
        "gapscan.scanners.osv.OSVScanner.installed_ecosystems", lambda self: {"PyPI"}
    )
    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "gapscan.notify.desktop_notify", lambda t, b, **k: sent.append((t, b)) or True
    )
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(saved_scan().model_dump_json())
    cfg = tmp_path / "gapscan.toml"
    cfg.write_text(f'[data]\ndir = "{tmp_path / "data"}"\n')
    out = tmp_path / "alerts.json"
    r = CliRunner().invoke(
        app,
        ["watch", str(scan_file), "-o", str(out), "--notify", "--fail-on-alert", "-c", str(cfg)],
    )
    assert r.exit_code == 3, r.output
    assert "2 new advisories" in r.output
    data = json.loads(out.read_text())
    assert [a["advisory"] for a in data[0]["alerts"]] == ["GHSA-new", "GHSA-yaml"]
    assert sent and sent[0][0] == "GapScan: 2 new advisories"


def test_cli_watch_needs_a_scan_or_all(tmp_path) -> None:
    from gapscan.cli import app

    cfg = tmp_path / "gapscan.toml"
    cfg.write_text(f'[data]\ndir = "{tmp_path / "data"}"\n')
    r = CliRunner().invoke(app, ["watch", "-c", str(cfg)])
    assert r.exit_code == 2
