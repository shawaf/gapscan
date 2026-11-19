"""Synthetic scans for the dashboard's performance and robustness tests (no scanner needed)."""

from __future__ import annotations

import random

from gapscan.config import Config
from gapscan.models import Category, Finding, ScannerRun, ScanResult, Severity
from gapscan.report.build import build_report
from gapscan.report.schema import ReportData

CWES = [
    "CWE-89",
    "CWE-78",
    "CWE-79",
    "CWE-22",
    "CWE-502",
    "CWE-327",
    "CWE-798",
    "CWE-918",
    "CWE-352",
    "CWE-20",
]
SCANNERS = ["semgrep", "bandit", "trivy", "osv", "gitleaks", "checkov"]


def synthetic_scan(n: int, seed: int = 7, nasty: bool = False) -> ScanResult:
    rng = random.Random(seed)
    sevs = list(Severity)
    findings = []
    for i in range(n):
        cat = rng.choice(
            [Category.CODE] * 6 + [Category.DEPENDENCY] * 2 + [Category.SECRET, Category.CONFIG]
        )
        cwe = [rng.choice(CWES)]
        title = f"Synthetic finding {i} ({cwe[0]})"
        if nasty and i == 0:
            title = '<img src=x onerror="window.__xss=1"> </script><script>window.__xss=1</script>'
        f = Finding(
            id=f"syn{i:06d}",
            scanner=rng.choice(SCANNERS),
            rule_id=f"rule.{i % 97}",
            title=title,
            severity=rng.choice(sevs),
            category=cat,
            cwe=cwe,
            owasp_top10=[f"A0{1 + i % 9}:2025"],
            asvs=[f"v5.0.0-1.{1 + i % 5}.{1 + i % 7}"] if i % 3 == 0 else [],
            file=None if cat == Category.DEPENDENCY else f"src/module_{i % 400}/file_{i % 37}.py",
            start_line=None if cat == Category.DEPENDENCY else 1 + i % 500,
            end_line=None if cat == Category.DEPENDENCY else 1 + i % 500,
            package=f"pkg{i % 150}" if cat == Category.DEPENDENCY else None,
            version="1.0.0" if cat == Category.DEPENDENCY else None,
            priority=float(rng.randint(1, 100)),
            message="a message",
            sources=[rng.choice(SCANNERS)],
        )
        findings.append(f)
    return ScanResult(target="synthetic", findings=findings, runs=[ScannerRun(scanner=s, status="ok", finding_count=n // 6) for s in SCANNERS],
                      created_at="2026-10-02T00:00:00Z", gapscan_version="test")  # fmt: skip


def synthetic_report(n: int, **kw: object) -> ReportData:
    return build_report(
        synthetic_scan(n, nasty=bool(kw.pop("nasty", False))),
        [],
        None,
        config=Config(),
        target=None,
        project="synthetic",
        **kw,
    )  # type: ignore[arg-type]
