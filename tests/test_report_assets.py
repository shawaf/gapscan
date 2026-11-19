"""Infrastructure and container-image views of the report (computed in Python)."""

from __future__ import annotations

from typing import Any

import pytest

from gapscan.report.assets import iac_kind, images, infrastructure
from gapscan.report.schema import FindingRow


def row(i: str, file: str, *, asset: str = "iac", sev: str = "medium", rule: str = "r",
        category: str = "config", **kw: Any) -> FindingRow:  # fmt: skip
    return FindingRow(id=i, title="t", rule_id=rule, severity=sev, category=category, priority=1,
                      verdict="not_triaged", file=file, asset=asset, **kw)  # fmt: skip


@pytest.mark.parametrize(
    ("file", "rule", "kind"),
    [
        ("Dockerfile", "r", "Dockerfile"),
        ("services/api/Dockerfile.prod", "r", "Dockerfile"),
        ("build/app.dockerfile", "r", "Dockerfile"),
        ("docker-compose.override.yml", "r", "Docker Compose"),
        (".github/workflows/ci.yml", "r", "CI pipeline"),
        (".gitlab-ci.yml", "r", "CI pipeline"),
        ("infra/main.tf", "r", "Terraform"),
        ("charts/app/templates/deployment.yaml", "r", "Helm"),
        ("k8s/deployment.yaml", "r", "Kubernetes"),
        ("deploy/app.yaml", "CKV_K8S_8", "Kubernetes"),  # no telling path: the rule decides
        ("stack.template.yaml", "r", "CloudFormation"),
        ("config/settings.ini", "r", "Other configuration"),
    ],
)
def test_iac_kind(file: str, rule: str, kind: str) -> None:
    assert iac_kind(row("x", file, rule=rule)) == kind


def test_infrastructure_groups_open_iac_findings_worst_first() -> None:
    rows = [
        row("1", "Dockerfile", sev="low"),
        row("2", "Dockerfile", sev="high"),
        row("3", "k8s/a.yaml", sev="medium"),
        row("4", "k8s/b.yaml", sev="critical"),
        row("5", "k8s/b.yaml", sev="low", open=False),  # dismissed: not counted
        row("6", "app.py", asset="code", category="code"),  # not infrastructure
        row("7", "Dockerfile", sev="low", severity_adjusted="info"),  # the reviewed severity counts
    ]
    groups = infrastructure(rows)
    assert [g.kind for g in groups] == ["Kubernetes", "Dockerfile"]  # a critical beats a high
    k8s, docker = groups
    assert [f.file for f in k8s.files] == ["k8s/b.yaml", "k8s/a.yaml"]
    assert k8s.files[0].finding_ids == ["4"] and k8s.by_severity["low"] == 0
    assert docker.files[0].findings == 3 and docker.files[0].max_severity == "high"
    assert docker.by_severity == {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 1}


def test_image_summary_counts_and_fixability() -> None:
    img = "image:app.tar > app.tar (debian 12.15)"
    py = "image:app.tar > Python"
    rows = [
        row("a", img, asset="image", category="dependency", sev="critical", package="openssl",
            version="3.0.1", fixed_version="3.0.2", kev=True),
        row("b", img, asset="image", category="dependency", sev="high", package="openssl",
            version="3.0.1"),
        row("c", py, asset="image", category="dependency", sev="low", package="jinja2", version="2.0"),
        row("d", "image:app.tar > Dockerfile", asset="image", category="config", sev="medium"),
        row("e", "image:other.tar", asset="image", category="secret", sev="high"),
        row("f", "requirements.txt", asset="dependency", category="dependency", package="x"),
    ]  # fmt: skip
    app, other = images(rows)
    assert (app.image, other.image) == ("app.tar", "other.tar")
    assert app.findings == 4 and app.vulnerabilities == 3 and app.vulnerable_packages == 2
    assert app.fixable == 1 and app.kev == 1 and app.misconfigurations == 1 and app.secrets == 0
    assert app.locations == ["Dockerfile", "Python", "app.tar (debian 12.15)"]
    assert app.by_severity["critical"] == 1 and other.secrets == 1 and other.locations == []
