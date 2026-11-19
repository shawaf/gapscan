"""Infrastructure-as-code and container-image views: grouping and counts for the dashboard.

Computed here (never in the browser or by a model) from the open finding rows. IaC findings are
grouped by the kind of file (Dockerfile, Kubernetes, Terraform, ...); image findings by image."""

from __future__ import annotations

import re
from collections import Counter, defaultdict

from .schema import FindingRow, IacFile, IacGroup, ImageSummary

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# (label, path pattern, rule-id pattern); the first match wins, path before rule id.
IAC_KINDS: list[tuple[str, re.Pattern[str], re.Pattern[str] | None]] = [
    ("Dockerfile", re.compile(r"(^|/)(Dockerfile|Containerfile)([.-][\w.-]+)?$|\.dockerfile$", re.I),
     re.compile(r"^(CKV2?_DOCKER_|AVD-DS-|DS\d)|dockerfile", re.I)),
    ("Docker Compose", re.compile(r"(^|/)(docker-)?compose([.-][\w-]+)?\.ya?ml$", re.I),
     re.compile(r"docker-compose", re.I)),
    ("CI pipeline", re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|azure-pipelines\.ya?ml|Jenkinsfile|bitbucket-pipelines\.ya?ml)$", re.I),
     re.compile(r"^(CKV2?_(GHA|GITLAB|AZUREPIPELINES|BITBUCKET)_)|github-actions", re.I)),
    ("Terraform", re.compile(r"\.(tf|tf\.json|tfvars|hcl)$", re.I), re.compile(r"terraform", re.I)),
    ("Helm", re.compile(r"(^|/)(charts?|helm)/|(^|/)Chart\.ya?ml$|(^|/)values(\.[\w-]+)?\.ya?ml$", re.I), None),
    ("Kubernetes", re.compile(r"(^|/)(k8s|kubernetes|manifests?|kustomize)/|kustomization\.ya?ml$", re.I),
     re.compile(r"^(CKV2?_K8S_|AVD-KSV-|KSV\d)|kubernetes", re.I)),
    ("CloudFormation", re.compile(r"cloudformation|(^|/)[\w.-]+\.template\.(json|ya?ml)$", re.I),
     re.compile(r"cloudformation", re.I)),
]  # fmt: skip
OTHER_KIND = "Other configuration"


def iac_kind(row: FindingRow) -> str:
    path = row.file or ""
    for label, pattern, _ in IAC_KINDS:
        if pattern.search(path):
            return label
    for label, _, rule in IAC_KINDS:
        if rule is not None and rule.search(row.rule_id):
            return label
    return OTHER_KIND


def _worst(severities: list[str]) -> str:
    return min(severities, key=SEVERITY_ORDER.index, default="info")


def _sev(row: FindingRow) -> str:
    return row.severity_adjusted or row.severity


def infrastructure(rows: list[FindingRow]) -> list[IacGroup]:
    """Open IaC findings grouped by kind of file, worst kind first; files worst first."""
    by_kind: dict[str, dict[str, list[FindingRow]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r.open and r.asset == "iac":
            by_kind[iac_kind(r)][r.file or "(no file)"].append(r)
    groups = []
    for kind, files in by_kind.items():
        items = [
            IacFile(
                file=f,
                findings=len(rs),
                max_severity=_worst([_sev(r) for r in rs]),
                finding_ids=[r.id for r in rs],
            )  # fmt: skip
            for f, rs in files.items()
        ]
        items.sort(key=lambda i: (SEVERITY_ORDER.index(i.max_severity), -i.findings, i.file))
        sev = Counter(_sev(r) for rs in files.values() for r in rs)
        groups.append(IacGroup(kind=kind, files=items,
                               by_severity={s: sev.get(s, 0) for s in SEVERITY_ORDER}))  # fmt: skip
    groups.sort(key=lambda g: tuple(-g.by_severity[s] for s in SEVERITY_ORDER) + (g.kind,))
    return groups


def _image_name(file: str | None) -> tuple[str, str]:
    """`image:app.tar > usr/lib/x` -> ("app.tar", "usr/lib/x")."""
    text = (file or "").removeprefix("image:")
    name, _, inside = text.partition(" > ")
    return name or "(image)", inside


def images(rows: list[FindingRow]) -> list[ImageSummary]:
    """Open findings of each scanned container image, with what fixing it would take."""
    by_image: dict[str, list[FindingRow]] = defaultdict(list)
    for r in rows:
        if r.open and r.asset == "image":
            by_image[_image_name(r.file)[0]].append(r)
    out = []
    for name, rs in sorted(by_image.items()):
        vulns = [r for r in rs if r.category == "dependency"]
        sev = Counter(_sev(r) for r in rs)
        out.append(ImageSummary(
            image=name, findings=len(rs), by_severity={s: sev.get(s, 0) for s in SEVERITY_ORDER},
            vulnerabilities=len(vulns),
            vulnerable_packages=len({(r.package, r.version) for r in vulns if r.package}),
            fixable=sum(1 for r in vulns if r.fixed_version), kev=sum(1 for r in vulns if r.kev),
            misconfigurations=sum(1 for r in rs if r.category == "config"),
            secrets=sum(1 for r in rs if r.category == "secret"),
            locations=sorted({loc for r in rs if (loc := _image_name(r.file)[1])}),
            finding_ids=[r.id for r in rs],
        ))  # fmt: skip
    return out
