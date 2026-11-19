"""The security pack's registration, through the `gapscan.packs` entry point (`pyproject.toml`):
its scanners, in the order the manager offers them, and its target packs (OWASP Top 10, ASVS,
MASVS), in the order a finding's controls are listed. It also gives the engine the steps it runs
for this domain: the scan step (scanners plus the SBOM), the annotators inside normalize (secret
facts, dependency reachability, KEV and EPSS), and which findings get a data-flow trace."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from .agent.triage import weakness_kind
from .config import Config
from .enrich import Enrichment, load_enrichment
from .malware import MalwareScanner
from .models import Finding
from .owasp.packs import security_target_packs
from .reachability import annotate as annotate_reachability
from .registry import Registry
from .scanners import scan_target
from .scanners.bandit import BanditScanner
from .scanners.checkov import CheckovScanner
from .scanners.gitleaks import GitleaksScanner
from .scanners.osv import OSVScanner
from .scanners.semgrep import SemgrepScanner
from .scanners.trivy import TrivyScanner
from .secret_facts import annotate_secrets
from .taint.scanner import TaintScanner


def register(reg: Registry) -> None:
    for target in security_target_packs():
        reg.add_target_pack(target)
    reg.add_collector(scan_target)
    reg.add_annotator(lambda c: SecretFacts())
    reg.add_annotator(lambda c: Reachability())  # before KEV/EPSS, as scoring reads both
    reg.add_annotator(vuln_enrichment)
    # Weak algorithms and insecure settings are judged by what was chosen, not by data flow.
    reg.add_flow_filter(lambda f: weakness_kind(f) == "dataflow")
    # The Security service's capabilities. A project enables these, and the enabled set maps to the
    # scanners below (see registry.scanners_for_capabilities). "containers" and "dynamic" are
    # declared for the model but have no scanners yet: image scanning runs from its own step when
    # images are supplied, and dynamic (DAST) is a later stage.
    reg.add_capability(
        "sast", "Static analysis (SAST)",
        description="GapScan's own rules and data-flow analysis over your source code",
    )  # fmt: skip
    reg.add_capability(
        "sca", "Dependencies (SCA)",
        description="Known-vulnerable and malicious dependencies, with reachability",
    )  # fmt: skip
    reg.add_capability(
        "secrets", "Secrets",
        description="Hard-coded credentials and keys (locations only; values are redacted)",
    )  # fmt: skip
    reg.add_capability(
        "iac", "Infrastructure as code",
        description="Terraform, Kubernetes and Dockerfile misconfiguration",
    )  # fmt: skip
    reg.add_capability(
        "containers", "Container images",
        description="Vulnerabilities in built container images",
        reserved=True,
    )  # fmt: skip
    reg.add_capability(
        "dynamic", "Dynamic analysis (DAST)",
        description="Running-application testing", reserved=True,
    )  # fmt: skip
    reg.add_scanner(
        "semgrep",
        _semgrep,
        capability="sast",
        description="Static analysis with local rules "
        "(GapScan's own rules for nine languages, plus the community rules if present)",
    )
    reg.add_scanner(
        "osv",
        lambda c: OSVScanner(c.scanners.osv.db_dir, c.scanners.timeout_s),
        capability="sca",
        description="Dependency vulnerabilities from an offline database",
    )
    reg.add_scanner(
        "trivy", _trivy, capability="sca",
        description="Dependencies, configuration and the SBOM",
    )  # fmt: skip
    reg.add_scanner(
        "gitleaks",
        lambda c: GitleaksScanner(c.scanners.timeout_s),
        capability="secrets",
        description="Secrets (locations only, values are redacted)",
    )
    reg.add_scanner(
        "checkov",
        lambda c: CheckovScanner(c.scanners.timeout_s),
        capability="iac",
        description="Infrastructure as code (Terraform, Kubernetes, Dockerfile)",
    )
    reg.add_scanner(
        "bandit",
        lambda c: BanditScanner(c.scanners.timeout_s),
        capability="sast",
        description="Python security checks",
    )
    # Built in (no binary, offline, fast): run whenever enabled, not offered in the picker.
    reg.add_scanner(
        "taint",
        lambda c: TaintScanner(c.scanners.timeout_s),
        selectable=False,
        capability="sast",
        description="Built-in data-flow analysis (no program needed)",
    )
    reg.add_scanner(
        "malware",
        _malware,
        selectable=False,
        capability="sca",
        description="Malicious packages: OSV MAL advisories and a typosquat check",
    )


def _semgrep(c: Config) -> SemgrepScanner:
    return SemgrepScanner(c.scanners.semgrep.rules_path, c.scanners.timeout_s)


def _trivy(c: Config) -> TrivyScanner:
    return TrivyScanner(c.scanners.trivy.cache_dir, c.scanners.timeout_s)


def _malware(c: Config) -> MalwareScanner:
    return MalwareScanner(c.scanners.osv.db_dir, c.scanners.timeout_s)


class SecretFacts:
    """Facts computed from each secret's withheld value; collapses Firebase client keys. Runs
    before findings are merged, so the collapsed keys are not merged first."""

    stage: Literal["evidence", "context"] = "evidence"

    def annotate(self, findings: list[Finding], target: Path) -> list[Finding]:
        return annotate_secrets(findings, target)

    def data_dates(self) -> dict[str, str]:
        return {}


class Reachability:
    """Whether the project's code reaches each vulnerable dependency."""

    stage: Literal["evidence", "context"] = "context"

    def annotate(self, findings: list[Finding], target: Path) -> list[Finding]:
        annotate_reachability(findings, target)
        return findings

    def data_dates(self) -> dict[str, str]:
        return {}


class VulnEnrichment:
    """CISA KEV and FIRST EPSS for findings with CVEs, from the offline mirrors."""

    stage: Literal["evidence", "context"] = "context"

    def __init__(self, enrichment: Enrichment) -> None:
        self.enrichment = enrichment

    def annotate(self, findings: list[Finding], target: Path) -> list[Finding]:
        for f in findings:
            if f.cve:
                f.kev, f.epss = self.enrichment.for_cves(f.cve)
        return findings

    def data_dates(self) -> dict[str, str]:
        return dict(self.enrichment.dates)


def vuln_enrichment(config: Config | None) -> VulnEnrichment | None:
    """Needs the configured data folder: without a config there is nothing to read."""
    return VulnEnrichment(load_enrichment(config.data.enrichment_dir)) if config else None
