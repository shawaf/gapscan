"""`gapscan doctor`: check that scanners, the LLM endpoint/model and vuln DBs are
present, and report their versions. Diagnostic only — never used during a scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import httpx

from .config import Config
from .registry import scanner_status


class Status(StrEnum):
    OK = "ok"
    MISSING = "missing"
    WARN = "warn"


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str


def check_scanners(config: Config) -> list[Check]:
    """Each enabled scanner, asked of its own adapter (gapscan.registry), so the doctor and the
    manager's scanner list always agree with what a scan will run."""
    checks: list[Check] = []
    for st in scanner_status(config, config.scanners.enabled):
        if not st.registered:
            packs = ", ".join(config.scanners.packs)
            checks.append(
                Check(st.name, Status.WARN, f"not registered by an allowed pack ({packs})")
            )
        elif not st.available:
            checks.append(Check(st.name, Status.MISSING, "not found: install it or put it on PATH"))
        else:
            detail = st.version or "available"
            checks.append(
                Check(
                    st.name, Status.OK, f"{detail} ({st.description})" if st.description else detail
                )
            )
    return checks


def check_llm(config: Config) -> list[Check]:
    """Probe the local LLM endpoint and verify the configured model is present.

    Hits the configured endpoint only, which the config validator has already
    constrained to localhost/internal hosts.
    """
    endpoint = config.llm.endpoint.rstrip("/")
    try:
        if config.llm.backend == "ollama":
            resp = httpx.get(f"{endpoint}/api/tags", timeout=5.0)
            resp.raise_for_status()
            models = [m.get("name", "") for m in resp.json().get("models", [])]
        else:  # openai-compatible
            resp = httpx.get(f"{endpoint}/v1/models", timeout=5.0)
            resp.raise_for_status()
            models = [m.get("id", "") for m in resp.json().get("data", [])]
    except (httpx.HTTPError, ValueError) as exc:
        return [Check("llm endpoint", Status.MISSING, f"{endpoint} unreachable: {exc}")]

    endpoint_check = Check("llm endpoint", Status.OK, f"{endpoint} ({config.llm.backend})")
    wanted = config.llm.model
    # Exact tag match; a bare name means ":latest". (A different size tag is NOT a match.)
    want = wanted if ":" in wanted else f"{wanted}:latest"
    model_ok = any(m in (wanted, want) for m in models)
    model_check = (
        Check("llm model", Status.OK, wanted)
        if model_ok
        else Check("llm model", Status.MISSING, f"{wanted!r} not pulled (have: {models or 'none'})")
    )
    return [endpoint_check, model_check]


def check_databases(config: Config) -> list[Check]:
    """Check presence of local vuln DBs / rules / KB index directories."""
    checks: list[Check] = []
    # GapScan's own rules are packaged with the code and always present. The Semgrep community rules
    # are an optional, license-restricted add-on that the product does not ship, so their absence is
    # a warning, never a failure.
    rules = config.scanners.semgrep.rules_path
    if rules.is_dir() and any(rules.iterdir()):
        checks.append(Check("semgrep rules", Status.OK, str(rules)))
    else:
        checks.append(
            Check(
                "semgrep rules",
                Status.WARN,
                "community rules not installed (optional); GapScan's own rules are used",
            )  # fmt: skip
        )
    required: list[tuple[str, Path]] = [
        ("osv db", config.scanners.osv.db_dir),
        ("trivy cache", config.scanners.trivy.cache_dir),
        ("kb index", config.data.kb_dir),
    ]
    for name, path in required:
        if path.is_dir() and any(path.iterdir()):
            checks.append(Check(name, Status.OK, str(path)))
        elif path.is_dir():
            checks.append(Check(name, Status.WARN, f"{path} is empty"))
        else:
            checks.append(Check(name, Status.MISSING, f"{path} not found"))
    return checks


def run_all_checks(config: Config) -> list[Check]:
    return [
        *check_scanners(config),
        *check_llm(config),
        *check_databases(config),
    ]
