"""System Health rows for the Control Center: each doctor check with a readable component name, a
group, a version and a how-to-fix hint, plus the date-based freshness of the offline data.

Everything is computed here (Python), never in the browser, and nothing is fetched."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from ..config import Config
from ..doctor import Check, Status
from ..scanners.semgrep import OWN_RULES

INSTALL = {
    "semgrep": ("Semgrep", "pip install semgrep   (or: brew install semgrep)"),
    "osv": ("OSV-Scanner", "brew install osv-scanner, or install it from the offline bundle"),
    "trivy": ("Trivy", "brew install trivy, or install it from the offline bundle"),
    "gitleaks": ("Gitleaks", "brew install gitleaks, or install it from the offline bundle"),
    "checkov": ("Checkov", "pip install checkov"),
    "bandit": ("Bandit", "pip install bandit"),
}
SCANNER_DETAIL = {
    "semgrep": "Static analysis with local rules.",
    "osv": "Dependency vulnerabilities from an offline database.",
    "trivy": "Dependencies, configuration and the SBOM.",
    "gitleaks": "Secret detection. Reports locations only, never values.",
    "checkov": "Infrastructure as code: Terraform, Kubernetes, Dockerfile.",
    "bandit": "Python security checks.",
}
STATUS = {Status.OK: "ok", Status.WARN: "warn", Status.MISSING: "problem"}


def own_rule_count(root: Any = OWN_RULES) -> int:
    count = 0
    for file in root.rglob("*.yaml") if root.is_dir() else []:
        count += sum(
            1
            for line in file.read_text(encoding="utf-8").splitlines()
            if line.startswith("  - id: ")
        )
    return count


def rows(cfg: Config, checks: list[Check]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in checks:
        status = STATUS[c.status]
        row: dict[str, Any] = {"name": c.name, "status": status, "component": c.name, "group": "Other",
                               "version": "", "detail": c.detail, "fix": ""}  # fmt: skip
        if c.name in INSTALL:
            label, hint = INSTALL[c.name]
            row.update(component=label, group="Scanner", version=c.detail if c.status == Status.OK else "Not found",
                       detail=SCANNER_DETAIL[c.name] if c.status == Status.OK else
                       f"Not found on PATH. Runs skip this tool, so its coverage is missing. ({c.detail})",
                       fix=hint if c.status != Status.OK else "")  # fmt: skip
        elif c.name == "llm endpoint":
            row.update(component="Model server", group="Model", version=cfg.llm.endpoint.replace("http://", ""),
                       detail="Local endpoint answered." if c.status == Status.OK else f"Not answering. {c.detail}",
                       fix="" if c.status == Status.OK else "Open Setup and start the AI engine, or start your own model server (for Ollama: ollama serve) and check llm.endpoint in gapscan.toml.")  # fmt: skip
        elif c.name == "llm model":
            row.update(component="Model", group="Model", version=cfg.llm.model,
                       detail=f"Active profile {cfg.llm.profile}." if c.status == Status.OK else f"Not available. {c.detail}",
                       fix="" if c.status == Status.OK else f"Download it in Setup, or run: ollama pull {cfg.llm.model}")  # fmt: skip
        elif c.name == "semgrep rules":
            n = own_rule_count()
            row.update(component="Rules", group="Rules", version=f"{n} GapScan rules",
                       detail=f"Community rule folder present. {n} GapScan rules for Kotlin, Swift and Dart always run." if c.status == Status.OK
                       else f"Community rule folder is missing or empty; the {n} GapScan rules still run.",
                       fix="" if c.status == Status.OK else "Fetch the rule pack or import an offline bundle (docs/offline.md).")  # fmt: skip
            if c.status != Status.OK:
                row["status"] = "warn"
        elif c.name == "osv db":
            row.update(component="Vulnerability database (OSV)", group="Data", version="local snapshot",
                       detail="Read by OSV-Scanner. Nothing is fetched during a scan." if c.status == Status.OK else c.detail,
                       fix="" if c.status == Status.OK else "Import an offline bundle, or refresh the database on a connected machine (docs/offline.md).")  # fmt: skip
        elif c.name == "trivy cache":
            row.update(component="Trivy databases", group="Data", version="local cache",
                       detail="Used by Trivy for dependencies and configuration." if c.status == Status.OK else c.detail,
                       fix="" if c.status == Status.OK else "Import an offline bundle, or prime the cache on a connected machine (docs/offline.md).")  # fmt: skip
        elif c.name == "kb index":
            row.update(component="Knowledge base", group="Knowledge", version="local index",
                       detail="OWASP Cheat Sheets, ASVS and CWE for cited explanations." if c.status == Status.OK else c.detail,
                       fix="" if c.status == Status.OK else "gapscan data fetch && gapscan kb build")  # fmt: skip
        out.append(row)
    return out


def summary(items: list[dict[str, Any]]) -> dict[str, int]:
    return {k: sum(1 for r in items if r["status"] == k) for k in ("ok", "warn", "problem")}


def freshness(
    snapshots: dict[str, str], max_age_days: int, today: date | None = None
) -> list[dict[str, Any]]:
    """Age of each dated snapshot in days, with the share of the allowed age used (amber after the limit)."""
    today = today or datetime.now(UTC).date()
    out: list[dict[str, Any]] = []
    for name, value in sorted(snapshots.items()):
        try:
            age = (today - date.fromisoformat(str(value)[:10])).days
        except ValueError:
            out.append(
                {"name": name, "value": str(value), "age_days": None, "used": None, "stale": False}
            )
            continue
        out.append(
            {
                "name": name,
                "value": str(value)[:10],
                "age_days": age,
                "used": min(1.0, age / max_age_days),
                "stale": age > max_age_days,
            }
        )
    return out
