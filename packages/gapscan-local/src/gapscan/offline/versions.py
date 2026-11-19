"""Resolve the latest *released* version of each OWASP source and compare it with the editions
GapScan's mapping tables were built for.

Used by `gapscan bundle` before it downloads anything. A different edition (a new Top 10 year, ASVS
5.1, MASVS 3...) is an error: the CWE -> Top 10 / ASVS tables must be regenerated and reviewed first,
so a report never mixes editions. Patch-level changes are warnings. Draft branches are never used:
only GitHub releases and the published edition folders count."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..owasp.build import MAPPINGS_DIR
from .fetch import GENAI_TOP10_REPO, GITHUB_API, _client, _ok

# The security pack's own files (another workspace package, so found through its module).
EXPECTED_PATH = MAPPINGS_DIR.parent / "expected_editions.json"
MAPPINGS_VERSIONS = MAPPINGS_DIR / "versions.json"
_YEAR = re.compile(r"^(\d{4})$")


def load_expected() -> dict[str, str]:
    raw = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def _years(client: httpx.Client, repo: str, path: str = "") -> list[str]:
    url = f"{GITHUB_API}/repos/{repo}/contents/{path}".rstrip("/")
    return sorted(
        i["name"]
        for i in _ok(client.get(url)).json()
        if i.get("type") == "dir" and _YEAR.match(i["name"])
    )


def resolve_versions(client: httpx.Client | None = None) -> dict[str, str]:
    """Latest released edition of every source, straight from the official repositories."""
    own = client is None
    client = client or _client()
    try:
        out: dict[str, str] = {}
        top10 = _years(client, "OWASP/Top10")
        out["top10"] = top10[-1] if top10 else ""
        release = _ok(client.get(f"{GITHUB_API}/repos/OWASP/ASVS/releases/latest")).json()
        m = next(
            (
                re.search(r"Standard_(\d+\.\d+\.\d+)_en\.csv$", a["name"])
                for a in release["assets"]
                if a["name"].endswith("_en.csv")
            ),
            None,
        )
        out["asvs"] = m.group(1) if m else ""
        api = _years(client, "OWASP/API-Security", "editions")
        out["api_top10"] = api[-1] if api else ""
        genai = _years(client, GENAI_TOP10_REPO)
        out["genai_llm_top10"] = genai[-1] if genai else ""
        masvs = _ok(client.get(f"{GITHUB_API}/repos/OWASP/owasp-masvs/releases/latest")).json()
        out["masvs"] = str(masvs["tag_name"]).lstrip("v")
        commit = _ok(
            client.get(f"{GITHUB_API}/repos/OWASP/CheatSheetSeries/commits", params={"per_page": 1})
        ).json()[0]
        out["cheatsheets"] = (
            f"snapshot@{commit['sha'][:12]} ({commit['commit']['committer']['date'][:10]})"
        )
        return out
    finally:
        if own:
            client.close()


@dataclass
class EditionCheck:
    errors: list[str] = field(default_factory=list)  # a different edition: stop
    warnings: list[str] = field(default_factory=list)  # a patch level change: review

    @property
    def ok(self) -> bool:
        return not self.errors


def check_editions(
    resolved: dict[str, str], expected: dict[str, str] | None = None
) -> EditionCheck:
    expected = expected or load_expected()
    result = EditionCheck()
    labels = {"top10": "OWASP Top 10", "asvs": "OWASP ASVS", "api_top10": "OWASP API Security Top 10",
              "genai_llm_top10": "OWASP GenAI LLM Top 10", "masvs": "OWASP MASVS"}  # fmt: skip
    for key, label in labels.items():
        got, want = resolved.get(key, ""), expected[key]
        if not got:
            result.errors.append(f"{label}: could not determine the latest released edition")
        elif got != want and not got.startswith(want + "."):
            result.errors.append(
                f"{label}: the official source now shows {got}, the mapping tables are for {want}. Regenerate and "
                f"review the tables (`gapscan data build-mappings`), then update owasp/expected_editions.json"
            )
    # ASVS requirement ids and text belong to an exact release: a patch release is worth a look.
    try:
        built = json.loads(MAPPINGS_VERSIONS.read_text(encoding="utf-8"))["asvs"]["version"]
        got = resolved.get("asvs", "")
        if got and got.startswith(expected["asvs"]) and got != built:
            result.warnings.append(
                f"OWASP ASVS: tables were built from {built}, latest is {got}; review what changed"
            )
    except (OSError, KeyError, ValueError):
        pass
    return result


def diff_versions(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Human-readable changes since the previous bundle (empty when nothing changed)."""
    lines = []
    for key in sorted(set(old) | set(new)):
        a, b = old.get(key), new.get(key)
        if a != b:
            lines.append(
                f"{key}: {a if a is not None else '(none)'} -> {b if b is not None else '(removed)'}"
            )
    return lines
