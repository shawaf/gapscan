"""One-time downloads of OWASP source data into the raw store (connected machine only).

This is the only code that talks to the network for OWASP data, and it is never called
during `scan` (hard rule #2). Versions are resolved from the official sources, never from
draft branches: the ASVS release assets, the Top 10 repo pinned to a commit SHA, and
OpenCRE's REST API.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Generator
from pathlib import Path

import httpx

from ..store.raw import RawStore

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
CC_BY_SA = "CC BY-SA 4.0"
OPENCRE_LICENSE = "CC0-1.0 (OpenCRE repo); embedded ASVS/CWE text keeps its own terms"
USER_AGENT = "gapscan-fetch/0.1 (+offline security tool; one-time OWASP data download)"

ASVS_VERSION = "5.0.0"
ASVS_ASSETS = [
    "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv",
    "OWASP_Application_Security_Verification_Standard_5.0.0_en.json",
    "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json",
]
# Official mapping files published in the ASVS repo. ASVS 5.0 dropped direct CWE mappings;
# these let us chain CWE -> ASVS 4.0.3 (via OpenCRE) -> ASVS 5.0.0, plus OWASP's own
# archived v5.0.be CWE export. Their provenance is recorded in the manifest.
ASVS_MAPPING_FILES = [
    "README.md",
    "mapping_v4.0.3_to_v5.0.0.yml",
    "mapping_v5.0.0_to_v4.0.3.yml",
    "mapping_v5.0.be_to_v5.0.0.yml",
    "v5.0.be_cwe_mapping.json",
]
OPENCRE = "https://opencre.org/rest/v1"
OPENCRE_STANDARDS = ["ASVS", "CWE"]

Getter = Callable[[str], httpx.Response]


class GitHubAPIAuth(httpx.Auth):
    """Sends GITHUB_TOKEN (optional; any read-only token) to api.github.com and to no other host.
    Without it GitHub allows 60 API requests an hour per address, which shared CI runners exhaust."""

    def __init__(self, token: str) -> None:
        self.token = token

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if self.token and request.url.host == "api.github.com" and request.url.scheme == "https":
            request.headers["Authorization"] = f"Bearer {self.token}"
        yield request


def _client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=60,
                        auth=GitHubAPIAuth(os.environ.get("GITHUB_TOKEN", "").strip()),
                        transport=transport)  # fmt: skip


def _ok(resp: httpx.Response) -> httpx.Response:
    if (
        resp.status_code in (403, 429)
        and resp.request.url.host == "api.github.com"
        and resp.headers.get("x-ratelimit-remaining") == "0"
    ):
        raise httpx.HTTPStatusError(
            "GitHub API rate limit reached (60 requests an hour without a token): set GITHUB_TOKEN "
            "to any read-only token and run the command again",
            request=resp.request,
            response=resp,
        )
    resp.raise_for_status()
    return resp


def fetch_top10_2025(store: RawStore, client: httpx.Client) -> int:
    """Top 10:2025 category pages (they list the CWEs per category), pinned to a commit."""
    commits = _ok(
        client.get(f"{GITHUB_API}/repos/OWASP/Top10/commits", params={"per_page": 1})
    ).json()
    sha = commits[0]["sha"]
    listing = _ok(
        client.get(f"{GITHUB_API}/repos/OWASP/Top10/contents/2025/docs/en", params={"ref": sha})
    ).json()
    n = 0
    for item in listing:
        if not item["name"].endswith(".md"):
            continue
        url = f"{RAW}/OWASP/Top10/{sha}/2025/docs/en/{item['name']}"
        store.save(f"top10-2025/{item['name']}", _ok(client.get(url)).content, url=url,
                   source="owasp-top10", version=f"2025@{sha[:12]}", license=CC_BY_SA)  # fmt: skip
        n += 1
    return n


def fetch_asvs(store: RawStore, client: httpx.Client) -> int:
    """ASVS 5.0.0 data files from the latest official release, plus the mapping files."""
    release = _ok(client.get(f"{GITHUB_API}/repos/OWASP/ASVS/releases/latest")).json()
    tag = release["tag_name"]
    by_name = {a["name"]: a["browser_download_url"] for a in release["assets"]}
    n = 0
    for name in ASVS_ASSETS:
        url = by_name[name]
        store.save(f"asvs-{ASVS_VERSION}/{name}", _ok(client.get(url)).content, url=url,
                   source="owasp-asvs", license=CC_BY_SA,
                   version=f"{ASVS_VERSION} (release {tag})")  # fmt: skip
        n += 1
    sha = _ok(client.get(f"{GITHUB_API}/repos/OWASP/ASVS/commits", params={"per_page": 1})).json()[
        0
    ]["sha"]
    for name in ASVS_MAPPING_FILES:
        url = f"{RAW}/OWASP/ASVS/{sha}/5.0/mappings/{name}"
        store.save(f"asvs-{ASVS_VERSION}/mappings/{name}", _ok(client.get(url)).content, url=url,
                   source="owasp-asvs-mappings", license=CC_BY_SA,
                   version=f"repo@{sha[:12]}")  # fmt: skip
        n += 1
    return n


def fetch_opencre(store: RawStore, client: httpx.Client) -> int:
    """OpenCRE's ASVS and CWE standard listings (every page, saved unmodified)."""
    n = 0
    for std in OPENCRE_STANDARDS:
        page, total = 1, 1
        while page <= total:
            url = f"{OPENCRE}/standard/{std}?page={page}&per_page=20"
            resp = _ok(client.get(url))
            total = int(resp.json().get("total_pages", 1))
            store.save(
                f"opencre/{std.lower()}/page-{page:03d}.json",
                resp.content,
                url=url,
                source="owasp-opencre",
                version="rest-v1",
                license=OPENCRE_LICENSE,
            )
            page += 1
            n += 1
    return n


def fetch_owasp(store: RawStore, client: httpx.Client | None = None) -> dict[str, int]:
    own = client is None
    client = client or _client()
    try:
        return {
            "top10-2025": fetch_top10_2025(store, client),
            "asvs": fetch_asvs(store, client),
            "opencre": fetch_opencre(store, client),
        }
    finally:
        if own:
            client.close()


# --- knowledge-base sources (Phase 6) ---------------------------------------------------

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
MITRE_LICENSE = "MITRE CWE Terms of Use (free use, keep the CWE copyright notice)"
GENAI_TOP10_REPO = "GenAI-Security-Project/GenAI-LLM-Top10"


def _commit(client: httpx.Client, repo: str) -> str:
    return str(
        _ok(client.get(f"{GITHUB_API}/repos/{repo}/commits", params={"per_page": 1})).json()[0][
            "sha"
        ]
    )


def _save_md(store: RawStore, client: httpx.Client, repo: str, sha: str, folder: str,
             dest: str, source: str, version: str) -> int:  # fmt: skip
    """Save every top-level .md file of `folder` at commit `sha` under `dest/`."""
    listing = _ok(
        client.get(f"{GITHUB_API}/repos/{repo}/contents/{folder}", params={"ref": sha})
    ).json()
    n = 0
    for item in listing:
        if item["type"] != "file" or not item["name"].endswith(".md"):
            continue
        url = f"{RAW}/{repo}/{sha}/{folder}/{item['name']}"
        store.save(f"{dest}/{item['name']}", _ok(client.get(url)).content, url=url,
                   source=source, version=version, license=CC_BY_SA)  # fmt: skip
        n += 1
    return n


def fetch_api_top10_2023(store: RawStore, client: httpx.Client) -> int:
    sha = _commit(client, "OWASP/API-Security")
    return _save_md(store, client, "OWASP/API-Security", sha, "editions/2023/en",
                    "api-security-2023", "owasp-api-top10", f"2023@{sha[:12]}")  # fmt: skip


def fetch_genai_top10_2026(store: RawStore, client: httpx.Client) -> int:
    sha = _commit(client, GENAI_TOP10_REPO)
    return _save_md(
        store, client, GENAI_TOP10_REPO, sha, "2026/final",
        "genai-llm-top10-2026", "owasp-genai-llm-top10", f"2026@{sha[:12]}",
    )  # fmt: skip


def fetch_cheatsheets(store: RawStore, client: httpx.Client) -> int:
    """The whole OWASP Cheat Sheet Series, pinned to one commit (snapshot at fetch time)."""
    repo = "OWASP/CheatSheetSeries"
    sha = _commit(client, repo)
    tree = _ok(
        client.get(f"{GITHUB_API}/repos/{repo}/git/trees/{sha}", params={"recursive": 1})
    ).json()
    names = [t["path"] for t in tree["tree"]
             if t["path"].startswith("cheatsheets/") and t["path"].endswith(".md")]  # fmt: skip
    for path in names:
        url = f"{RAW}/{repo}/{sha}/{path}"
        store.save(
            f"cheatsheets/{path.removeprefix('cheatsheets/')}",
            _ok(client.get(url)).content,
            url=url,
            source="owasp-cheatsheets",
            version=f"snapshot@{sha[:12]}",
            license=CC_BY_SA,
        )
    return len(names)


def fetch_masvs(store: RawStore, client: httpx.Client) -> int:
    """MASVS from the latest published release (the repo moved: redirects are followed)."""
    rel = _ok(client.get(f"{GITHUB_API}/repos/OWASP/owasp-masvs/releases/latest")).json()
    asset = next(a for a in rel["assets"] if a["name"] == "OWASP_MASVS.cdx.json")
    url = asset["browser_download_url"]
    tag = rel["tag_name"]
    dest = f"masvs-{tag.lstrip('v')}/OWASP_MASVS.cdx.json"
    store.save(dest, _ok(client.get(url)).content, url=url, source="owasp-masvs",
               version=f"release {tag}", license=CC_BY_SA)  # fmt: skip
    return 1


def fetch_cwe(store: RawStore, client: httpx.Client) -> int:
    """MITRE's current CWE catalog (XML in a zip), saved unmodified."""
    store.save("cwe/cwec_latest.xml.zip", _ok(client.get(CWE_URL)).content, url=CWE_URL,
               source="mitre-cwe", version="latest", license=MITRE_LICENSE)  # fmt: skip
    return 1


def fetch_kb_sources(
    owasp: RawStore, mitre: RawStore, client: httpx.Client | None = None
) -> dict[str, int]:
    own = client is None
    client = client or _client()
    try:
        return {
            "api-top10-2023": fetch_api_top10_2023(owasp, client),
            "genai-llm-top10-2026": fetch_genai_top10_2026(owasp, client),
            "cheatsheets": fetch_cheatsheets(owasp, client),
            "masvs": fetch_masvs(owasp, client),
            "cwe": fetch_cwe(mitre, client),
        }
    finally:
        if own:
            client.close()


# --- vulnerability enrichment: CISA KEV and FIRST EPSS (Phase 9) -------------------------

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_LICENSE = "US Government work (public domain)"
EPSS_LICENSE = "FIRST EPSS: free to use, cite FIRST (https://www.first.org/epss/)"


def fetch_enrichment(store: RawStore, client: httpx.Client | None = None) -> dict[str, str]:
    """Download the CISA KEV catalog and the current EPSS scores into the enrichment store as
    kev.json / epss.csv (the names `enrich.load_enrichment` reads). Returns {dataset: date}."""
    import gzip
    import json

    own = client is None
    client = client or _client()
    try:
        kev = _ok(client.get(KEV_URL)).content
        data = json.loads(kev)  # refuse to store something that is not the catalog
        if "vulnerabilities" not in data:
            raise ValueError("unexpected KEV payload: no 'vulnerabilities' key")
        store.save(
            "kev.json",
            kev,
            url=KEV_URL,
            source="cisa-kev",
            version=str(data.get("catalogVersion", "")),
            license=KEV_LICENSE,
        )
        epss = gzip.decompress(_ok(client.get(EPSS_URL)).content)
        head = epss[:400].decode("utf-8", "replace")
        if "cve" not in head.lower():
            raise ValueError("unexpected EPSS payload: no 'cve' header")
        store.save(
            "epss.csv",
            epss,
            url=EPSS_URL,
            source="first-epss",
            version=head.splitlines()[0][:80],
            license=EPSS_LICENSE,
        )
        return {"cisa_kev": str(data.get("dateReleased", ""))[:10], "epss": _epss_date(head)}
    finally:
        if own:
            client.close()


def _epss_date(head: str) -> str:
    for part in head.splitlines()[0].lstrip("#").split(","):
        if part.startswith("score_date:"):
            return part.split(":", 1)[1][:10]
    return ""


# --- vulnerability databases (Phase 9) ------------------------------------------------------

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
# The languages GapScan targets, plus the tooling they commonly carry (fastlane's Gemfile.lock).
OSV_ECOSYSTEMS = ["PyPI", "npm", "Maven", "Go", "Pub", "SwiftURL", "RubyGems", "NuGet", "Packagist",
                  "crates.io"]  # fmt: skip
OSV_LAYOUT = "osv-scalibr"  # the directory name osv-scanner 2.x reads (checked against 2.6.0)


def fetch_osv_db(
    db_dir: Path, ecosystems: list[str] | None = None, client: httpx.Client | None = None
) -> str:
    """Download OSV's per-ecosystem archives into the layout osv-scanner reads offline. Returns the
    snapshot date (UTC, today) and records it in SNAPSHOT_DATE."""
    from datetime import UTC, datetime

    own = client is None
    client = client or httpx.Client(
        headers={"User-Agent": USER_AGENT}, follow_redirects=True, timeout=600
    )
    try:
        for eco in ecosystems or OSV_ECOSYSTEMS:
            target = db_dir / OSV_LAYOUT / eco / "all.zip"
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_suffix(".part")
            with client.stream("GET", f"{OSV_BASE}/{eco}/all.zip") as resp:
                resp.raise_for_status()
                with tmp.open("wb") as fh:
                    for chunk in resp.iter_bytes(1 << 20):
                        fh.write(chunk)
            tmp.replace(target)  # never leave a half-written archive in place
        date = datetime.now(UTC).strftime("%Y-%m-%d")
        (db_dir / "SNAPSHOT_DATE").write_text(date + "\n", encoding="utf-8")
        return date
    finally:
        if own:
            client.close()


def fetch_trivy_db(cache_dir: Path, *, java_db: bool = False, timeout_s: int = 1800) -> str:
    """Download Trivy's vulnerability DB (and optionally the large Java DB) with the trivy binary.
    Returns the DB's UpdatedAt date."""
    import json
    import os
    import subprocess

    from gapscan.scanners.trivy import NO_PHONE_HOME

    base = ["trivy", "--cache-dir", str(cache_dir), "image", "--quiet"]
    env = {**os.environ, **NO_PHONE_HOME}  # download the DB only, no version check or telemetry
    subprocess.run(
        [*base, "--download-db-only"], check=True, capture_output=True, timeout=timeout_s, env=env
    )  # noqa: S603
    if java_db:
        subprocess.run(
            [*base, "--download-java-db-only"],
            check=True, capture_output=True, timeout=timeout_s, env=env,
        )  # noqa: S603  # fmt: skip
    meta = json.loads((cache_dir / "db" / "metadata.json").read_text(encoding="utf-8"))
    return str(meta.get("UpdatedAt", ""))[:10]
