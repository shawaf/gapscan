from __future__ import annotations

import json

import httpx
import pytest
from typer.testing import CliRunner

from gapscan.cli import app
from gapscan.offline.fetch import fetch_owasp
from gapscan.store.raw import RawStore


def test_store_saves_bytes_verbatim_and_verifies(tmp_path):
    store = RawStore(tmp_path)
    raw = b'{"b": 1,\n  "a":2}\r\n\xff'  # odd whitespace + invalid utf-8 must survive
    entry = store.save("x/y.json", raw, url="https://e/x", source="s", version="1")
    assert store.read_raw("x/y.json") == raw and entry.bytes == len(raw)
    assert store.verify() == []
    (tmp_path / "x" / "y.json").write_bytes(b"tampered")
    assert store.verify() == ["modified: x/y.json"]
    (tmp_path / "x" / "y.json").unlink()
    assert store.verify() == ["missing: x/y.json"]


def test_store_refuses_path_escape(tmp_path):
    with pytest.raises(ValueError):
        RawStore(tmp_path).read_raw("../secret")


def test_manifest_replaces_entry_on_resave(tmp_path):
    store = RawStore(tmp_path)
    store.save("a", b"1", url="u", source="s", version="1")
    store.save("a", b"22", url="u", source="s", version="2")
    (e,) = store.manifest().entries
    assert e.bytes == 2 and e.version == "2"


def _fake_github(request: httpx.Request) -> httpx.Response:
    u = str(request.url)
    if "Top10/commits" in u:
        return httpx.Response(200, json=[{"sha": "a" * 40}])
    if "Top10/contents" in u:
        return httpx.Response(200, json=[{"name": "A01_2025-X.md"}, {"name": "img.png"}])
    if "releases/latest" in u:
        assets = [{"name": n, "browser_download_url": f"https://dl/{n}"} for n in [
            "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv",
            "OWASP_Application_Security_Verification_Standard_5.0.0_en.json",
            "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json"]]  # fmt: skip
        return httpx.Response(200, json={"tag_name": "latest", "assets": assets})
    if "ASVS/commits" in u:
        return httpx.Response(200, json=[{"sha": "b" * 40}])
    if "opencre.org" in u:
        page = int(request.url.params["page"])
        return httpx.Response(200, content=json.dumps({"total_pages": 2, "page": page}).encode())
    return httpx.Response(200, content=b"raw:" + u.encode())


def test_fetch_owasp_with_mock_transport(tmp_path):
    store = RawStore(tmp_path)
    client = httpx.Client(transport=httpx.MockTransport(_fake_github))
    counts = fetch_owasp(store, client)
    assert counts == {"top10-2025": 1, "asvs": 8, "opencre": 4}
    paths = {e.path for e in store.manifest().entries}
    assert "top10-2025/A01_2025-X.md" in paths and "opencre/cwe/page-002.json" in paths
    top = next(e for e in store.manifest().entries if e.path.startswith("top10-2025"))
    assert top.version == "2025@" + "a" * 12 and top.license == "CC BY-SA 4.0"
    assert store.verify() == []


def test_cli_list_show_verify(tmp_path, monkeypatch):
    cfg = tmp_path / "gapscan.toml"
    cfg.write_text(f'[data]\ndir = "{tmp_path}"\n')
    RawStore(tmp_path / "owasp").save("t/f.md", b"# raw\n", url="u", source="s", version="v")
    r = CliRunner()
    assert "f.md" in r.invoke(app, ["data", "list", "-c", str(cfg)]).stdout
    assert r.invoke(app, ["data", "show", "t/f.md", "-c", str(cfg)]).stdout == "# raw\n"
    assert r.invoke(app, ["data", "verify", "-c", str(cfg)]).exit_code == 0
    assert r.invoke(app, ["data", "show", "../x", "-c", str(cfg)]).exit_code == 1


def test_fetch_enrichment_stores_kev_and_epss_under_the_names_the_loader_reads(tmp_path):
    import gzip

    from gapscan.enrich import load_enrichment
    from gapscan.offline.fetch import fetch_enrichment

    kev = {
        "catalogVersion": "2026.10.01",
        "dateReleased": "2026-10-01T12:00:00Z",
        "vulnerabilities": [{"cveID": "CVE-2021-1"}],
    }
    epss = "#model_version:v2025.03.14,score_date:2026-10-02T00:00:00Z\ncve,epss,percentile\nCVE-2021-1,0.42,0.9\n"

    def handler(request: httpx.Request) -> httpx.Response:
        if "known_exploited" in str(request.url):
            return httpx.Response(200, json=kev)
        return httpx.Response(200, content=gzip.compress(epss.encode()))

    store = RawStore(tmp_path)
    dates = fetch_enrichment(store, httpx.Client(transport=httpx.MockTransport(handler)))
    assert dates == {"cisa_kev": "2026-10-01", "epss": "2026-10-02"}
    enr = load_enrichment(tmp_path)  # the same loader the scan uses
    assert enr.kev == {"CVE-2021-1"} and enr.epss == {"CVE-2021-1": 0.42} and store.verify() == []
    sources = {e.path: e.license for e in store.manifest().entries}
    assert "public domain" in sources["kev.json"] and "FIRST" in sources["epss.csv"]


def test_fetch_enrichment_refuses_a_payload_that_is_not_the_catalog(tmp_path):
    import pytest as _pytest

    from gapscan.offline.fetch import fetch_enrichment

    bad = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"oops": 1}))
    )
    with _pytest.raises(ValueError, match="KEV"):
        fetch_enrichment(RawStore(tmp_path), bad)
    assert not (tmp_path / "kev.json").exists()


def test_github_token_goes_to_the_github_api_only(monkeypatch):
    from gapscan.offline import fetch

    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[request.url.host] = request.headers.get("Authorization")
        return httpx.Response(200, json=[])

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    client = fetch._client(httpx.MockTransport(handler))
    for url in ("https://api.github.com/repos/a/b", "https://raw.githubusercontent.com/a/b",
                "https://opencre.org/rest/v1/x"):  # fmt: skip
        client.get(url)
    assert seen == {"api.github.com": "Bearer ghp_test", "raw.githubusercontent.com": None,
                    "opencre.org": None}  # fmt: skip


def test_github_rate_limit_says_how_to_fix_it():
    from gapscan.offline import fetch

    req = httpx.Request("GET", "https://api.github.com/repos/a/b")
    resp = httpx.Response(403, headers={"x-ratelimit-remaining": "0"}, request=req)
    with pytest.raises(httpx.HTTPStatusError, match="GITHUB_TOKEN"):
        fetch._ok(resp)
