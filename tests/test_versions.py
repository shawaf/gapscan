from __future__ import annotations

import httpx
import pytest

from gapscan.offline.versions import check_editions, diff_versions, load_expected, resolve_versions

EXPECTED = {
    "top10": "2025",
    "asvs": "5.0",
    "api_top10": "2023",
    "genai_llm_top10": "2026",
    "masvs": "2",
}
OK = {
    "top10": "2025",
    "asvs": "5.0.0",
    "api_top10": "2023",
    "genai_llm_top10": "2026",
    "masvs": "2.1.0",
}


def server(
    top10=("2021", "2025"),
    asvs="5.0.0",
    api=("2019", "2023"),
    genai=("2025", "2026"),
    masvs="v2.1.0",
):
    def dirs(names):
        return [{"name": n, "type": "dir"} for n in names] + [
            {"name": "README.md", "type": "file"},
            {"name": "2021-2003_Comparison", "type": "dir"},
        ]

    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if "OWASP/Top10/contents" in u:
            return httpx.Response(200, json=dirs(top10))
        if "OWASP/ASVS/releases/latest" in u:
            return httpx.Response(
                200,
                json={
                    "assets": [
                        {"name": f"OWASP_Application_Security_Verification_Standard_{asvs}_en.csv"},
                        {"name": "x.pdf"},
                    ]
                },
            )
        if "API-Security/contents/editions" in u:
            return httpx.Response(200, json=dirs(api))
        if "GenAI-LLM-Top10/contents" in u:
            return httpx.Response(200, json=dirs(genai))
        if "owasp-masvs/releases/latest" in u:
            return httpx.Response(200, json={"tag_name": masvs})
        if "CheatSheetSeries/commits" in u:
            return httpx.Response(
                200,
                json=[{"sha": "a" * 40, "commit": {"committer": {"date": "2026-10-01T00:00:00Z"}}}],
            )
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_resolve_reads_the_latest_released_edition_from_each_source():
    r = resolve_versions(server())
    assert r == {
        **OK,
        "cheatsheets": "snapshot@aaaaaaaaaaaa (2026-10-01)",
    }  # year folders only: comparison folders ignored


def test_expected_file_matches_the_tables_in_the_repo():
    assert load_expected() == EXPECTED


def test_current_editions_pass_without_warnings():
    c = check_editions(OK, EXPECTED)
    assert c.ok and c.errors == []


@pytest.mark.parametrize(
    ("override", "needle"),
    [
        ({"top10": "2029"}, "OWASP Top 10"),
        ({"asvs": "5.1.0"}, "OWASP ASVS"),
        ({"api_top10": "2027"}, "API Security"),
        ({"genai_llm_top10": "2027"}, "GenAI"),
        ({"masvs": "3.0.0"}, "MASVS"),
        ({"top10": ""}, "could not determine"),
    ],
)
def test_a_new_edition_fails_loudly_with_instructions(override, needle):
    c = check_editions({**OK, **override}, EXPECTED)
    assert not c.ok and any(needle in e for e in c.errors)
    if "could not" not in c.errors[0]:
        assert "Regenerate and review" in c.errors[0] and "expected_editions.json" in c.errors[0]


def test_a_patch_release_is_a_warning_not_an_error():
    c = check_editions({**OK, "asvs": "5.0.1", "masvs": "2.2.0"}, EXPECTED)
    assert c.ok and any("5.0.1" in w for w in c.warnings)


def test_end_to_end_with_a_new_top10_in_the_mock_registry():
    c = check_editions(resolve_versions(server(top10=("2021", "2025", "2029"))), EXPECTED)
    assert not c.ok and "2029" in c.errors[0]


def test_diff_lists_only_what_changed():
    old = {"asvs": "5.0.0", "masvs": "2.1.0", "cwe": "4.19"}
    new = {"asvs": "5.0.1", "masvs": "2.1.0", "cwe": "4.20", "kev": "2026-10-02"}
    assert diff_versions(old, new) == [
        "asvs: 5.0.0 -> 5.0.1",
        "cwe: 4.19 -> 4.20",
        "kev: (none) -> 2026-10-02",
    ]
    assert diff_versions(new, new) == []
