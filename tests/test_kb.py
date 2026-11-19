from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import numpy as np
import pytest

from gapscan.agent.tools import ToolBox
from gapscan.agent.triage import with_references
from gapscan.config import Config
from gapscan.kb import KnowledgeBase, build_kb, load_kb
from gapscan.kb.index import KBIndex, fts_query
from gapscan.kb.ingest import (
    Chunk,
    clean_markdown,
    ingest_api_top10,
    ingest_cheatsheets,
    ingest_masvs,
    ingest_policies,
    markdown_chunks,
    parse_cwe_xml,
)
from gapscan.llm.client import LLMError
from gapscan.models import Category, Finding, Severity, Verdict, VerdictLabel
from gapscan.store.raw import RawStore

ROOT = Path(__file__).resolve().parent.parent


class FakeEmbedder:
    """Deterministic bag-of-words embedder: shared words give similar vectors."""

    model = "fake-embed"

    def embed(self, texts, kind):
        out = np.zeros((len(texts), 64), dtype=np.float32)
        for i, t in enumerate(texts):
            for w in t.lower().split():
                out[i, int(hashlib.md5(w.strip(".,:()").encode()).hexdigest(), 16) % 64] += 1.0
        return out / np.maximum(np.linalg.norm(out, axis=1, keepdims=True), 1e-9)


def chunk(doc, text, source="cheatsheet", title=None, heading="H"):
    return Chunk(id=hashlib.sha256((doc + text).encode()).hexdigest()[:16], source=source, doc_id=doc,
                 title=title or doc, heading=heading, text=text, url=f"https://x/{doc}", version="v1",
                 license="CC BY-SA 4.0")  # fmt: skip


CORPUS = [
    chunk("SQL_Injection_Prevention_Cheat_Sheet", "Use prepared statements with parameterized queries to prevent SQL injection.", title="SQL Injection Prevention"),
    chunk("XSS_Cheat", "Encode output for the HTML context to prevent cross site scripting.", title="XSS Prevention"),
    chunk("Pwd_Cheat", "Hash passwords with argon2id or bcrypt, never with md5.", title="Password Storage"),
    chunk("CWE-89", "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", source="cwe", title="CWE-89 SQL Injection"),
    chunk("CWE-89", "CWE-89 potential mitigations: use parameterized queries.", source="cwe", title="CWE-89 SQL Injection", heading="Potential mitigations"),
    chunk("A05:2025", "Injection includes SQL injection and cross site scripting.", source="top10-2025", title="A05:2025 Injection"),
]  # fmt: skip


@pytest.fixture
def kb(tmp_path):
    emb = FakeEmbedder()
    return KnowledgeBase(KBIndex.build(CORPUS, tmp_path / "kb", emb), emb)


# --- ingest ----------------------------------------------------------------------------


def test_markdown_chunks_keep_heading_path_and_drop_noise():
    md = "# My Sheet\n\nintro text that is long enough to keep around here.\n\n## Part A\n\n![img](a.png)\n<!-- hidden -->\nBody of part A is here and is long enough.\n\n### Sub\n\nSub body text which is also long enough to be kept."
    cs = markdown_chunks(
        md, source="cheatsheet", doc_id="D", fallback_title="D", url="u", version="v", license="l"
    )
    assert {c.title for c in cs} == {"My Sheet"}
    assert [c.heading for c in cs] == ["", "Part A", "Part A > Sub"]
    assert all("hidden" not in c.text and "a.png" not in c.text for c in cs)
    assert "Body of part A" in cs[1].text


def test_long_sections_split_with_a_size_cap_and_code_blocks_are_not_headings():
    body = "\n\n".join(f"paragraph {i} " + "word " * 80 for i in range(12))
    md = f"# T\n\n## S\n\n{body}\n\n```\n# not a heading\n```\n"
    cs = markdown_chunks(
        md, source="cheatsheet", doc_id="D", fallback_title="D", url="u", version="v", license="l"
    )
    assert len(cs) > 3 and all(len(c.text) <= 1700 for c in cs)
    assert not any(c.heading == "not a heading" for c in cs)


def test_clean_markdown_strips_html_tables():
    assert "<table>" not in clean_markdown("a <table><tr><td>cell</td></tr></table> b")


CWE_XML = b"""<?xml version="1.0"?>
<Weakness_Catalog Name="CWE" Version="9.9" Date="2030-01-01" xmlns="http://cwe.mitre.org/cwe-7">
<Weaknesses>
 <Weakness ID="89" Name="SQL Injection" Status="Stable">
  <Description>Builds SQL from input.</Description>
  <Extended_Description>Attackers change the query.</Extended_Description>
  <Alternate_Terms><Alternate_Term><Term>SQLi</Term></Alternate_Term></Alternate_Terms>
  <Common_Consequences><Consequence><Scope>Confidentiality</Scope><Impact>Read Application Data</Impact></Consequence></Common_Consequences>
  <Potential_Mitigations><Mitigation><Phase>Implementation</Phase><Strategy>Parameterization</Strategy><Description>Use prepared statements.</Description></Mitigation></Potential_Mitigations>
 </Weakness>
 <Weakness ID="5" Name="Old thing" Status="Deprecated"><Description>gone</Description></Weakness>
</Weaknesses></Weakness_Catalog>"""


def test_parse_cwe_xml():
    cs = parse_cwe_xml(CWE_XML, version="CWE 9.9", license="MITRE")
    assert [(c.doc_id, c.heading) for c in cs] == [
        ("CWE-89", "Description"),
        ("CWE-89", "Potential mitigations"),
    ]
    assert (
        "SQLi" in cs[0].text and "Read Application Data" in cs[0].text and "Query" not in cs[0].text
    )
    assert "prepared statements" in cs[1].text and cs[0].url.endswith("/89.html")
    assert all(c.version == "CWE 9.9" for c in cs)


def test_source_ingestion_from_a_raw_store(tmp_path):
    store = RawStore(tmp_path)
    store.save("cheatsheets/Foo_Cheat_Sheet.md", b"# Foo\n\n## Intro\n\nThis cheat sheet explains how to do foo safely.", url="u", source="owasp-cheatsheets", version="snap", license="CC BY-SA 4.0")  # fmt: skip
    cs = ingest_cheatsheets(store)
    assert (
        cs[0].doc_id == "Foo_Cheat_Sheet"
        and cs[0].url.endswith("/Foo_Cheat_Sheet.html")
        and cs[0].version == "snap"
    )
    for name in ["0xa1-broken-object-level-authorization.md", "0xa9-improper-inventory-management.md",
                 "0xaa-unsafe-consumption-of-apis.md", "0x00-header.md"]:  # fmt: skip
        store.save(f"api-security-2023/{name}", b"# T\n\nsome text that is long enough to become a chunk here.", url="u", source="s", version="v", license="l")  # fmt: skip
    assert sorted(c.doc_id for c in ingest_api_top10(store)) == [
        "API10:2023",
        "API1:2023",
        "API9:2023",
    ]
    masvs = {
        "definitions": {
            "standards": [
                {
                    "requirements": [
                        {
                            "identifier": "MASVS-STORAGE",
                            "title": "Storage",
                            "text": "Protect stored data.",
                        }
                    ]
                }
            ]
        }
    }
    store.save("masvs-2.1.0/OWASP_MASVS.cdx.json", json.dumps(masvs).encode(), url="u", source="m", version="release v2.1.0", license="l")  # fmt: skip
    assert ingest_masvs(store)[0].doc_id == "MASVS-STORAGE"


def test_policies_are_ingested_as_the_owners_own(tmp_path):
    (tmp_path / "secure_coding.md").write_text(
        "# Our Policy\n\n## Logging\n\nNever log passwords or tokens, in any environment, ever."
    )
    cs = ingest_policies(tmp_path)
    assert cs and cs[0].source == "policy" and cs[0].license == "owner's own document"
    assert ingest_policies(tmp_path / "missing") == []


def test_cwe_zip_roundtrip(tmp_path):
    from gapscan.kb.ingest import ingest_cwe

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("cwec_v9.9.xml", CWE_XML)
    store = RawStore(tmp_path)
    store.save(
        "cwe/cwec_latest.xml.zip",
        buf.getvalue(),
        url="u",
        source="mitre-cwe",
        version="latest",
        license="MITRE",
    )
    cs = ingest_cwe(store)
    assert cs and cs[0].version == "CWE 9.9 (2030-01-01)"


# --- index / search --------------------------------------------------------------------


def test_fts_query_is_safe_against_syntax_injection():
    # Operators and punctuation never reach FTS5 as syntax: only quoted terms joined by OR.
    assert fts_query('sql" OR 1=1 --') == '"sql" OR "1"'
    assert fts_query('NEAR(a b) "unbalanced') == '"near" OR "b" OR "unbalanced"'
    assert fts_query("") == "" and fts_query("the of a") == ""
    assert fts_query("CWE-89 sql_injection") == '"cwe-89" OR "sql_injection"'


def test_hybrid_search_finds_by_keyword_and_by_meaning(kb):
    top = kb.search_chunks("prepared statements parameterized queries", 2)
    assert top[0].doc_id == "SQL_Injection_Prevention_Cheat_Sheet"
    assert kb.search_chunks("hash passwords argon2id", 1)[0].doc_id == "Pwd_Cheat"
    assert len(kb.search_chunks("zzzz nothing matches qqqq", 3)) <= 3  # never raises
    only_cwe = kb.search_chunks("sql injection", 5, {"cwe"})
    assert only_cwe and {c.source for c in only_cwe} == {"cwe"}


def test_exact_document_id_queries_return_that_document_first(kb):
    hits = kb.search_chunks("CWE-89", 3)
    assert [c.heading for c in hits[:2]] == ["H", "Potential mitigations"] and hits[
        0
    ].doc_id == "CWE-89"
    assert kb.search_chunks("a05:2025", 1)[0].doc_id == "A05:2025"


def test_keyword_search_still_works_without_embeddings_or_when_the_model_server_is_down(tmp_path):
    keyword_only = KnowledgeBase(KBIndex.build(CORPUS, tmp_path / "k1"), None)
    assert (
        keyword_only.search_chunks("prepared statements", 1)[0].doc_id
        == "SQL_Injection_Prevention_Cheat_Sheet"
    )

    class Down(FakeEmbedder):
        def embed(self, texts, kind):
            if kind == "query":
                raise LLMError("server down")
            return super().embed(texts, kind)

    built = KBIndex.build(CORPUS, tmp_path / "k2", Down())
    assert (
        KnowledgeBase(built, Down()).search_chunks("prepared statements", 1)[0].doc_id
        == "SQL_Injection_Prevention_Cheat_Sheet"
    )


def test_embedding_model_mismatch_falls_back_to_keywords(tmp_path):
    built = KBIndex.build(CORPUS, tmp_path / "k", FakeEmbedder())

    class Other(FakeEmbedder):
        model = "different-model"

    assert (
        KnowledgeBase(built, Other()).search_chunks("prepared statements", 1)[0].doc_id
        == "SQL_Injection_Prevention_Cheat_Sheet"
    )


def test_results_carry_citations_and_stats(kb):
    (hit,) = kb.search("prepared statements parameterized", 1)
    assert hit.startswith(
        "[SQL Injection Prevention > H | v1 | CC BY-SA 4.0] (https://x/SQL_Injection_Prevention_Cheat_Sheet)"
    )
    st = kb.index.stats()
    assert (
        st["chunks"] == len(CORPUS)
        and st["by_source"]["cwe"] == 2
        and st["embedding_model"] == "fake-embed"
    )


def test_lookup_comes_from_the_kb(kb):
    full = kb.lookup("CWE-89")
    assert full and "SQL Injection" in full and "mitigations" in full
    assert kb.lookup("CWE-99999") is None


def test_references_are_curated_and_never_guessed(kb):
    refs = kb.references_for(["CWE-89"])
    assert refs == [
        "OWASP Cheat Sheet: SQL Injection Prevention (https://x/SQL_Injection_Prevention_Cheat_Sheet, v1)"
    ]
    # A CWE with no curated entry gets nothing (not the nearest fuzzy match); a curated sheet
    # that is not in this index is not cited either.
    assert kb.references_for(["CWE-704"]) == [] and kb.references_for(["CWE-424242"]) == []
    assert (
        kb.references_for(["CWE-79"]) == []
    )  # curated, but the XSS sheet is not in this tiny index
    assert (
        kb.references_for(["CWE-250"]) == []
    )  # the root-user Dockerfile case must not cite logging
    assert kb.references_for([], dependency=True) == []  # supply-chain sheet absent here


def test_curated_map_is_well_formed():
    from gapscan.kb.references import CWE_TO_CHEATSHEETS, cheatsheets_for

    assert cheatsheets_for(["CWE-89"]) == [
        "SQL_Injection_Prevention_Cheat_Sheet",
        "Query_Parameterization_Cheat_Sheet",
    ]
    assert cheatsheets_for(["CWE-89", "CWE-564"]) == cheatsheets_for(["CWE-89"])  # no duplicates
    assert cheatsheets_for(["CWE-1"], dependency=True) == [
        "Vulnerable_Dependency_Management_Cheat_Sheet"
    ]
    assert all(
        k.startswith("CWE-") and v and all(x.endswith("_Cheat_Sheet") for x in v)
        for k, v in CWE_TO_CHEATSHEETS.items()
    )


# --- tools / agent integration ---------------------------------------------------------


def test_lookup_cwe_tool_uses_the_kb_when_present(kb):
    r = ToolBox(ROOT / "eval" / "fixtures" / "vuln-app", "python", kb).execute(
        "lookup_cwe", {"id": "CWE-89"}
    )
    assert r.ok and "potential mitigations" in r.text and "Top 10:2025" in r.text
    assert (
        "prepared statements"
        in ToolBox(ROOT, "python", kb).execute("search_kb", {"query": "prepared statements"}).text
    )


def test_references_only_for_confirmed_findings(kb):
    def v(label, **kw):
        return Verdict(finding_id="x", verdict=label, confidence=0.9, cwe=["CWE-89"], **kw)

    assert with_references(v(VerdictLabel.TRUE_POSITIVE), kb).references
    assert with_references(v(VerdictLabel.LIKELY_TRUE_POSITIVE), kb).references
    dep = Finding(
        scanner="osv",
        rule_id="x",
        title="t",
        severity=Severity.LOW,
        category=Category.DEPENDENCY,
        package="p",
    )
    no_cwe = Verdict(finding_id="x", verdict=VerdictLabel.TRUE_POSITIVE, confidence=0.9)
    assert (
        with_references(no_cwe, kb).references == []
    )  # no CWE and not a dependency: nothing to cite
    assert (
        with_references(no_cwe, kb, dep).references == []
    )  # dependency sheet absent from this tiny index
    assert not with_references(v(VerdictLabel.FALSE_POSITIVE), kb).references
    assert not with_references(v(VerdictLabel.TRUE_POSITIVE, triage_failed=True), kb).references
    assert not with_references(v(VerdictLabel.TRUE_POSITIVE), None).references


def test_build_and_load_via_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = Config(
        data={"dir": str(tmp_path / "d"), "kb_dir": str(tmp_path / "d" / "kb")},
        kb={"policies_dir": str(tmp_path / "pol")},
    )
    assert load_kb(cfg) is None  # not built yet
    with pytest.raises(RuntimeError, match="no sources"):
        build_kb(cfg, embed=False)
    (tmp_path / "pol").mkdir()
    (tmp_path / "pol" / "p.md").write_text(
        "# Policy\n\n## Secrets\n\nSecrets must live in the vault and never in the repository."
    )
    build_kb(cfg, embed=False)
    kb = load_kb(cfg, use_embeddings=False)
    assert kb is not None and kb.search_chunks("vault secrets repository", 1)[0].source == "policy"


# --- real data (skipped when the KB has not been built on this machine) ------------------


needs_kb = pytest.mark.skipif(
    not (ROOT / "data" / "kb" / "kb.sqlite").is_file(), reason="run `gapscan kb build` first"
)


@needs_kb
def test_done_when_lookup_cwe_89_and_sql_injection_prevention_search_on_the_real_kb():
    cfg = Config()
    kb = load_kb(cfg, use_embeddings=False)  # keyword-only also has to work offline
    assert kb is not None
    entry = kb.lookup("CWE-89")
    assert entry and "SQL Injection" in entry and "MITRE" in entry
    top = kb.search_chunks("sql injection prevention", 3)
    assert (
        top[0].doc_id == "SQL_Injection_Prevention_Cheat_Sheet" and top[0].license == "CC BY-SA 4.0"
    )
    assert kb.search_chunks("A05:2025", 1)[0].title.startswith("A05:2025")
    api = kb.search_chunks("broken object level authorization", 1, {"api-top10-2023"})
    assert api and api[0].doc_id == "API1:2023"
    assert kb.references_for(["CWE-89"])[0].startswith(
        "OWASP Cheat Sheet: SQL Injection Prevention"
    )


def test_cwe_catalog_version_is_read_from_the_stored_xml(tmp_path):
    from gapscan.kb.ingest import cwe_catalog_version

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("cwec_v9.9.xml", CWE_XML)
    store = RawStore(tmp_path)
    assert cwe_catalog_version(store) == ""  # nothing stored yet
    store.save(
        "cwe/cwec_latest.xml.zip",
        buf.getvalue(),
        url="u",
        source="mitre-cwe",
        version="latest",
        license="MITRE",
    )
    assert cwe_catalog_version(store) == "CWE 9.9 (2030-01-01)"
