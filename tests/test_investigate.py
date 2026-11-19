"""Deep-dive investigation: the whole-project search tools, deterministic
grounding of every cited line, and the tool loop."""

from __future__ import annotations

import json

import pytest

from gapscan.agent import tools as tools_mod
from gapscan.agent.investigate import DeepStep, Seen, ground, investigate, is_code_shaped
from gapscan.agent.tools import DEEP_TOOL_NAMES, TOOL_NAMES, ToolBox
from gapscan.context.extract import build_context
from gapscan.models import (
    Category,
    EvidenceEffect,
    EvidenceItem,
    Finding,
    InvestigationAnswer,
    ProtectionState,
    RelatedItem,
    ScopeItem,
    Severity,
    Verdict,
    VerdictLabel,
)

from .test_agent import scripted, tool

KEY_MANAGER = """package app.db

// legacy passphrase was hunter2-legacy
class DatabaseKeyManager(private val policy: EncryptionPolicy) {
    fun key(): ByteArray {
        if (!policy.enabled) return LEGACY_KEY
        return wrapWithKeystore(randomKey())
    }
}
"""
POLICY = """package app.db

class EncryptionPolicy(val flavor: String) {
    val enabled: Boolean get() = flavor == "prod"
}
"""


@pytest.fixture
def project(tmp_path):
    (tmp_path / "app/src/main/db").mkdir(parents=True)
    (tmp_path / "app/src/main/db/DatabaseKeyManager.kt").write_text(KEY_MANAGER)
    (tmp_path / "app/src/main/db/EncryptionPolicy.kt").write_text(POLICY)
    (tmp_path / "app/src/main/res").mkdir()
    (tmp_path / "app/src/main/res/strings.xml").write_text(
        '<resources>\n  <string name="factorySecretKey">LEGACY_KEY</string>\n</resources>\n'
    )
    (tmp_path / ".env").write_text("LEGACY_KEY=abc\n")  # credential file: never searched
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules/x.js").write_text("LEGACY_KEY\n")  # vendored: skipped
    return tmp_path


def kt_finding() -> Finding:
    return Finding(scanner="semgrep", rule_id="hardcoded-db-key", title="Hardcoded DB key",
                   severity=Severity.HIGH, category=Category.CODE, cwe=["CWE-321"],
                   file="app/src/main/db/DatabaseKeyManager.kt", start_line=6, end_line=6)  # fmt: skip


def confirmed(f: Finding) -> Verdict:
    return Verdict(finding_id=f.id, verdict=VerdictLabel.TRUE_POSITIVE, confidence=0.9,
                   reasoning="the legacy key is used when the policy is off")  # fmt: skip


def final(**answer):
    base = {"summary": "s", "protection": "partial"}
    return json.dumps({"action": "final", "answer": base | answer})


# --- search_repo / list_files ------------------------------------------------------------


def test_deep_tools_extend_the_triage_tools_only():
    assert set(TOOL_NAMES) < set(DEEP_TOOL_NAMES)
    assert {"search_repo", "list_files", "build_variants", "read_config"} == set(
        DEEP_TOOL_NAMES
    ) - set(TOOL_NAMES)


def test_search_repo_finds_every_line_and_reports_a_complete_search(project):
    r = ToolBox(project).execute("search_repo", {"text": "legacy_key"})
    assert r.ok and r.outcome == "matches_found"
    assert "app/src/main/db/DatabaseKeyManager.kt:6:" in r.text
    assert "app/src/main/res/strings.xml:2:" in r.text
    assert "node_modules" not in r.text and ".env" not in r.text
    assert "1 credential files not searched" in r.text and "search COMPLETE" in r.text
    assert ("app/src/main/res/strings.xml", 2, 2) in r.seen


def test_search_repo_empty_and_complete_is_proof_of_absence(project):
    r = ToolBox(project).execute("search_repo", {"text": "PRAGMA rekey"})
    assert r.ok and r.outcome == "no_matches" and "search COMPLETE" in r.text and not r.seen


def test_a_glob_that_matches_no_file_does_not_prove_absence(project):
    r = ToolBox(project).execute("search_repo", {"text": "PRAGMA rekey", "glob": "*.nothing"})
    assert r.outcome == "no_matches_incomplete" and "no searchable file matched" in r.text


def test_a_glob_limited_empty_search_proves_absence_within_the_glob(project):
    r = ToolBox(project).execute("search_repo", {"text": "PRAGMA rekey", "glob": "*.kt"})
    assert r.outcome == "no_matches" and "COMPLETE within the glob" in r.text
    assert r.scope == "*.kt"


def test_absence_claims_carry_the_scope_of_their_search(project):
    f = kt_finding()
    replies = [
        tool("search_repo", text="PRAGMA rekey", glob="*.kt"),
        tool("search_repo", text="rotateKey"),
        final(evidence=[
            {"claim": "no re-key in Kotlin code", "effect": "missing", "search": "PRAGMA rekey"},
            {"claim": "no rotation", "effect": "missing", "search": "rotateKey",
             "search_scope": "*.md"},  # the model's value is ignored
        ]),
    ]  # fmt: skip
    inv = investigate(scripted(replies), f, None, confirmed(f), ToolBox(project))
    assert inv.answer is not None
    assert [e.search_scope for e in inv.answer.evidence] == ["*.kt", ""]


def test_only_absence_claims_keep_a_search():
    seen = Seen()
    seen.add("a.kt", 1, 5)
    answer = InvestigationAnswer(summary="s", protection=ProtectionState.ABSENT, evidence=[
        EvidenceItem(claim="c", ref="a.kt:2", effect=EvidenceEffect.UNDERMINES, search="x",
                     search_scope="")])  # fmt: skip
    kept, _ = ground(answer, seen)
    assert kept.evidence[0].search is None and kept.evidence[0].search_scope is None


def test_search_repo_glob_limits_the_files(project):
    r = ToolBox(project).execute("search_repo", {"text": "LEGACY_KEY", "glob": "*.xml"})
    assert "strings.xml" in r.text and "DatabaseKeyManager" not in r.text
    r = ToolBox(project).execute("search_repo", {"text": "LEGACY_KEY", "glob": "app/**/db/*.kt"})
    assert "DatabaseKeyManager" in r.text and "strings.xml" not in r.text


def test_search_repo_hit_cap_makes_the_search_incomplete(project, monkeypatch):
    monkeypatch.setattr(tools_mod, "MAX_SEARCH_HITS", 1)
    r = ToolBox(project).execute("search_repo", {"text": "legacy"})
    assert r.outcome == "matches_found" and "search INCOMPLETE" in r.text
    assert len(r.seen) == 1


def test_search_repo_with_a_skipped_file_cannot_prove_absence(project, monkeypatch):
    monkeypatch.setattr(tools_mod, "MAX_FILE_BYTES", 10)
    r = ToolBox(project).execute("search_repo", {"text": "PRAGMA rekey"})
    assert r.outcome == "no_matches_incomplete" and "too large or unreadable" in r.text


def test_search_repo_masks_secrets_and_never_leaves_the_target(tmp_path):
    outside = tmp_path / "outside.kt"
    outside.write_text('val token = "OUTSIDE-NEEDLE"\n')
    target = tmp_path / "t"
    target.mkdir()
    (target / "link.kt").symlink_to(outside)
    (target / "a.kt").write_text('val password = "s3cr3t-NEEDLE-value"\n')
    r = ToolBox(target).execute("search_repo", {"text": "needle"})
    assert "OUTSIDE" not in r.text and "link.kt" not in r.text
    assert "a.kt:1:" in r.text and "s3cr3t" not in r.text


@pytest.mark.parametrize(
    "args", [{"text": "x"}, {"text": "a\nb"}, {"text": "ok", "glob": "../*"}, {}]
)
def test_search_repo_rejects_bad_arguments(project, args):
    assert not ToolBox(project).execute("search_repo", args).ok


def test_list_files_matches_names_and_paths(project):
    tb = ToolBox(project)
    assert tb.execute("list_files", {"glob": "*.xml"}).text == "app/src/main/res/strings.xml"
    assert "EncryptionPolicy.kt" in tb.execute("list_files", {"glob": "**/db/*.kt"}).text
    assert tb.execute("list_files", {"glob": "*.swift"}).outcome == "no_files"
    assert not tb.execute("list_files", {"glob": "/etc/*;rm"}).ok


def test_read_code_records_the_lines_it_showed(project):
    r = ToolBox(project).execute("read_code", {"file": "app/src/main/db/EncryptionPolicy.kt",
                                              "start": 3, "end": 4})  # fmt: skip
    assert r.seen == [("app/src/main/db/EncryptionPolicy.kt", 3, 4)]


# --- grounding ---------------------------------------------------------------------------


def test_grounding_keeps_only_shown_lines_and_proven_absence():
    seen = Seen()
    seen.add("a.kt", 10, 20)
    seen.empty_searches["pragma rekey"] = ""
    answer = InvestigationAnswer(
        summary="s", protection=ProtectionState.PARTIAL,
        evidence=[
            EvidenceItem(claim="shown", ref="a.kt:12-15", effect=EvidenceEffect.PROTECTS),
            EvidenceItem(claim="./ prefix ok", ref="./a.kt:20", effect=EvidenceEffect.UNDERMINES),
            EvidenceItem(claim="runs past", ref="a.kt:18-25", effect=EvidenceEffect.PROTECTS),
            EvidenceItem(claim="other file", ref="b.kt:1", effect=EvidenceEffect.UNDERMINES),
            EvidenceItem(claim="no ref", effect=EvidenceEffect.UNDERMINES),
            EvidenceItem(claim="no rekey", effect=EvidenceEffect.MISSING, search="PRAGMA rekey"),
            EvidenceItem(claim="unsearched", effect=EvidenceEffect.MISSING, search="rotate"),
            EvidenceItem(claim="unbacked", effect=EvidenceEffect.MISSING),
        ],
        scope=[ScopeItem(where="prod", affected=False, ref="a.kt:11"),
               ScopeItem(where="dev", affected=True, ref="a.kt:99")],
        related=[RelatedItem(ref="a.kt:10", note="same"), RelatedItem(ref="garbage", note="x")],
    )  # fmt: skip
    kept, dropped = ground(answer, seen)
    assert [e.claim for e in kept.evidence] == ["shown", "./ prefix ok", "no rekey"]
    assert [s.where for s in kept.scope] == ["prod"]
    assert [r.ref for r in kept.related] == ["a.kt:10"]
    assert len(dropped) == 5 + 1 + 1


# --- loop --------------------------------------------------------------------------------


def test_investigation_cites_only_what_the_tools_showed(project):
    f = kt_finding()
    ctx = build_context(f, project)
    replies = [
        tool("search_repo", text="LEGACY_KEY"),
        tool("search_repo", text="PRAGMA rekey"),
        tool("find_definition", symbol="EncryptionPolicy",
             file="app/src/main/db/DatabaseKeyManager.kt"),
        final(
            evidence=[
                {"claim": "keystore-wrapped key exists", "effect": "protects",
                 "ref": "app/src/main/db/DatabaseKeyManager.kt:7"},
                {"claim": "only prod enables it", "effect": "undermines",
                 "ref": "app/src/main/db/EncryptionPolicy.kt:4"},
                {"claim": "no re-key of old databases", "effect": "missing",
                 "search": "PRAGMA rekey"},
                {"claim": "invented line", "effect": "undermines",
                 "ref": "app/src/main/db/Migrations.kt:40"},
            ],
            scope=[{"where": "dev and staging flavors", "affected": True,
                    "ref": "app/src/main/db/EncryptionPolicy.kt:4"}],
            related=[{"ref": "app/src/main/res/strings.xml:2",
                      "note": "legacy key compiled into resources"}],
            remediation=["enable encryption in every flavor", "re-key existing databases"],
            verification=["pull the DB from a test device and confirm it does not open"],
            target_state="done when every build uses the keystore key",
        ),
    ]  # fmt: skip
    inv = investigate(scripted(replies), f, ctx, confirmed(f), ToolBox(project, "kotlin"))
    assert not inv.failed and inv.answer is not None
    claims = [e.claim for e in inv.answer.evidence]
    assert claims == ["keystore-wrapped key exists", "only prod enables it",
                      "no re-key of old databases"]  # fmt: skip
    assert len(inv.answer.scope) == 1 and len(inv.answer.related) == 1
    assert inv.dropped == [
        "evidence: app/src/main/db/Migrations.kt:40 was not shown for 'invented line'"
    ]
    assert [t.tool for t in inv.tool_calls] == ["search_repo", "search_repo", "find_definition"]
    assert inv.prompt_version == "investigate_v4" and inv.tokens > 0


def test_investigation_is_forced_to_answer_at_the_budget(project):
    f = kt_finding()
    sent: list[dict] = []
    replies = [tool("list_files", glob="*.kt"), final()]
    inv = investigate(scripted(replies, sent), f, None, confirmed(f), ToolBox(project),
                      max_tool_calls=1)  # fmt: skip
    assert not inv.failed and len(inv.tool_calls) == 1
    assert "Tool budget used up" in sent[-1]["messages"][-1]["content"]


def test_a_tool_request_after_the_budget_fails_the_investigation(project):
    f = kt_finding()
    replies = [tool("list_files", glob="*.kt")] * 2
    inv = investigate(scripted(replies), f, None, confirmed(f), ToolBox(project),
                      max_tool_calls=1)  # fmt: skip
    assert inv.failed and len(inv.tool_calls) == 1


def test_invalid_output_marks_the_investigation_failed(project):
    f = kt_finding()
    inv = investigate(scripted(["not json"] * 3), f, None, confirmed(f), ToolBox(project))
    assert inv.failed and inv.answer is None and "invalid" in inv.error


def test_tools_outside_the_allowlist_are_rejected_by_the_schema():
    with pytest.raises(ValueError):
        DeepStep.model_validate({"action": "tool", "tool": "run_shell", "args": {}})


def test_prompt_wraps_project_content_as_untrusted(project):
    f = kt_finding()
    sent: list[dict] = []
    investigate(scripted([final()], sent), f, build_context(f, project), confirmed(f),
                ToolBox(project))  # fmt: skip
    prompt = sent[0]["messages"][0]["content"]
    body = prompt.split("<untrusted_data>", 1)[1]
    assert "TRIAGE VERDICT: true_positive" in body and "DatabaseKeyManager" in body
    assert "search_repo" in prompt and "list_files" in prompt


# --- pipeline and report -----------------------------------------------------------------


def _scan(project):
    from gapscan.models import ScanResult

    hi = kt_finding().model_copy(update={"priority": 80.0})
    lo = Finding(scanner="semgrep", rule_id="low", title="Low", severity=Severity.LOW,
                 category=Category.CODE, file="app/src/main/db/EncryptionPolicy.kt",
                 start_line=4, end_line=4, priority=20.0)  # fmt: skip
    fp = Finding(scanner="semgrep", rule_id="fp", title="FP", severity=Severity.HIGH,
                 category=Category.CODE, file="app/src/main/db/EncryptionPolicy.kt",
                 start_line=3, end_line=3, priority=90.0)  # fmt: skip
    verdicts = [
        confirmed(hi),
        confirmed(lo),
        Verdict(finding_id=fp.id, verdict=VerdictLabel.FALSE_POSITIVE, confidence=0.9),
    ]
    return ScanResult(target=str(project), findings=[lo, hi, fp]), verdicts, hi


def test_only_confirmed_findings_above_the_priority_cut_are_investigated(project):
    from gapscan.agent.review import deep_dive_groups
    from gapscan.config import Config

    result, verdicts, hi = _scan(project)
    assert [[f.id for f in g] for g in deep_dive_groups(Config(), result, verdicts, 10)] == [
        [hi.id]
    ]
    cfg = Config.model_validate({"agent": {"deep_dive_min_priority": 0}})
    assert len(deep_dive_groups(cfg, result, verdicts, 10)) == 2  # never the false positive
    assert len(deep_dive_groups(cfg, result, verdicts, 1)) == 1


def test_pipeline_runs_the_deep_dive_and_the_report_shows_it_masked(project, tmp_path):
    from gapscan.agent.review import deep_dive_findings
    from gapscan.config import Config
    from gapscan.llm.cache import ResponseCache
    from gapscan.report.build import build_report

    result, verdicts, hi = _scan(project)
    reply = final(
        summary='key is api_key = "' + "sk_" + "live_0123456789abcdefghijklmn" + '" in prod',
        evidence=[{"claim": "legacy key used", "effect": "undermines",
                   "ref": "app/src/main/db/DatabaseKeyManager.kt:6"},
                  {"claim": "made up", "effect": "protects", "ref": "nowhere.kt:1"}],
        remediation=["rotate the key"],
    )  # fmt: skip
    seen_ids: list[str] = []
    invs = deep_dive_findings(
        Config(), result, project, verdicts, limit=5, client=scripted([reply]),
        cache=ResponseCache(tmp_path / "c.sqlite"), kb=None,
        on_investigation=lambda i: seen_ids.append(i.finding_id),
    )  # fmt: skip
    assert seen_ids == [hi.id] and len(invs[0].dropped) == 1
    report = build_report(result, verdicts, None, config=Config(), target=project,
                          investigations=invs)  # fmt: skip
    dd = report.details[hi.id].deep_dive
    assert dd is not None and not dd.failed and dd.dropped == 1
    assert [e.claim for e in dd.evidence] == ["legacy key used"]
    assert "sk_live" not in dd.summary and dd.remediation == ["rotate the key"]
    others = [d for fid, d in report.details.items() if fid != hi.id]
    assert all(d.deep_dive is None for d in others)


# --- root-cause grouping, manifests, globs, self-references ------------------------------


def _f(rule, line, cwe=(), *, file="app.py", title="t", cat=Category.CODE, prio=50.0, **kw):
    return Finding(scanner="semgrep", rule_id=rule, title=title, severity=Severity.HIGH,
                   category=cat, cwe=list(cwe), file=file, start_line=line, end_line=line,
                   priority=prio, **kw)  # fmt: skip


def test_scanner_duplicates_of_one_bug_are_grouped_but_different_bugs_are_not():
    from gapscan.agent.grouping import group_findings, group_id

    sqli = [
        _f("python.sqlalchemy.security.sqlalchemy-execute-raw-query", 16, ["CWE-89"], prio=70),
        _f("python.flask.security.injection.tainted-sql-string", 16, ["CWE-704"], prio=60),
        _f("python.django.security.injection.tainted-sql-string", 16, ["CWE-915"]),
    ]
    cmd = [
        _f("python.lang.security.audit.subprocess-shell-true", 23, ["CWE-78"]),
        _f("gapscan.python.command-injection", 23, ["CWE-78"]),
    ]
    xss = _f("gapscan.python.taint-xss", 23, ["CWE-79"])  # same line, different bug
    docker = [
        _f(
            "DS-0002",
            None,
            file="Dockerfile",
            title="Image user should not be 'root'",
            message="Specify at least 1 USER command in Dockerfile",
            cat=Category.CONFIG,
        ),
        _f(
            "dockerfile.security.missing-user",
            4,
            ["CWE-250"],
            file="Dockerfile",
            cat=Category.CONFIG,
        ),
    ]
    deps = [_f("PYSEC-1", None, file="requirements.txt", cat=Category.DEPENDENCY,
               package="Flask", version="1.0"),
            _f("PYSEC-2", None, file="requirements.txt", cat=Category.DEPENDENCY,
               package="flask", version="1.0"),
            _f("PYSEC-3", None, file="requirements.txt", cat=Category.DEPENDENCY,
               package="flask", version="2.0")]  # fmt: skip
    groups = group_findings([*sqli, *cmd, xss, *docker, *deps])
    sizes = sorted(len(g) for g in groups)
    assert sizes == [1, 1, 2, 2, 2, 3]  # DS-0002 joins the other run-as-root rule
    sql_group = next(g for g in groups if len(g) == 3)
    assert sql_group[0].id == sqli[0].id  # highest priority is investigated
    assert group_id(sql_group) == group_id(list(reversed(sql_group)))


def test_dependency_findings_show_and_may_cite_the_manifest_line(project):
    (project / "requirements.txt").write_text("requests==2.0\nFlask==1.0\nflask-cors==3\n")
    dep = Finding(scanner="osv", rule_id="PYSEC-2023-62", title="Flask cookie", package="flask",
                  version="1.0", severity=Severity.HIGH, category=Category.DEPENDENCY,
                  file="requirements.txt")  # fmt: skip
    sent: list[dict] = []
    reply = final(evidence=[{"claim": "Flask 1.0 is pinned", "effect": "undermines",
                             "ref": "requirements.txt:2"}])  # fmt: skip
    inv = investigate(scripted([reply], sent), dep, None, confirmed(dep), ToolBox(project))
    prompt = sent[0]["messages"][0]["content"]
    assert "WHERE requirements.txt DECLARES flask" in prompt and "2 | Flask==1.0" in prompt
    assert "flask-cors" not in prompt.split("DECLARES flask", 1)[1].split("</untrusted_data>")[0]
    assert inv.answer is not None and len(inv.answer.evidence) == 1 and not inv.dropped


def test_whole_project_globs_count_as_no_glob(project):
    r = ToolBox(project).execute("search_repo", {"text": "PRAGMA rekey", "glob": "**/*"})
    assert r.outcome == "no_matches" and "search COMPLETE" in r.text


def test_related_locations_cannot_be_the_finding_itself(project):
    f = kt_finding()
    ctx = build_context(f, project)
    reply = final(related=[
        {"ref": "app/src/main/db/DatabaseKeyManager.kt:6", "note": "itself"},
        {"ref": "app/src/main/res/strings.xml:2", "note": "same key in resources"},
    ])  # fmt: skip
    replies = [tool("search_repo", text="LEGACY_KEY"), reply]
    inv = investigate(scripted(replies), f, ctx, confirmed(f), ToolBox(project))
    assert inv.answer is not None
    assert [r.ref for r in inv.answer.related] == ["app/src/main/res/strings.xml:2"]
    assert any("is the finding itself" in d for d in inv.dropped)


def test_one_investigation_is_shown_on_every_group_member(project, tmp_path):
    from gapscan.agent.review import deep_dive_findings
    from gapscan.config import Config
    from gapscan.llm.cache import ResponseCache
    from gapscan.models import ScanResult
    from gapscan.report.build import build_report

    a = kt_finding().model_copy(update={"priority": 80.0})
    b = Finding(scanner="gitleaks", rule_id="hardcoded-key-2", title="Hardcoded DB key",
                severity=Severity.HIGH, category=Category.CODE, cwe=["CWE-321"],
                file=a.file, start_line=6, end_line=6, priority=70.0)  # fmt: skip
    result = ScanResult(target=str(project), findings=[a, b])
    sent: list[dict] = []
    invs = deep_dive_findings(Config(), result, project, [confirmed(a), confirmed(b)], limit=5,
                              client=scripted([final()], sent),
                              cache=ResponseCache(tmp_path / "c.sqlite"), kb=None)  # fmt: skip
    assert len(invs) == 1 and invs[0].finding_id == a.id and set(invs[0].covers) == {a.id, b.id}
    assert "OTHER SCANNER RESULTS FOR THIS SAME ISSUE" in sent[0]["messages"][0]["content"]
    report = build_report(result, [confirmed(a), confirmed(b)], None, config=Config(),
                          target=project, investigations=invs)  # fmt: skip
    for fid in (a.id, b.id):
        dd = report.details[fid].deep_dive
        assert dd is not None and dd.covers == 2


def test_regex_syntax_is_rejected_so_it_cannot_prove_absence(project):
    tb = ToolBox(project)
    for text in ("flask.*session", "feature|FLAG", r"key\d+", "a.+b"):
        r = tb.execute("search_repo", {"text": text})
        assert not r.ok and "literal" in r.text, text
    assert tb.execute("search_repo", {"text": "pickle.loads("}).ok  # plain code is fine


def test_related_refs_on_a_different_scanned_issue_are_dropped():
    from gapscan.agent.investigate import other_issue_lines

    sqli = _f("gapscan.python.taint-sqli", 16, ["CWE-89"])
    cmd = _f("gapscan.python.command-injection", 23, ["CWE-78"])
    sqli_again = _f("gapscan.python.sqli-string-built", 40, ["CWE-89"])
    other = other_issue_lines([sqli], [sqli, cmd, sqli_again])
    assert other == [("app.py", 23, 23)]
    seen = Seen()
    seen.add("app.py", 1, 50)
    answer = InvestigationAnswer(summary="s", protection=ProtectionState.ABSENT, related=[
        RelatedItem(ref="app.py:23", note="command injection"),
        RelatedItem(ref="app.py:40", note="same string-built SQL"),
    ])  # fmt: skip
    kept, dropped = ground(answer, seen, [("app.py", 16, 16)], other)
    assert [r.ref for r in kept.related] == ["app.py:40"]
    assert dropped == ["related: app.py:23 is a different kind of issue found by the scan"]


# --- checklists, code-shaped absence, import-level grouping -------------------------------


def test_every_checklist_is_reachable_and_complete():
    from gapscan.agent.checklists import load_checklists
    from gapscan.agent.grouping import _KINDS

    classes = load_checklists()["classes"]
    reachable = {name for name, _ in _KINDS} | {"secret", "dependency"}
    assert set(classes) <= reachable
    for name, entry in classes.items():
        assert entry["source"].endswith("Cheat_Sheet") and entry["fix"] and entry["controls"], name
        for c in entry["controls"]:
            assert all(sig.strip() for sig in c["signals"]), (name, c["signals"])


def test_the_checklist_is_trusted_guidance_outside_the_project_data(project):
    f = _f("python.lang.security.insecure-hash-algorithm-md5", 6, ["CWE-327"],
           file="app/src/main/db/DatabaseKeyManager.kt")  # fmt: skip
    sent: list[dict] = []
    investigate(scripted([final()], sent), f, None, confirmed(f), ToolBox(project))
    prompt = sent[0]["messages"][0]["content"]
    head, data = prompt.rsplit("<untrusted_data>", 1)  # the rules text also names the tag
    assert "Password Storage Cheat Sheet" in head and "Argon2id" in head
    assert "Replacing MD5 with SHA-256" in head  # the known-wrong fix is called out
    assert "Cheat Sheet" not in data


def test_no_checklist_for_a_weakness_gapscan_has_none_for(project):
    sent: list[dict] = []
    f = kt_finding()  # CWE-321, no checklist
    investigate(scripted([final()], sent), f, None, confirmed(f), ToolBox(project))
    assert "What good looks like" not in sent[0]["messages"][0]["content"]


def test_absence_must_rest_on_a_code_shaped_search():
    assert not is_code_shaped("parameterized") and not is_code_shaped("avoid pickle")
    assert (
        is_code_shaped("USER") and is_code_shaped("shell=False") and is_code_shaped("json.loads(")
    )
    seen = Seen()
    seen.empty_searches.update({"parameterized": "", "bindparam(": ""})
    answer = InvestigationAnswer(summary="s", protection=ProtectionState.ABSENT, evidence=[
        EvidenceItem(claim="no params", effect=EvidenceEffect.MISSING, search="parameterized"),
        EvidenceItem(claim="no bind", effect=EvidenceEffect.MISSING, search="bindparam("),
    ])  # fmt: skip
    kept, dropped = ground(answer, seen)
    assert [e.claim for e in kept.evidence] == ["no bind"]
    assert "plain word" in dropped[0]
    # a checklist signal is vetted even when it is a plain word ("useradd" in a Dockerfile)
    seen.empty_searches["useradd"] = "**/Dockerfile*"
    answer = InvestigationAnswer(summary="s", protection=ProtectionState.ABSENT, evidence=[
        EvidenceItem(claim="no user", effect=EvidenceEffect.MISSING, search="useradd")])  # fmt: skip
    assert ground(answer, seen)[0].evidence == []
    assert len(ground(answer, seen, vetted={"useradd"})[0].evidence) == 1


def test_an_import_finding_joins_the_calls_it_enables():
    from gapscan.agent.grouping import group_findings

    b404 = _f("B404", 5, ["CWE-78"],
              title="Consider possible security implications associated with the subprocess module.")  # fmt: skip
    cmd = _f("python.lang.security.audit.subprocess-shell-true", 23, ["CWE-78"])
    sqli = _f("gapscan.python.taint-sqli", 16, ["CWE-89"])
    groups = group_findings([b404, cmd, sqli])
    assert sorted(len(g) for g in groups) == [1, 2]
    assert {f.rule_id for g in groups if len(g) == 2 for f in g} == {"B404", cmd.rule_id}
