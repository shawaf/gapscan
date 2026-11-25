from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path

import httpx
import pytest

from gapscan.agent.review import deep_dive_groups
from gapscan.config import Config
from gapscan.models import Investigation, InvestigationAnswer, RepoSummary, ScanResult, Verdict
from gapscan.report.dashboard import TEMPLATE_PATH
from gapscan.server import build_server
from gapscan.server.db import Database
from gapscan.server.jobs import Pipeline
from gapscan.server.security import Forbidden, check_host, require_loopback, split_host
from gapscan.services import effective_config

ROOT = Path(__file__).resolve().parent.parent
D = ROOT / "tests" / "data" / "report"
pytestmark = pytest.mark.skipif(
    not TEMPLATE_PATH.is_file(), reason="dashboard template not built (make dashboard)"
)


class FakePipeline(Pipeline):
    """The recorded fixture scan and model verdicts, with hooks to slow down, fail or cancel."""

    def __init__(self) -> None:
        self.scan_result = ScanResult.model_validate_json((D / "scan.json").read_text())
        tri = json.loads((D / "triage.json").read_text())
        self.verdicts = [Verdict.model_validate(v) for v in tri["verdicts"]]
        self.summary = RepoSummary.model_validate(tri["summary"])
        self.fail: str | None = None
        self.gate: threading.Event | None = (
            None  # when set, triage waits on it (to test cancelling)
        )
        self.started = threading.Event()
        self.scanned: list[Path] = []

    def scan(self, cfg, target):
        self.scanned.append(target)
        if self.fail:
            raise RuntimeError(self.fail)
        return self.scan_result.model_copy(deep=True)

    def triage(self, cfg, result, target, limit, on_verdict, memories=None):
        self.memories_seen = memories
        self.started.set()
        out = []
        for v in self.verdicts[:limit]:
            if self.gate is not None:
                self.gate.wait(5)
            on_verdict(v)
            out.append(v)
        return out

    def summarize(self, cfg, result, verdicts):
        return self.summary

    deep_fail: str | None = None
    deep_calls = 0

    def deep_dive(self, cfg, result, target, verdicts, limit, on_investigation):
        """Canned investigations for the real root-cause groups (no model)."""
        self.deep_calls += 1
        out = []
        for g in deep_dive_groups(cfg, result, verdicts, limit):
            if self.deep_fail:
                raise RuntimeError(self.deep_fail)
            inv = Investigation(
                finding_id=g[0].id, covers=[f.id for f in g], model="fake",
                prompt_version="investigate_v2",
                answer=InvestigationAnswer(summary="fake investigation", protection="absent"),
            )  # fmt: skip
            on_investigation(inv)
            out.append(inv)
        return out

    cases = [{"id": f"c{i}", "expected": "true_positive"} for i in range(4)]
    bench_gate = None

    def benchmark_cases(self):
        return self.cases

    def benchmark_case(self, cfg, model, case):
        if self.bench_gate is not None:
            self.bench_gate.wait(5)
        ok = case["id"] != "c3"
        return {
            "id": case["id"],
            "expected": case["expected"],
            "status": "ok",
            "verdict": "true_positive" if ok else "false_positive",
            "correct": ok,
            "seconds": 1.5,
            "attempts": 1,
            "confidence": 0.9,
            "prompt_tokens": 10,
            "completion_tokens": 5,
        }


class Client:
    def __init__(self, server, pipeline):
        self.server, self.pipeline = server, pipeline
        self.http = httpx.Client(
            base_url=f"http://127.0.0.1:{server.port}", follow_redirects=False, timeout=60
        )
        self.origin = f"http://127.0.0.1:{server.port}"
        self.http.get(f"/?token={server.token}")  # the cookie handshake the browser does

    def req(self, method, path, body=None, **kw):
        headers = {
            "Origin": self.origin,
            "Content-Type": "application/json",
            **kw.pop("headers", {}),
        }
        kw.setdefault("content", json.dumps(body) if body is not None else None)
        return self.http.request(
            method,
            path,
            content=kw.pop("content"),
            headers=headers,
            **kw,
        )

    def get(self, path, **kw):
        return self.http.get(path, **kw)

    def wait(self, scan_id, status=("done", "failed", "cancelled"), timeout=30):
        import time

        end = time.monotonic() + timeout
        while time.monotonic() < end:
            row = self.get(f"/api/scans/{scan_id}").json()
            if row["status"] in status:
                return row
            time.sleep(0.03)
        raise AssertionError(f"scan {scan_id} stuck: {row}")


@pytest.fixture
def env(tmp_path):
    cfg = Config(
        data={"dir": str(tmp_path / "data")},
        scanners={
            "osv": {"db_dir": str(tmp_path / "o")},
            "trivy": {"cache_dir": str(tmp_path / "t")},
        },
    )
    pipeline = FakePipeline()
    server = build_server(cfg, port=0, pipeline=pipeline)
    server._manager_html = "<!doctype html><title>manager</title>"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    project_dir = tmp_path / "myapp"
    project_dir.mkdir()
    (project_dir / "app.py").write_text("print('hi')\n")
    client = Client(server, pipeline)
    client.project_dir = project_dir
    yield client
    server.shutdown()
    server.jobs.stop()
    server.server_close()


def add_project(c, name="myapp", path=None):
    r = c.req("POST", "/api/projects", {"name": name, "path": str(path or c.project_dir)})
    assert r.status_code == 201, r.text
    return r.json()


# --- security --------------------------------------------------------------------------------


def test_api_requires_the_session_token(env):
    anon = httpx.Client(base_url=f"http://127.0.0.1:{env.server.port}")
    assert anon.get("/api/projects").status_code == 401
    assert anon.get("/").status_code == 401 and b"token" in anon.get("/").content
    assert anon.get("/health").json() == {"ok": True}  # liveness only, nothing sensitive
    assert anon.get("/?token=wrong").status_code == 401
    assert (
        anon.get(
            "/api/projects", headers={"Authorization": f"Bearer {env.server.token}"}
        ).status_code
        == 200
    )
    assert anon.get("/api/projects", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert anon.get("/api/projects", headers={"Cookie": "gapscan_session=nope"}).status_code == 401


def test_cookie_handshake_is_httponly_samesite_and_hides_the_token(env):
    r = httpx.get(
        f"http://127.0.0.1:{env.server.port}/?token={env.server.token}", follow_redirects=True
    )
    assert r.status_code == 200 and r.history  # redirected, so the token leaves the address bar
    first = httpx.get(
        f"http://127.0.0.1:{env.server.port}/?token={env.server.token}", follow_redirects=False
    )
    cookie = first.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and first.headers["location"] == "/"
    assert env.get("/").status_code in (
        200,
        503,
    )  # the manager page (503 only if the UI is not built yet)


def test_dns_rebinding_is_refused(env):
    for host in (
        "evil.com",
        f"evil.com:{env.server.port}",
        "127.0.0.1.evil.com",
        f"127.0.0.1:{env.server.port + 1}",
    ):
        r = env.get("/api/projects", headers={"Host": host})
        assert r.status_code == 421, host
    assert (
        env.get("/api/projects", headers={"Host": f"localhost:{env.server.port}"}).status_code
        == 200
    )


def test_cross_site_writes_are_refused(env):
    body = json.dumps({"path": str(env.project_dir)})
    no_origin = env.http.post(
        "/api/projects", content=body, headers={"Content-Type": "application/json"}
    )
    foreign = env.http.post(
        "/api/projects",
        content=body,
        headers={"Content-Type": "application/json", "Origin": "https://evil.example"},
    )
    form = env.http.post(
        "/api/projects",
        content=f"path={env.project_dir}",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": env.origin},
    )
    assert (no_origin.status_code, foreign.status_code, form.status_code) == (403, 403, 415)
    assert env.get("/api/projects").json() == []  # none of them created anything


def test_responses_carry_security_headers_and_a_csp(env):
    r = env.get("/api/projects")
    assert (
        r.headers["x-content-type-options"] == "nosniff"
        and r.headers["referrer-policy"] == "no-referrer"
    )
    assert (
        r.headers["cache-control"] == "no-store"
        and "default-src 'none'" in r.headers["content-security-policy"]
    )
    assert "frame-ancestors 'self'" in r.headers["content-security-policy"]


def test_only_loopback_addresses_are_accepted(tmp_path):
    for ok in ("127.0.0.1", "localhost", "::1", "127.0.0.5"):
        require_loopback(ok)
    for bad in ("0.0.0.0", "192.168.1.5", "example.com", ""):
        with pytest.raises(ValueError, match="loopback"):
            require_loopback(bad)
    with pytest.raises(ValueError):
        build_server(Config(data={"dir": str(tmp_path)}), host="0.0.0.0")
    assert not (tmp_path / "gapscan.db").exists()  # refused before the database is created


def test_host_header_parsing():
    assert split_host("127.0.0.1:8765") == ("127.0.0.1", "8765") and split_host("[::1]:80") == (
        "[::1]",
        "80",
    )
    assert split_host("localhost") == ("localhost", "")
    check_host("[::1]:8765", 8765)
    with pytest.raises(Forbidden):
        check_host("127.0.0.1:1", 8765)
    with pytest.raises(Forbidden):
        check_host(None, 8765)


def test_malformed_requests_get_clean_errors(env):
    assert env.req("POST", "/api/projects", None, content=b"{not json").status_code == 400
    assert (
        env.http.post(
            "/api/projects",
            content=b"[1]",
            headers={"Origin": env.origin, "Content-Type": "application/json"},
        ).status_code
        == 400
    )
    big = env.http.post(
        "/api/projects",
        content=b"x" * 1_100_000,
        headers={"Origin": env.origin, "Content-Type": "application/json"},
    )
    assert big.status_code == 413
    # The unread body must not be parsed as the next request on a kept-alive connection.
    assert big.headers.get("Connection") == "close"
    assert env.get("/api/nope").status_code == 404 and env.req(
        "PATCH", "/api/projects", {}
    ).status_code in (404, 405, 501)
    assert env.req("DELETE", "/api/settings").status_code == 405
    assert "Traceback" not in env.get("/api/scans/999999").text


# --- projects ---------------------------------------------------------------------------------


def test_project_validation(env, tmp_path):
    p = add_project(env)
    assert p["name"] == "myapp" and p["latest"] is None and p["history"] == []
    assert (
        env.req("POST", "/api/projects", {"path": str(env.project_dir)}).status_code == 409
    )  # duplicate
    for bad, why in [("relative/path", "absolute"), (str(tmp_path / "missing"), "not a folder"), ("/", "root"), (str(Path.home()), "home"),
                     (str(tmp_path / "data"), "own data"), ("", "required")]:  # fmt: skip
        r = env.req("POST", "/api/projects", {"path": bad})
        assert r.status_code == 400, why
    (tmp_path / "data").mkdir(exist_ok=True)
    assert env.req("POST", "/api/projects", {"path": str(tmp_path / "data")}).status_code == 400
    assert [x["name"] for x in env.get("/api/projects").json()] == ["myapp"]


def test_a_project_has_a_security_service_with_capability_toggles(env):
    p = add_project(env)
    services = env.get(f"/api/projects/{p['id']}/services").json()
    assert [s["domain"] for s in services] == ["security"]
    sec = services[0]
    assert sec["enabled"] is True
    assert sec["capabilities"]["enabled"] == ["sast", "sca", "secrets", "iac"]
    available = {c["id"]: c["reserved"] for c in sec["capabilities"]["available"]}
    assert available["sast"] is False and available["containers"] is True
    # Narrow to a subset; the response reflects it in catalogue order.
    put = env.req(
        "PUT", f"/api/projects/{p['id']}/services/security",
        {"capabilities": ["secrets", "sast"]},
    )  # fmt: skip
    assert put.status_code == 200
    assert put.json()["capabilities"]["enabled"] == ["sast", "secrets"]
    # Reserved/unknown capabilities and an unknown domain are refused.
    assert (
        env.req(
            "PUT", f"/api/projects/{p['id']}/services/security", {"capabilities": ["containers"]}
        ).status_code
        == 400
    )
    assert (
        env.req("PUT", f"/api/projects/{p['id']}/services/ghost", {"enabled": True}).status_code
        == 404
    )


def test_deleting_a_project_removes_records_but_never_the_users_files(env):
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {}).json()["id"]
    env.wait(sid)
    assert (env.server.jobs.run_dir(sid) / "report.html").is_file()
    assert env.req("DELETE", f"/api/projects/{p['id']}").status_code == 200
    assert not env.server.jobs.run_dir(sid).exists() and env.get("/api/projects").json() == []
    assert (env.project_dir / "app.py").read_text() == "print('hi')\n"  # untouched


# --- scans ------------------------------------------------------------------------------------


def test_scan_lifecycle_produces_a_report_exports_and_history(env):
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True, "limit": 12}).json()[
        "id"
    ]
    row = env.wait(sid)
    assert (
        row["status"] == "done"
        and row["phase"] == "done"
        and row["findings"] == 67
        and row["score"] > 0
        and row["grade"] in "ABCDF"
    )
    assert (
        row["progress_done"] == row["progress_total"] == 12
        and "scanning" in row["log"]
        and "done: risk" in row["log"]
    )
    assert row["has_report"] and "report.sarif" in row["exports"] and row["model"]
    assert env.pipeline.scanned == [env.project_dir.resolve()]
    html = env.get(f"/api/scans/{sid}/report.html")
    assert (
        html.status_code == 200
        and f'name="gapscan-server" content="/api/projects/{p["id"]}"' in html.text
    )
    assert (
        'id="gapscan-data"' in html.text
        and "script-src 'unsafe-inline'" in html.headers["content-security-policy"]
    )
    sarif = env.get(f"/api/scans/{sid}/exports/report.sarif")
    assert (
        sarif.status_code == 200
        and json.loads(sarif.text)["version"] == "2.1.0"
        and "attachment" in sarif.headers["content-disposition"]
    )
    detail = env.get(f"/api/projects/{p['id']}").json()
    assert (
        detail["latest_done"]["id"] == sid
        and detail["scans"][0]["id"] == sid
        and detail["history"][0]["score"] == row["score"]
    )


def test_scan_without_model_review_is_marked_not_reviewed(env):
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {}).json()["id"]
    row = env.wait(sid)
    assert row["status"] == "done" and row["options"]["triage"] is False and row["model"] == ""
    report = json.loads((env.server.jobs.run_dir(sid) / "report.json").read_text())
    assert report["counts"]["llm_triaged"] == 0


def test_second_scan_is_compared_with_the_first(env):
    p = add_project(env)
    first = env.req("POST", f"/api/projects/{p['id']}/scans", {}).json()["id"]
    env.wait(first)
    env.pipeline.scan_result = env.pipeline.scan_result.model_copy(
        update={"findings": env.pipeline.scan_result.findings[5:]}
    )  # 5 findings fixed
    second = env.req("POST", f"/api/projects/{p['id']}/scans", {}).json()["id"]
    env.wait(second)
    base = json.loads((env.server.jobs.run_dir(second) / "report.json").read_text())["baseline"]
    assert base["fixed"] == 5 and base["new"] == 0 and base["previous_score"] is not None
    hist = env.get(f"/api/projects/{p['id']}").json()["history"]
    assert [h["id"] for h in hist] == [first, second] and hist[1]["score"] < hist[0]["score"]


def test_a_failing_scan_is_reported_and_the_worker_keeps_going(env):
    p = add_project(env)
    env.pipeline.fail = "scanner exploded"
    bad = env.req("POST", f"/api/projects/{p['id']}/scans", {}).json()["id"]
    row = env.wait(bad)
    assert (
        row["status"] == "failed"
        and "scanner exploded" in row["error"]
        and "FAILED" in row["log"]
        and not row["has_report"]
    )
    assert (
        row["stats"]["failed_at"] == "scanning"
    )  # the step it stopped in, for the failed-run banner
    env.pipeline.fail = None
    ok = env.req("POST", f"/api/projects/{p['id']}/scans", {}).json()["id"]
    assert env.wait(ok)["status"] == "done"


def test_cancelling_a_running_review_stops_it_and_frees_the_queue(env):
    p = add_project(env)
    env.pipeline.gate = threading.Event()
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True, "limit": 30}).json()[
        "id"
    ]
    queued = env.req("POST", f"/api/projects/{p['id']}/scans", {}).json()[
        "id"
    ]  # waits behind the first
    assert env.pipeline.started.wait(5)
    assert (
        env.req("POST", f"/api/scans/{queued}/cancel").status_code == 200
    )  # cancelled while waiting
    assert env.get(f"/api/scans/{queued}").json()["status"] == "cancelled"
    assert env.req("POST", f"/api/scans/{sid}/cancel").status_code == 200
    env.pipeline.gate.set()
    row = env.wait(sid)
    assert row["status"] == "cancelled" and not row["has_report"] and row["progress_done"] < 30
    assert env.req("POST", f"/api/scans/{sid}/cancel").status_code == 409  # nothing left to cancel
    env.pipeline.gate = None
    follow = env.req("POST", f"/api/projects/{p['id']}/scans", {}).json()["id"]
    assert env.wait(follow)["status"] == "done"


def test_scan_options_are_validated(env):
    p = add_project(env)
    for bad in ({"limit": -1}, {"limit": 100_001}, {"limit": "many"}, {"limit": True}):
        assert env.req("POST", f"/api/projects/{p['id']}/scans", bad).status_code == 400
    assert env.req("POST", "/api/projects/999/scans", {}).status_code == 404


def test_ids_in_paths_cannot_escape_the_runs_directory(env):
    add_project(env)
    for path in (
        "/api/scans/1/exports/../../../etc/passwd",
        "/api/scans/1/exports/..%2f..%2fx",
        "/api/scans/../1",
        "/api/scans/1/report.html/../../x",
    ):
        assert env.get(path).status_code in (404, 400), path
    assert env.get("/api/scans/1/exports/not-an-export").status_code == 404


def test_deleting_scans_and_restart_marks_running_jobs_interrupted(env, tmp_path):
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {}).json()["id"]
    env.wait(sid)
    assert (
        env.req("DELETE", f"/api/scans/{sid}").status_code == 200
        and env.get(f"/api/scans/{sid}").status_code == 404
    )
    db = Database(tmp_path / "other.db")
    pid = db.add_project("x", "/tmp/x")["id"]
    running = db.create_scan(pid, {})
    db.update_scan(running, status="running")
    assert (
        Database(tmp_path / "other.db").scan(running)["status"] == "interrupted"
    )  # a restart cannot leave it "running"


# --- decisions --------------------------------------------------------------------------------


def test_decisions_persist_and_rebuilding_applies_them_to_the_score(env):
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True, "limit": 40}).json()[
        "id"
    ]
    before = env.wait(sid)
    report = json.loads((env.server.jobs.run_dir(sid) / "report.json").read_text())
    victim = report["top_risks"][0]["finding_id"]
    assert (
        env.req(
            "PUT",
            f"/api/projects/{p['id']}/decisions/{victim}",
            {"decision": "accepted_risk", "note": "behind a VPN"},
        ).status_code
        == 200
    )
    assert env.get(f"/api/projects/{p['id']}/decisions").json()[0]["note"] == "behind a VPN"
    assert env.req("POST", f"/api/scans/{sid}/rebuild").status_code == 202
    after = env.wait(sid)
    assert (
        after["status"] == "done"
        and after["score"] < before["score"]
        and after["open_findings"] == before["open_findings"] - 1
    )
    rebuilt = json.loads((env.server.jobs.run_dir(sid) / "report.json").read_text())
    assert next(f for f in rebuilt["findings"] if f["id"] == victim)["decision"] == "accepted_risk"
    assert env.req("DELETE", f"/api/projects/{p['id']}/decisions/{victim}").status_code == 200
    assert env.get(f"/api/projects/{p['id']}/decisions").json() == []


def test_decision_validation(env):
    p = add_project(env)
    base = f"/api/projects/{p['id']}/decisions"
    assert env.req("PUT", f"{base}/abc", {"decision": "ignore_forever"}).status_code == 400
    assert env.req("PUT", f"{base}/bad id!", {"decision": "fixed"}).status_code in (400, 404)
    assert (
        env.req("PUT", "/api/projects/99/decisions/abc", {"decision": "fixed"}).status_code == 404
    )
    assert env.req("POST", "/api/scans/99/rebuild").status_code == 404


def test_a_running_scan_cannot_be_rebuilt_or_deleted(env):
    p = add_project(env)
    env.pipeline.gate = threading.Event()
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True}).json()["id"]
    assert env.pipeline.started.wait(5)
    assert (
        env.req("POST", f"/api/scans/{sid}/rebuild").status_code == 409
        and env.req("DELETE", f"/api/scans/{sid}").status_code == 409
    )
    assert env.req("DELETE", f"/api/projects/{p['id']}").status_code == 409
    env.pipeline.gate.set()
    env.wait(sid)


# --- settings, models, doctor, data -------------------------------------------------------------


def test_settings_are_validated_and_change_the_model_used_by_new_scans(env):
    s = env.get("/api/settings").json()
    assert s["profile"] == "best" and s["triage_limit"] == 40
    assert env.req("PUT", "/api/settings", {"profile": "nonsense"}).status_code == 400
    for bad in (
        {"triage_limit": -1},
        {"max_tool_calls": 11},
        {"asvs_level": 4},
        {"default_preset": "dry"},
    ):
        assert env.req("PUT", "/api/settings", bad).status_code == 400
    assert (
        env.req("PUT", "/api/settings", {"triage_limit": 0}).status_code == 200
    )  # 0 = every finding
    assert env.req("PUT", "/api/settings", {"use_tools": "yes"}).status_code == 400
    out = env.req(
        "PUT", "/api/settings", {"profile": "small", "triage_limit": 15, "use_tools": False}
    ).json()
    assert out == {
        "profile": "small",
        "triage_limit": 15,
        "use_tools": False,
        "max_tool_calls": 4,
        "asvs_level": 2,
        "default_preset": "full",
        "deep_dive": True,
        "deep_dive_limit": 5,
        "scanners": list(Config().scanners.enabled),
    }
    cfg = effective_config(env.server.config, env.server.db.settings())
    assert (
        cfg.llm.model == "granite4.2:8b"
        and cfg.llm.code_context_tokens == 4000
        and cfg.agent.use_tools is False
    )
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True}).json()["id"]
    assert env.wait(sid)["options"]["limit"] == 15  # the saved default


def test_models_endpoint_lists_profiles_and_installed_models(env, monkeypatch):
    monkeypatch.setattr(
        "gapscan.server.app.LLMClient.list_models",
        lambda self: [
            {"name": "qwen3-coder:30b", "size_gb": 18.0, "params": "30B", "quant": "Q4_K_M"}
        ],
    )
    m = env.get("/api/models").json()
    by = {p["name"]: p for p in m["profiles"]}
    assert (
        by["best"]["installed"] is True
        and by["best"]["selected"]
        and by["small"]["installed"] is False
    )
    assert m["installed"][0]["name"] == "qwen3-coder:30b" and m["error"] == ""
    assert (
        by["best"]["size_gb"] == 18.0 and by["small"]["size_gb"] is None
    )  # a size only for installed models

    from gapscan.llm.client import LLMError

    def down(self):
        raise LLMError("cannot reach the model server")

    monkeypatch.setattr("gapscan.server.app.LLMClient.list_models", down)
    assert "cannot reach" in env.get("/api/models").json()["error"]


def test_doctor_and_data_endpoints(env, tmp_path):
    doc = env.get("/api/doctor").json()
    checks = doc["items"]
    assert {c["name"] for c in checks} >= {"semgrep", "llm endpoint", "kb index"} and all(
        c["status"] in ("ok", "problem", "warn") for c in checks
    )
    assert set(doc["summary"]) == {"ok", "warn", "problem"} and sum(doc["summary"].values()) == len(
        checks
    )
    assert doc["checked_at"].startswith("20")
    assert all({"component", "group", "version", "detail", "fix"} <= set(c) for c in checks)
    d = env.get("/api/data").json()
    assert d["bundle"] is None and d["max_age_days"] == 30
    (tmp_path / "data").mkdir(exist_ok=True)
    (tmp_path / "data" / "bundle-state.json").write_text(
        json.dumps(
            {"bundle_created_at": "2026-10-02T00:00:00Z", "snapshots": {"osv_db": "2026-10-02"}}
        )
    )
    assert env.get("/api/data").json()["bundle"]["snapshots"] == {"osv_db": "2026-10-02"}


def test_bundle_verification_runs_as_a_background_task(env, tmp_path):
    from gapscan.offline.bundle import BundleOptions, build_bundle

    from .test_bundle import make_data

    bundle = tmp_path / "b.tar.gz"
    build_bundle(make_data(tmp_path / "src"), bundle, BundleOptions())
    tid = env.req("POST", "/api/data/bundle", {"path": str(bundle), "verify_only": True}).json()[
        "id"
    ]
    import time

    for _ in range(100):
        t = env.get(f"/api/tasks/{tid}").json()
        if t["status"] != "running":
            break
        time.sleep(0.05)
    assert (
        t["status"] == "done"
        and any("bundle intact" in line for line in t["log"])
        and "osv_db" in t["result"]["snapshots"]
    )
    assert (
        env.req("POST", "/api/data/bundle", {"path": str(tmp_path / "missing.tar.gz")}).status_code
        == 400
    )
    assert (
        env.req("POST", "/api/data/bundle", {"path": "/etc/passwd"}).status_code == 400
    )  # only bundle files
    tampered = tmp_path / "t.tar.gz"
    tampered.write_bytes(b"not a bundle")
    tid2 = env.req("POST", "/api/data/bundle", {"path": str(tampered), "verify_only": True}).json()[
        "id"
    ]
    for _ in range(100):
        t2 = env.get(f"/api/tasks/{tid2}").json()
        if t2["status"] != "running":
            break
        time.sleep(0.05)
    assert t2["status"] == "failed" and "refused" in t2["log"][-1]
    assert env.get("/api/tasks/ffffffff").status_code == 404


# --- team memories -------------------------------------------------------------------------


def run_scan_to_done(env, project_id, triage=True):
    sid = env.req(
        "POST", f"/api/projects/{project_id}/scans", {"triage": triage, "limit": 5}
    ).json()["id"]
    return sid, env.wait(sid)


def test_memories_can_be_added_listed_toggled_and_deleted(env):
    p = add_project(env)
    base = f"/api/projects/{p['id']}/memories"
    assert env.get(base).json() == []
    made = env.req(
        "POST",
        base,
        {"text": "the logs folder is never deployed", "path": "src/logs", "kind": "context"},
    )
    assert made.status_code == 201
    memory = made.json()
    assert env.get(base).json()[0]["id"] == memory["id"] and memory["enabled"] is True
    assert env.req("PUT", f"{base}/{memory['id']}", {"enabled": False}).status_code == 200
    assert env.get(base).json()[0]["enabled"] is False
    assert env.req("PUT", f"{base}/{memory['id']}", {"enabled": "yes"}).status_code == 400
    assert env.req("DELETE", f"{base}/{memory['id']}").status_code == 200
    assert (
        env.get(base).json() == []
        and env.req("DELETE", f"{base}/{memory['id']}").status_code == 404
    )


def test_memory_validation(env):
    p = add_project(env)
    base = f"/api/projects/{p['id']}/memories"
    assert env.req("POST", base, {"text": "short"}).status_code == 400
    assert env.req("POST", base, {"text": "x" * 401}).status_code == 400
    assert (
        env.req("POST", base, {"text": "a long enough note", "kind": "nonsense"}).status_code == 400
    )
    assert (
        env.req("POST", "/api/projects/999/memories", {"text": "a long enough note"}).status_code
        == 404
    )
    assert env.req("PUT", f"{base}/0123456789", {"enabled": True}).status_code == 404
    assert env.get(f"/api/projects/{p['id']}/memories/../x").status_code in (401, 404, 400)
    anon = httpx.Client(base_url=f"http://127.0.0.1:{env.server.port}")
    assert anon.get(base).status_code == 401  # memories need the session like everything else


def test_a_decision_with_a_note_becomes_a_memory_and_one_without_does_not(env):
    p = add_project(env)
    sid, row = run_scan_to_done(env, p["id"], triage=False)
    assert row["status"] == "done"
    fid = env.pipeline.scan_result.findings[0].id
    no_note = env.req(
        "PUT",
        f"/api/projects/{p['id']}/decisions/{fid}",
        {"decision": "false_positive", "note": ""},
    ).json()
    assert no_note["memory"] is None
    with_note = env.req("PUT", f"/api/projects/{p['id']}/decisions/{fid}",
                        {"decision": "false_positive", "note": "the value is generated by the server, not by users"}).json()  # fmt: skip
    assert with_note["memory"]
    mems = env.get(f"/api/projects/{p['id']}/memories").json()
    assert (
        len(mems) == 1
        and mems[0]["kind"] == "false_positive"
        and mems[0]["source"].startswith("decision:")
    )
    unknown = env.req("PUT", f"/api/projects/{p['id']}/decisions/{'0' * 16}",
                      {"decision": "false_positive", "note": "a long enough note for an unknown finding"}).json()  # fmt: skip
    assert unknown["memory"] is None


def test_scans_with_model_review_receive_the_projects_memories(env):
    p = add_project(env)
    env.req(
        "POST", f"/api/projects/{p['id']}/memories", {"text": "the logs folder is never deployed"}
    )
    sid, row = run_scan_to_done(env, p["id"], triage=True)
    assert row["status"] == "done"
    seen = env.pipeline.memories_seen
    assert seen and seen[0].text == "the logs folder is never deployed"
    assert "team memories available" in env.get(f"/api/scans/{sid}").json()["log"]


# --- run options, queue, scanners, report data ----------------------------------------------


def test_run_options_are_validated_and_stored(env):
    p = add_project(env)
    url = f"/api/projects/{p['id']}/scans"
    bad = [
        {"scanners": []}, {"scanners": ["nope"]}, {"scanners": "semgrep"}, {"profile": "gigantic"},
        {"max_tool_calls": 99}, {"asvs_level": 4}, {"baseline": 999},
    ]  # fmt: skip
    for body in bad:
        assert env.req("POST", url, body).status_code == 400, body
    good = env.req("POST", url, {"triage": False, "scanners": ["semgrep", "gitleaks", "semgrep"],
                                 "profile": "small", "max_tool_calls": 2, "asvs_level": 3}).json()  # fmt: skip
    row = env.wait(good["id"])
    assert row["status"] == "done"
    assert row["options"]["scanners"] == ["gitleaks", "semgrep"]
    assert (
        row["options"]["profile"],
        row["options"]["max_tool_calls"],
        row["options"]["asvs_level"],
    ) == ("small", 2, 3)
    assert (
        row["stats"]["merged"] == len(env.pipeline.scan_result.findings)
        and row["stats"]["scanners"]
    )


def test_a_baseline_must_be_a_finished_run_of_the_same_project(env, tmp_path):
    first = add_project(env)
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    second = add_project(env, "other", other_dir)
    sid, _ = run_scan_to_done(env, first["id"], triage=False)
    assert (
        env.req("POST", f"/api/projects/{second['id']}/scans", {"baseline": sid}).status_code == 400
    )
    ok = env.req("POST", f"/api/projects/{first['id']}/scans", {"baseline": sid}).json()
    assert env.wait(ok["id"])["options"]["baseline"] == sid


def test_effective_config_applies_the_options_of_one_run():
    cfg = effective_config(Config(), {}, {"scanners": ["gitleaks", "semgrep"], "max_tool_calls": 7,
                                          "asvs_level": 1, "profile": "tiny"})  # fmt: skip
    # in the fixed scanner order; the built-in data-flow and malware checks always run with them
    assert cfg.scanners.enabled == ["semgrep", "gitleaks", "taint", "malware"]
    saved = {"scanners": ["semgrep", "osv", "trivy", "gitleaks", "checkov", "bandit"]}  # older UI
    assert {"taint", "malware"} <= set(effective_config(Config(), saved).scanners.enabled)
    assert (cfg.agent.max_tool_calls, cfg.general.asvs_level) == (7, 1)
    assert cfg.llm.profile == "tiny"
    assert effective_config(Config(), {}).scanners.enabled == Config().scanners.enabled


def test_the_queue_lists_running_and_waiting_runs_in_order(env):
    import threading

    p = add_project(env)
    gate = threading.Event()
    env.pipeline.gate = gate
    first = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True, "limit": 3}).json()[
        "id"
    ]
    assert env.pipeline.started.wait(10)
    second = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": False}).json()["id"]
    third = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": False}).json()["id"]
    q = env.get("/api/queue").json()
    assert [r["id"] for r in q] == [first, second, third]
    assert [r["status"] for r in q] == ["running", "queued", "queued"]
    assert [r["position"] for r in q] == [0, 1, 2] and q[0]["project"] == "myapp"
    gate.set()
    env.wait(third)
    assert env.get("/api/queue").json() == []


def test_scanner_availability_and_the_scan_report_data(env):
    names = [s["name"] for s in env.get("/api/scanners").json()]
    assert names == ["semgrep", "osv", "trivy", "gitleaks", "checkov", "bandit"]
    one = env.get("/api/scanners").json()[0]
    assert set(one) == {"name", "description", "available", "version", "default"}
    p = add_project(env)
    sid, _ = run_scan_to_done(env, p["id"], triage=True)
    data = env.get(f"/api/scans/{sid}/report.json")
    assert data.status_code == 200 and data.headers["content-type"].startswith("application/json")
    body = data.json()
    assert body["meta"]["report_schema_version"] == 1 and body["findings"]
    assert env.get("/api/scans/999/report.json").status_code == 404


def test_a_finding_has_a_history_across_runs(env):
    p = add_project(env)
    first, _ = run_scan_to_done(env, p["id"], triage=True)
    second, _ = run_scan_to_done(env, p["id"], triage=True)
    fid = env.pipeline.scan_result.findings[0].id
    hist = env.get(f"/api/projects/{p['id']}/findings/{fid}/history").json()
    assert [h["run"] for h in hist] == [second, first]  # newest first
    assert all(h["verdict"] and "severity" in h and h["open"] is not None for h in hist)
    assert env.get(f"/api/projects/{p['id']}/findings/{'0' * 16}/history").json() == []
    assert env.get(f"/api/projects/999/findings/{fid}/history").status_code == 404
    assert env.get(f"/api/projects/{p['id']}/findings/not*valid/history").status_code in (400, 404)


def test_compare_two_runs_lists_new_fixed_and_the_score_series(env):
    p = add_project(env)
    url = f"/api/projects/{p['id']}/compare"
    assert env.get(url).status_code == 409  # needs two finished runs
    first, _ = run_scan_to_done(env, p["id"], triage=False)
    # the second run loses one finding and gains another
    kept = env.pipeline.scan_result.findings
    env.pipeline.scan_result = env.pipeline.scan_result.model_copy(deep=True)
    dropped, added = (
        kept[0],
        kept[0].model_copy(update={"id": "feedfacefeedface", "title": "A brand new finding"}),
    )
    env.pipeline.scan_result.findings = [f for f in kept if f.id != dropped.id] + [added]
    second, _ = run_scan_to_done(env, p["id"], triage=False)
    body = env.get(url).json()
    assert (body["a"]["id"], body["b"]["id"]) == (first, second)
    assert [r["title"] for r in body["new"]] == ["A brand new finding"]
    assert [r["id"] for r in body["fixed"]] == [dropped.id]
    assert body["unchanged"] == len(kept) - 1 and [x["id"] for x in body["series"]] == [
        first,
        second,
    ]
    assert (
        env.get(f"{url}?a={second}&b={first}").json()["new"]
        and env.get(f"{url}?a={first}&b={first}").status_code == 400
    )
    assert env.get(f"{url}?a=9999&b={first}").status_code == 400
    assert env.get("/api/projects/999/compare").status_code == 404


def test_default_scanners_are_a_saved_setting_used_when_a_run_does_not_choose(env):
    assert env.get("/api/settings").json()["scanners"] == list(Config().scanners.enabled)
    assert env.req("PUT", "/api/settings", {"scanners": []}).status_code == 400
    assert env.req("PUT", "/api/settings", {"scanners": ["nope"]}).status_code == 400
    saved = env.req("PUT", "/api/settings", {"scanners": ["gitleaks", "semgrep", "semgrep"]}).json()
    assert saved["scanners"] == ["gitleaks", "semgrep"]
    defaults = {s["name"] for s in env.get("/api/scanners").json() if s["default"]}
    assert defaults == {"gitleaks", "semgrep"}
    builtin = ["taint", "malware"]  # always run
    assert effective_config(Config(), {"scanners": ["gitleaks", "semgrep"]}).scanners.enabled == [
        "semgrep",
        "gitleaks",
        *builtin,
    ]
    # a run's own choice wins over the saved default
    assert effective_config(
        Config(), {"scanners": ["gitleaks"]}, {"scanners": ["bandit"]}
    ).scanners.enabled == ["bandit", *builtin]


# --- dry run, archive, benchmark ------------------------------------------------------------


def test_a_dry_run_lists_the_plan_and_changes_nothing(env):
    (env.project_dir / "app.py").write_text("print('hi')\n")
    (env.project_dir / "main.kt").write_text("fun main() {}\n")
    (env.project_dir / ".gapscanignore").write_text("vendor/\nrule:some.rule\n")
    p = add_project(env)
    before = list(env.project_dir.iterdir())
    sid = env.req(
        "POST", f"/api/projects/{p['id']}/scans", {"dry_run": True, "triage": True, "limit": 9}
    ).json()["id"]
    row = env.wait(sid)
    assert row["status"] == "done" and row["kind"] == "dryrun"
    plan = row["stats"]["plan"]
    assert (
        plan["files"] >= 3
        and plan["by_language"].get("python") == 1
        and plan["by_language"].get("kotlin") == 1
    )
    assert plan["ignore"] == {"file": True, "paths": 1, "rules": 1}
    assert {s["name"] for s in plan["scanners"]} == set(Config().scanners.enabled)
    assert plan["ai"]["enabled"] and plan["ai"]["limit"] == 9 and "Nothing" in plan["changes"]
    assert "dry run for" in row["log"] and "AI review: would review up to 9" in row["log"]
    assert env.pipeline.scanned == []  # no scanner was started
    assert sorted(env.project_dir.iterdir()) == sorted(
        before
    )  # and nothing was written to the project
    assert not env.get(f"/api/scans/{sid}").json()["has_report"]
    # a dry run is not a scored run: it never becomes the latest result, the baseline or the trend
    summary = env.get(f"/api/projects/{p['id']}").json()
    assert summary["latest_done"] is None and summary["history"] == []
    real, _ = run_scan_to_done(env, p["id"], triage=False)
    assert env.get(f"/api/projects/{p['id']}").json()["latest_done"]["id"] == real


def test_a_dry_run_estimates_from_the_last_similar_run(env):
    p = add_project(env)
    run_scan_to_done(env, p["id"], triage=False)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"dry_run": True}).json()["id"]
    assert env.wait(sid)["stats"]["plan"]["estimate_seconds"] is not None


def test_archiving_hides_a_project_blocks_runs_and_can_be_undone(env):
    p = add_project(env)
    pid = p["id"]
    assert env.get("/api/projects").json()[0]["archived"] is False
    assert env.req("PUT", f"/api/projects/{pid}", {"archived": "yes"}).status_code == 400
    assert env.req("PUT", f"/api/projects/{pid}", {"archived": True}).json()["archived"] is True
    assert env.get("/api/projects").json()[0]["archived"] is True  # still listed, flagged
    assert env.req("POST", f"/api/projects/{pid}/scans", {}).status_code == 409
    assert env.get(f"/api/projects/{pid}").json()["name"] == "myapp"  # history stays reachable
    assert env.req("PUT", f"/api/projects/{pid}", {"archived": False}).json()["archived"] is False
    assert env.req("POST", f"/api/projects/{pid}/scans", {"triage": False}).status_code == 202
    assert env.req("PUT", "/api/projects/999", {"archived": True}).status_code == 404


def test_a_project_with_a_running_scan_cannot_be_archived(env):
    p = add_project(env)
    env.pipeline.gate = threading.Event()
    env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True, "limit": 30})
    assert env.pipeline.started.wait(10)
    assert env.req("PUT", f"/api/projects/{p['id']}", {"archived": True}).status_code == 409
    env.pipeline.gate.set()
    env.server.jobs.wait_idle(20)


def test_a_model_benchmark_waits_in_the_queue_and_reports_its_result(env):
    model = Config().llm.all_profiles["best"].model
    assert env.req("POST", "/api/benchmarks", {"model": "not-a-profile-model"}).status_code == 400
    p = add_project(env)
    env.pipeline.gate = threading.Event()
    scan = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True, "limit": 3}).json()[
        "id"
    ]
    assert env.pipeline.started.wait(10)
    env.req("POST", "/api/benchmarks", {"model": model})
    q = env.get("/api/queue").json()
    assert [(r["kind"], r["status"]) for r in q] == [("scan", "running"), ("benchmark", "queued")]
    assert (
        q[1]["position"] == 1 and q[1]["options"]["model"] == model
    )  # it never competes with a scan
    env.pipeline.gate.set()
    env.wait(scan)
    import time

    for _ in range(200):
        latest = env.get("/api/benchmarks").json()
        if latest.get(model, {}).get("status") == "done":
            break
        time.sleep(0.05)
    row = latest[model]
    assert row["status"] == "done" and row["progress_total"] == 4
    assert row["summary"]["cases"] == 4 and abs(row["summary"]["accuracy"] - 0.75) < 1e-9
    assert env.get("/api/queue").json() == []


def test_a_waiting_benchmark_can_be_cancelled_and_a_missing_one_is_rejected(env):
    model = Config().llm.all_profiles["best"].model
    p = add_project(env)
    env.pipeline.gate = threading.Event()
    env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True, "limit": 3})
    assert env.pipeline.started.wait(10)
    bid = env.req("POST", "/api/benchmarks", {"model": model}).json()["id"]
    assert env.req("POST", f"/api/benchmarks/{bid}/cancel").status_code == 200
    assert env.get("/api/benchmarks").json()[model]["status"] == "cancelled"
    assert env.req("POST", f"/api/benchmarks/{bid}/cancel").status_code == 409
    env.pipeline.gate.set()
    env.server.jobs.wait_idle(20)
    env.pipeline.cases = []
    assert env.req("POST", "/api/benchmarks", {"model": model}).status_code == 409


# --- build a bundle, started by ------------------------------------------------------------


def _wait_task(env, tid):
    import time

    for _ in range(200):
        t = env.get(f"/api/tasks/{tid}").json()
        if t["status"] != "running":
            return t
        time.sleep(0.05)
    raise AssertionError("task never finished")


def test_build_a_bundle_packages_local_data_and_verifies(env, tmp_path):
    from gapscan.offline.update import verify_bundle

    from .test_bundle import make_data

    make_data(tmp_path)  # fills tmp_path/data, the data folder of this server
    out = tmp_path / "out"
    out.mkdir()
    tid = env.req("POST", "/api/data/build", {"path": str(out)}).json()["id"]
    t = _wait_task(env, tid)
    assert t["status"] == "done", t["log"]
    built = Path(t["result"]["path"])
    assert built.parent == out and built.name.endswith(".tar.gz")
    assert verify_bundle(built).snapshots
    # an existing file is never overwritten; a bad name or folder is refused
    assert env.req("POST", "/api/data/build", {"path": str(built)}).status_code == 409
    assert env.req("POST", "/api/data/build", {"path": str(out / "x.zip")}).status_code == 400
    assert (
        env.req("POST", "/api/data/build", {"path": str(out / "no" / "x.tar.gz")}).status_code
        == 400
    )


def test_runs_record_who_started_them(env):
    import getpass

    pid = add_project(env)["id"]
    env.req("POST", f"/api/projects/{pid}/scans", {}).json()["id"]
    detail = env.get(f"/api/projects/{pid}").json()
    assert detail["scans"][0]["started_by"] == getpass.getuser()


def test_saved_tool_calls_and_asvs_level_apply_unless_the_run_overrides(env):
    out = env.req("PUT", "/api/settings", {"max_tool_calls": 2, "asvs_level": 3}).json()
    assert out["max_tool_calls"] == 2 and out["asvs_level"] == 3
    base, saved = env.server.config, env.server.db.settings()
    cfg = effective_config(base, saved)
    assert cfg.agent.max_tool_calls == 2 and cfg.general.asvs_level == 3
    cfg = effective_config(base, saved, {"max_tool_calls": 6, "asvs_level": 1})
    assert cfg.agent.max_tool_calls == 6 and cfg.general.asvs_level == 1


# --- deep dive ----------------------------------------------------------


def test_a_reviewed_run_deep_dives_the_top_confirmed_issues_and_reports_them(env):
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans",
                  {"triage": True, "limit": 40, "deep_dive_limit": 2}).json()["id"]  # fmt: skip
    row = env.wait(sid)
    assert row["status"] == "done", row
    assert row["options"]["deep_dive"] is True and row["options"]["deep_dive_limit"] == 2
    assert row["stats"]["deep_dive"]["investigations"] == 2
    run_dir = env.server.jobs.run_dir(sid)
    saved = json.loads((run_dir / "triage.json").read_text())["investigations"]
    assert len(saved) == 2
    report = json.loads((run_dir / "report.json").read_text())
    shown = [fid for fid, d in report["details"].items() if d.get("deep_dive")]
    assert set(shown) == {fid for inv in saved for fid in inv["covers"]}
    assert "deep dive into the top 2 confirmed issues" in row["log"]
    assert row["progress_done"] == row["progress_total"] == 40  # still the AI review counts


def test_the_deep_dive_can_be_turned_off_per_run_and_by_default(env):
    p = add_project(env)
    off = env.req("POST", f"/api/projects/{p['id']}/scans",
                  {"triage": True, "limit": 40, "deep_dive": False}).json()["id"]  # fmt: skip
    assert env.wait(off)["status"] == "done" and env.pipeline.deep_calls == 0
    assert (
        env.req("PUT", "/api/settings", {"deep_dive": False, "deep_dive_limit": 3}).json()[
            "deep_dive"
        ]
        is False
    )
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True}).json()["id"]
    row = env.wait(sid)
    assert row["options"]["deep_dive"] is False and env.pipeline.deep_calls == 0
    scanners_only = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": False}).json()
    assert "deep_dive" not in env.wait(scanners_only["id"])["options"]
    assert env.req("PUT", "/api/settings", {"deep_dive": "yes"}).status_code == 400
    assert env.req("PUT", "/api/settings", {"deep_dive_limit": 500}).status_code == 400


def test_a_failing_deep_dive_does_not_fail_the_run(env):
    p = add_project(env)
    env.pipeline.deep_fail = "model went away"
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": True, "limit": 40}).json()[
        "id"
    ]
    row = env.wait(sid)
    assert row["status"] == "done", row
    assert "deep dive stopped: model went away" in row["log"]


def test_rebuilding_a_report_keeps_its_investigations(env):
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans",
                  {"triage": True, "limit": 40, "deep_dive_limit": 1}).json()["id"]  # fmt: skip
    assert env.wait(sid)["status"] == "done"
    jobs = env.server.jobs
    from gapscan.stages import RunFolder, Stage

    folder = RunFolder(jobs.run_dir(sid))
    verdicts, summary, investigations = jobs._load_triage(folder.path, folder.load_scan())
    assert verdicts and len(investigations) == 1
    stages = folder.manifest().stages  # each saved output is linked to the one it came from
    assert stages[Stage.TRIAGE].inputs["normalize"] == stages[Stage.NORMALIZE].sha256


def test_an_allowlisted_packs_scanner_is_offered_and_can_be_chosen(tmp_path, monkeypatch):
    """The picker comes from the server's packs: a second pack's scanner is listed with its own
    description (it used to raise KeyError) and a run may choose it."""
    from types import SimpleNamespace

    from gapscan import registry as reg_mod
    from gapscan.registry import BUILTIN_PACKS
    from gapscan.security_pack import register as security
    from tests.test_registry import DummyScanner

    def extra(r):
        r.add_scanner("dummy", lambda c: DummyScanner(), description="A team's own scanner")

    eps = [SimpleNamespace(name="security", value=BUILTIN_PACKS["security"], load=lambda: security),
           SimpleNamespace(name="extra", value="team.pack:register", load=lambda: extra)]  # fmt: skip
    monkeypatch.setattr(reg_mod, "entry_points", lambda group: eps)
    reg_mod.registry.cache_clear()
    cfg = Config(data={"dir": str(tmp_path / "data")}, scanners={"packs": ["security", "extra"]})
    server = build_server(cfg, port=0, pipeline=FakePipeline())
    server._manager_html = "<!doctype html><title>manager</title>"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = Client(server, server.jobs.pipeline)
        listed = {s["name"]: s for s in client.get("/api/scanners").json()}
        assert listed["dummy"]["description"] == "A team's own scanner"
        assert listed["dummy"]["available"] is True
        project = tmp_path / "p"
        project.mkdir()
        pid = client.req("POST", "/api/projects", {"name": "p", "path": str(project)}).json()["id"]
        r = client.req("POST", f"/api/projects/{pid}/scans", {"scanners": ["dummy"]})
        assert r.status_code in (200, 201, 202), r.text
    finally:
        server.shutdown()
        server.jobs.stop()
        server.server_close()
        reg_mod.registry.cache_clear()


# --- git branch / commit capture and diff scope ----------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=a@b.c", "-c", "user.name=t", *args],
        check=True, capture_output=True,
    )  # fmt: skip


def _make_repo(path: Path) -> None:
    _git(path, "init", "-q", "-b", "main")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "base")


def test_refs_endpoint_reports_branch_commit_and_refs(env):
    _make_repo(env.project_dir)
    _git(env.project_dir, "branch", "feature/y")
    p = add_project(env)
    r = env.get(f"/api/projects/{p['id']}/refs").json()
    assert r["git"] is True and r["branch"] == "main" and len(r["commit"]) >= 7
    assert "main" in r["refs"] and "feature/y" in r["refs"]


def test_refs_endpoint_on_a_non_repo_is_empty(env):
    p = add_project(env)  # the project folder is not a git repo
    assert env.get(f"/api/projects/{p['id']}/refs").json() == {
        "git": False,
        "branch": "",
        "commit": "",
        "dirty": False,
        "refs": [],
    }


def test_scan_records_the_branch_and_commit(env):
    _make_repo(env.project_dir)
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": False}).json()["id"]
    row = env.wait(sid)
    assert row["status"] == "done"
    assert row["branch"] == "main" and len(row["commit_sha"]) >= 7


def test_scan_on_a_non_repo_leaves_branch_blank(env):
    p = add_project(env)
    sid = env.req("POST", f"/api/projects/{p['id']}/scans", {"triage": False}).json()["id"]
    row = env.wait(sid)
    assert row["status"] == "done" and row["branch"] == "" and row["commit_sha"] == ""


def test_scan_with_an_unknown_base_ref_fails_clearly(env):
    _make_repo(env.project_dir)
    p = add_project(env)
    sid = env.req(
        "POST", f"/api/projects/{p['id']}/scans", {"triage": False, "base": "no-such-ref"}
    ).json()["id"]
    row = env.wait(sid)
    assert row["status"] == "failed" and "no-such-ref" in row["error"]


def test_scan_with_a_base_ref_keeps_only_introduced_findings(env):
    _make_repo(env.project_dir)
    p = add_project(env)
    sid = env.req(
        "POST", f"/api/projects/{p['id']}/scans", {"triage": False, "base": "main"}
    ).json()["id"]
    row = env.wait(sid)
    # The fixture findings are not in this repo's diff, so the diff scope drops them all.
    assert row["status"] == "done" and "diff scope" in row["log"] and row["open_findings"] == 0


def test_a_malformed_base_ref_is_refused(env):
    _make_repo(env.project_dir)
    p = add_project(env)
    r = env.req(
        "POST", f"/api/projects/{p['id']}/scans", {"triage": False, "base": "--upload-pack"}
    )
    assert r.status_code == 400


# --- in-browser folder picker ----------------------------------------------------------------


def test_fs_endpoint_lists_subfolders_and_marks_git(env, tmp_path):
    root = tmp_path / "browse"
    (root / "proj" / ".git").mkdir(parents=True)
    (root / "plain").mkdir()
    (root / "file.txt").write_text("x")
    r = env.get(f"/api/fs?path={root}").json()
    assert r["path"] == str(root.resolve()) and r["parent"] == str(root.parent)
    names = {e["name"]: e["git"] for e in r["entries"]}
    assert names == {"proj": True, "plain": False}  # the file is not listed


def test_fs_endpoint_defaults_to_home(env):
    r = env.get("/api/fs").json()
    assert r["path"] == r["home"] and "entries" in r


def test_fs_endpoint_rejects_a_non_folder(env, tmp_path):
    (tmp_path / "f.txt").write_text("x")
    assert env.get(f"/api/fs?path={tmp_path / 'f.txt'}").status_code == 400


def test_fs_endpoint_needs_the_session_token(env):
    anon = httpx.Client(base_url=f"http://127.0.0.1:{env.server.port}")
    assert anon.get("/api/fs").status_code == 401


def test_git_head_endpoint_reports_branch_for_a_folder(env):
    _make_repo(env.project_dir)
    r = env.get(f"/api/git-head?path={env.project_dir}").json()
    assert r["git"] is True and r["branch"] == "main" and len(r["commit"]) >= 7


def test_git_head_endpoint_is_empty_for_a_non_repo_or_missing_path(env, tmp_path):
    assert env.get(f"/api/git-head?path={tmp_path}").json()["git"] is False
    assert env.get("/api/git-head").json() == {
        "git": False,
        "branch": "",
        "commit": "",
        "dirty": False,
    }
    # a half-typed path never errors
    assert env.get(f"/api/git-head?path={tmp_path / 'nope'}").json()["git"] is False


def test_fs_listing_carries_the_folders_own_head(env):
    _make_repo(env.project_dir)
    r = env.get(f"/api/fs?path={env.project_dir}").json()
    assert r["head"]["git"] is True and r["head"]["branch"] == "main"


def test_without_the_compliance_catalog_the_endpoint_is_absent(env, monkeypatch):
    """GapScan Open ships without gapscan.compliance: the manager says so and hides the page."""
    import importlib.util as iu

    real = iu.find_spec
    monkeypatch.setattr(
        iu, "find_spec", lambda name, *a: None if name == "gapscan.compliance" else real(name, *a)
    )
    r = env.req("GET", "/api/compliance")
    assert r.status_code == 200 and r.json()["available"] is False


def test_a_planned_feature_can_be_enabled_and_disabled_per_project(env, monkeypatch):
    p = add_project(env)
    group = "standards"
    # GapScan Open has no planned features, so the id is refused until a catalog provides it.
    url = f"/api/projects/{p['id']}/services/{group}"
    monkeypatch.setattr("gapscan.server.app.compliance_catalog", lambda: None)
    assert env.req("PUT", url, {"enabled": True}).status_code == 404
    monkeypatch.setattr(
        "gapscan.server.app.compliance_catalog", lambda: {"groups": [{"id": group}]}
    )
    # It is not set up until enabled; enabling creates the service for this project.
    before = {s["domain"] for s in env.get(f"/api/projects/{p['id']}/services").json()}
    assert group not in before
    r = env.req("PUT", f"/api/projects/{p['id']}/services/{group}", {"enabled": True})
    assert r.status_code == 200 and r.json()["enabled"] is True
    after = {
        s["domain"] for s in env.get(f"/api/projects/{p['id']}/services").json() if s["enabled"]
    }
    assert group in after
    # Turning it back off keeps the row but marks it disabled.
    off = env.req("PUT", f"/api/projects/{p['id']}/services/{group}", {"enabled": False})
    assert off.status_code == 200 and off.json()["enabled"] is False
    # An unknown feature id is still refused.
    assert (
        env.req(
            "PUT", f"/api/projects/{p['id']}/services/not-a-feature", {"enabled": True}
        ).status_code
        == 404
    )
