"""The packaged app (`make freeze`) must run on its own: serve the Control Center, keep its data in its
own folder, and complete a scan whose report shows the bundled pages, rules and OWASP tables.
Skipped when `dist/gapscan/` has not been built."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import httpx
import pytest

BUILT = Path(__file__).resolve().parents[1] / "dist" / "gapscan" / "gapscan"
pytestmark = pytest.mark.skipif(not BUILT.is_file(), reason="not built (make freeze)")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def app(tmp_path):
    home, port = tmp_path / "home", free_port()
    env = {**os.environ, "GAPSCAN_HOME": str(home)}
    proc = subprocess.Popen(  # noqa: S603 - the program under test
        [str(BUILT), "serve", "--no-open", "--port", str(port)],
        env=env, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )  # fmt: skip
    url = ""
    deadline = time.monotonic() + 60
    assert proc.stdout is not None
    while time.monotonic() < deadline and not url:
        line = proc.stdout.readline()
        if "token=" in line:
            url = next(w for w in line.split() if "token=" in w)
        elif proc.poll() is not None:
            break
    assert url, "the app did not print its address"
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=60)
    client.get(url.split(str(port), 1)[1])  # the token handshake sets the cookie
    yield client, home, f"http://127.0.0.1:{port}"
    proc.terminate()
    proc.wait(timeout=15)


def test_the_packaged_app_serves_scans_and_keeps_data_in_its_folder(app, tmp_path):
    client, home, origin = app
    page = client.get("/")
    assert page.status_code == 200 and "GapScan" in page.text
    setup = client.get("/api/setup").json()  # the bundled manifest and hardware check
    assert setup["runtime"]["pack"] is not None and setup["tiers"]
    project = tmp_path / "vuln"
    project.mkdir()
    (project / "app.py").write_text(
        "import sqlite3, hashlib\n"
        "def find(db, name):\n"
        '    return db.execute("SELECT * FROM users WHERE name=\'" + name + "\'")\n'
        "def h(p):\n    return hashlib.md5(p.encode()).hexdigest()\n"
    )
    h = {"Origin": origin, "Content-Type": "application/json"}
    pid = client.post(
        "/api/projects", json={"name": "vuln", "path": str(project)}, headers=h
    ).json()["id"]
    sid = client.post(f"/api/projects/{pid}/scans", json={"triage": False}, headers=h).json()["id"]
    for _ in range(300):
        scan = client.get(f"/api/scans/{sid}").json()
        if scan["status"] not in ("queued", "running"):
            break
        time.sleep(1)
    assert scan["status"] == "done", scan.get("error") or scan.get("log")
    report = client.get(f"/api/scans/{sid}/report.json").json()
    tools = {t["name"]: t["status"] for t in scan["stats"]["scanners"]}
    # gitleaks and osv-scanner ship inside the app; the Python scanners (bandit, semgrep, checkov)
    # come from the setup wizard or the machine, so they are only required when present here
    # (the release workflow puts semgrep and bandit on PATH before running this test).
    assert tools["gitleaks"] == "ok" and tools["osv"] != "failed"
    if shutil.which("bandit") or shutil.which("semgrep"):
        assert report["findings"], "the scanners found nothing in a file with SQL injection and md5"
        assert all(f["owasp"] for f in report["findings"]), "OWASP mapping tables were not bundled"
        page = client.get(f"/api/scans/{sid}/report.html")  # embeds each finding's quoted code
        assert page.status_code == 200 and "hashlib.md5" in page.text
    if shutil.which("bandit"):
        assert tools["bandit"] == "ok"
    assert client.get(f"/api/scans/{sid}/exports/report.sarif").status_code == 200
    assert (home / "data" / "gapscan.db").is_file()  # all state is under the app folder


def test_the_bundled_scanners_are_found_without_anything_installed(tmp_path):
    """On a machine with no scanners at all, Gitleaks and OSV-Scanner still work because they ship inside."""
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "GAPSCAN_HOME": str(tmp_path / "home")}
    out = subprocess.run(
        [str(BUILT), "doctor"], env=env, cwd=tmp_path, capture_output=True, text=True, timeout=120
    ).stdout
    rows = {
        line.split("│")[1].strip(): line.split("│")[2].strip()
        for line in out.splitlines()
        if line.count("│") >= 3
    }
    assert rows["gitleaks"] == "OK"
    # osv-scanner ships inside too, but it is only ready once its offline database is there
    assert (BUILT.parent / "_internal" / "tools" / "osv-scanner").is_file()
    assert (
        rows["semgrep"] == "MISSING" and rows["trivy"] == "MISSING"
    )  # these come from the setup wizard


def test_the_welcome_plan_and_sample_project_work_inside_the_packaged_app(app, tmp_path):
    client, home, origin = app
    plan = client.get("/api/setup").json()
    assert [s["step"] for s in plan["plan"]][0] == "engine" and plan["welcome"] is None
    h = {"Origin": origin, "Content-Type": "application/json"}
    sample = client.post("/api/sample", content="{}", headers=h).json()
    folder = Path(sample["path"])
    assert folder == (home / "sample-project").resolve()
    assert {"app.py", "requirements.txt", "Dockerfile", "app.js"} <= {
        p.name for p in folder.rglob("*") if p.is_file()
    }
