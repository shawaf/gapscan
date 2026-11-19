"""Scanner delivery: PATH activation, bundled/managed/system lookup, installing raw programs, archives and the
pinned Python with wheels, all from a local fake host."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from gapscan.runtime import tools as tools_mod
from gapscan.runtime.hardware import Hardware
from gapscan.runtime.manifest import Manifest, Pack, Wheel
from gapscan.runtime.tools import ToolManager, activate, managed_dirs

from .test_runtime import Origin, no_host_ollama, noop, sha  # noqa: F401

HW = Hardware("macos", "arm64", 32.0, 500.0, "metal")
SCRIPT = "#!/bin/sh\necho {name} 1.0\n"


@pytest.fixture
def origin():
    o = Origin()
    yield o
    o.close()


@pytest.fixture
def clean_path(tmp_path, monkeypatch):
    """A PATH with nothing useful on it, so only managed copies can be found."""
    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(tools_mod, "bundled_dir", lambda: None)
    return empty


def targz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def wheel_bytes(package: str, body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"{package}/__init__.py", "")
        z.writestr(f"{package}/__main__.py", body)
        z.writestr(
            f"{package}-1.0.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {package}\nVersion: 1.0\n",
        )
        z.writestr(
            f"{package}-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: t\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        z.writestr(f"{package}-1.0.dist-info/RECORD", "")
    return buf.getvalue()


def pip_python() -> str | None:
    """A Python that has pip (the project venv may not); None when there is none on this machine."""
    for cand in (
        sys.executable,
        shutil.which("python3"),
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3.12",
    ):
        if not cand or not Path(cand).exists():
            continue
        try:
            ok = subprocess.run([cand, "-m", "pip", "--version"], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if ok.returncode == 0:
            return cand
    return None


def manifest(origin: Origin, python: str | None) -> Manifest:
    trivy = targz(
        {"trivy_0.1/trivy": SCRIPT.format(name="trivy").encode(), "trivy_0.1/LICENSE": b"x"}
    )
    gitleaks = SCRIPT.format(name="gitleaks").encode()
    origin.files.update({"/trivy.tgz": trivy, "/gitleaks": gitleaks})
    packs = [
        Pack(id="trivy", kind="scanner", url=origin.base + "/trivy.tgz", size=len(trivy), sha256=sha(trivy), filename="trivy.tgz",
             version="0.1", platform="macos-arm64", archive="tar.gz", provides=["trivy"]),
        Pack(id="gitleaks", kind="scanner", url=origin.base + "/gitleaks", size=len(gitleaks), sha256=sha(gitleaks), filename="gitleaks",
             version="1", platform="macos-arm64", provides=["gitleaks"], binary="gitleaks"),
    ]  # fmt: skip
    wheels, launchers = [], {}
    if python:
        shim = f'#!/bin/sh\nexec "{python}" "$@"\n'.encode()
        py = targz({"python/bin/python3": shim})
        wheel = wheel_bytes("fakebandit", "print('bandit ok')\n")
        origin.files.update({"/py.tgz": py, "/fakebandit-1.0-py3-none-any.whl": wheel})
        packs.append(Pack(id="python", kind="python", url=origin.base + "/py.tgz", size=len(py), sha256=sha(py), filename="py.tgz",
                          version="3.12", platform="macos-arm64", archive="tar.gz"))  # fmt: skip
        wheels = [Wheel(filename="fakebandit-1.0-py3-none-any.whl", url=origin.base + "/fakebandit-1.0-py3-none-any.whl",
                        size=len(wheel), sha256=sha(wheel))]  # fmt: skip
        launchers = {"bandit": "fakebandit"}
    return Manifest(
        created_at="2026-10-05",
        allowed_hosts=[],
        packs=packs,
        wheels={"macos-arm64": wheels},
        launchers=launchers,
    )


def test_nothing_is_found_on_a_bare_path_and_the_plan_lists_the_downloads(
    origin, tmp_path, clean_path
):
    tm = ToolManager(tmp_path / "rt", manifest(origin, pip_python()), HW)
    assert set(tm.missing()) == set(tools_mod.SCANNERS)
    plan = tm.plan()
    assert set(plan["packs"]) == {"trivy", "gitleaks"} and plan["size"] > 0
    assert (
        "semgrep" in plan["unavailable"] and "osv-scanner" in plan["unavailable"]
    )  # no pack offered for them


def test_install_raw_and_archived_programs_and_put_them_on_the_path(origin, tmp_path, clean_path):
    root = tmp_path / "rt"
    tm = ToolManager(root, manifest(origin, None), HW)
    seen = []
    tm.install(lambda d, t: seen.append((d, t)), say=lambda m: None)
    assert seen[-1][0] == seen[-1][1] > 0
    tm.activate()
    assert tm.where("trivy")[0] == "managed" and tm.where("gitleaks")[0] == "managed"
    assert (
        subprocess.run(["trivy"], capture_output=True, text=True).stdout.strip() == "trivy 1.0"
    )  # found by bare name
    assert (
        subprocess.run(["gitleaks"], capture_output=True, text=True).stdout.strip()
        == "gitleaks 1.0"
    )
    assert os.environ["PATH"].startswith(str(root / "tools"))
    assert "trivy" not in tm.missing()
    before = os.environ["PATH"]
    activate(root)
    assert os.environ["PATH"] == before  # idempotent
    tm.install(lambda d, t: None)  # nothing left to download: no network needed
    origin.files.clear()
    tm.install(lambda d, t: None)


def test_a_failed_checksum_installs_nothing(origin, tmp_path, clean_path):
    m = manifest(origin, None)
    m.packs[0].sha256 = "0" * 64
    tm = ToolManager(tmp_path / "rt", m, HW)
    from gapscan.runtime.download import DownloadError

    with pytest.raises(DownloadError, match="checksum"):
        tm.install(lambda d, t: None)
    assert (
        tm.where("trivy")[0] == "missing"
        and not (tmp_path / "rt" / "tools" / "trivy" / ".installed").exists()
    )


def test_system_programs_count_and_are_not_downloaded(origin, tmp_path, clean_path):
    mine = clean_path / "trivy"
    mine.write_text(SCRIPT.format(name="mine"))
    mine.chmod(0o755)
    tm = ToolManager(tmp_path / "rt", manifest(origin, None), HW)
    assert tm.where("trivy")[0] == "path" and "trivy" not in tm.missing()
    assert tm.plan()["packs"] == ["gitleaks"]


def test_bundled_programs_come_first(origin, tmp_path, clean_path, monkeypatch):
    bundled = tmp_path / "bundle"
    bundled.mkdir()
    (bundled / "gitleaks").write_text(SCRIPT.format(name="bundled"))
    (bundled / "gitleaks").chmod(0o755)
    monkeypatch.setattr(tools_mod, "bundled_dir", lambda: bundled)
    tm = ToolManager(tmp_path / "rt", manifest(origin, None), HW)
    assert tm.where("gitleaks")[0] == "bundled" and "gitleaks" not in tm.plan()["packs"]
    assert managed_dirs(tmp_path / "rt")[0] == bundled


@pytest.mark.skipif(pip_python() is None, reason="no Python with pip on this machine")
def test_python_scanners_install_offline_from_verified_wheels_and_run_through_a_launcher(
    origin, tmp_path, clean_path
):
    root = tmp_path / "rt"
    tm = ToolManager(root, manifest(origin, pip_python()), HW)
    assert tm.python_available() and tm.plan()["python"]
    tm.install(lambda d, t: None)
    tm.activate()
    assert tm.where("bandit")[0] == "managed"
    out = subprocess.run(["bandit"], capture_output=True, text=True)
    assert out.stdout.strip() == "bandit ok", out.stderr
    launcher = (root / "tools" / "python-tools" / "bin" / "bandit").read_text()
    assert (
        "-m fakebandit" in launcher and str(root) not in launcher
    )  # relative: the folder can move
    assert not (root / "tools" / "downloads" / "wheels").exists()


def test_setup_api_installs_scanners_and_reports_them(origin, tmp_path, clean_path):
    import threading
    import time

    from gapscan.config import Config
    from gapscan.runtime.manager import RuntimeManager
    from gapscan.server import build_server

    from .test_server import Client, FakePipeline

    cfg = Config(data={"dir": str(tmp_path / "data")},
                 scanners={"osv": {"db_dir": str(tmp_path / "o")}, "trivy": {"cache_dir": str(tmp_path / "t")}})  # fmt: skip
    server = build_server(
        cfg,
        port=0,
        pipeline=FakePipeline(),
        runtime=RuntimeManager(tmp_path / "data", manifest(origin, None), HW),
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        c = Client(server, server.jobs.pipeline)
        st = c.get("/api/setup").json()
        assert {s["name"]: s["via"] for s in st["scanners"]}["trivy"] == "missing"
        assert (
            set(st["scanner_plan"]["packs"]) == {"trivy", "gitleaks"}
            and st["scanner_plan"]["size"] > 0
        )
        tid = c.req("POST", "/api/setup/run", {"step": "scanners"}).json()["id"]
        for _ in range(200):
            t = c.get(f"/api/tasks/{tid}").json()
            if t["status"] != "running":
                break
            time.sleep(0.05)
        assert t["status"] == "done", t["log"]
        st = c.get("/api/setup").json()
        assert {s["name"]: s["via"] for s in st["scanners"]}["trivy"] == "managed" and st[
            "scanner_plan"
        ]["packs"] == []
        scanners = {s["name"]: s for s in c.get("/api/scanners").json()}
        assert scanners["gitleaks"]["available"] is True  # the scanner list noticed the install
    finally:
        server.shutdown()
        server.jobs.stop()
        server.server_close()


@pytest.mark.skipif(pip_python() is None, reason="no Python with pip on this machine")
def test_launchers_can_call_a_console_script_function(origin, tmp_path, clean_path):
    m = manifest(origin, pip_python())
    m.launchers = {"bandit": "fakebandit.__main__:main"}
    wheel = wheel_bytes("fakebandit", "def main():\n    print('function ok')\n    return 0\n")
    origin.files["/fakebandit-1.0-py3-none-any.whl"] = wheel
    m.wheels["macos-arm64"][0].size, m.wheels["macos-arm64"][0].sha256 = len(wheel), sha(wheel)
    tm = ToolManager(tmp_path / "rt", m, HW)
    tm.install(lambda d, t: None)
    tm.activate()
    assert (
        "from fakebandit.__main__ import main"
        in (tmp_path / "rt" / "tools" / "python-tools" / "bin" / "bandit").read_text()
    )
    assert (
        subprocess.run(["bandit"], capture_output=True, text=True).stdout.strip() == "function ok"
    )
