"""The managed AI runtime: download rules, archive safety, the supervised server and the setup API."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import sys
import tarfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from gapscan.config import Config
from gapscan.runtime.download import (
    DownloadCancelled,
    DownloadError,
    download,
    extract_archive,
    host_allowed,
    is_installed,
)
from gapscan.runtime.hardware import Hardware, needs_gb, usable_gb
from gapscan.runtime.manager import RuntimeError_, RuntimeManager
from gapscan.runtime.manifest import MANIFEST_PATH as MANIFEST_FILE
from gapscan.runtime.manifest import Manifest, Pack, load_manifest, platform_key, runtime_pack
from gapscan.runtime.server import LlamaServer, ServerError
from gapscan.server import build_server

from .test_server import Client, FakePipeline

FAKE_SERVER = f"""#!{sys.executable}
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
a = sys.argv
port = int(a[a.index("--port") + 1]); alias = a[a.index("--alias") + 1]
class H(BaseHTTPRequestHandler):
    def log_message(self, *x): pass
    def _send(self, body, code=200):
        data = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self._send({{"status": "ok"}} if self.path == "/health" else {{"data": [{{"id": alias}}]}})
HTTPServer(("127.0.0.1", port), H).serve_forever()
"""


@pytest.fixture(autouse=True)
def no_host_ollama(tmp_path, monkeypatch):
    """Never let a test see (or link) a model from the Ollama installed on the developer's machine."""
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "no-ollama"))


class Origin:
    """A tiny file host with Range support and optional redirects, standing in for the real hosts."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.redirects: dict[str, str] = {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path in owner.redirects:
                    self.send_response(302)
                    self.send_header("Location", owner.redirects[self.path])
                    self.end_headers()
                    return
                data = owner.files.get(self.path)
                if data is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                start = 0
                rng = self.headers.get("Range")
                if rng:
                    start = int(rng.split("=")[1].split("-")[0])
                    if start >= len(data):
                        self.send_response(416)
                        self.end_headers()
                        return
                    self.send_response(206)
                else:
                    self.send_response(200)
                body = data[start:]
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.http.server_address[1]}"

    def close(self) -> None:
        self.http.shutdown()
        self.http.server_close()


@pytest.fixture
def origin():
    o = Origin()
    yield o
    o.close()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def runtime_archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo("llama-b1/llama-server")
        data = FAKE_SERVER.encode()
        info.size, info.mode = len(data), 0o644
        t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# --- hardware and manifest ---------------------------------------------------------------------


def test_what_fits_follows_memory_and_gpu():
    mac = Hardware("macos", "arm64", 32.0, 200.0, "metal")
    assert needs_gb(18_556_689_568) <= usable_gb(mac)  # the best model runs on a 32 GB Mac
    assert needs_gb(18_556_689_568) > usable_gb(Hardware("macos", "arm64", 24.0, 200.0, "metal"))
    assert usable_gb(Hardware("linux", "x64", 16.0, 100.0, "none")) < usable_gb(mac)
    nv = Hardware("windows", "x64", 16.0, 100.0, "nvidia", "RTX", 24.0)
    assert usable_gb(nv) > 24


def test_shipped_manifest_is_complete_and_pinned():
    m = load_manifest()
    assert {p.platform for p in m.packs if p.kind == "runtime"} >= {
        "macos-arm64",
        "linux-x64",
        "windows-x64",
    }
    assert m.embedding() is not None and len(m.models()) >= 2
    assert all(len(p.sha256) == 64 and p.size > 0 and p.url.startswith("https://") for p in m.packs)
    assert all(host_allowed(p.url, m.allowed_hosts) for p in m.packs)
    assert runtime_pack(m, Hardware("macos", "arm64", 16, 100, "metal")).platform == "macos-arm64"
    assert platform_key(Hardware("windows", "x64", 16, 100, "nvidia")) == "windows-vulkan-x64"
    assert platform_key(Hardware("linux", "x64", 16, 100, "none")) == "linux-x64"


def test_hosts_must_be_listed_and_secure():
    allowed = ["huggingface.co", "*.hf.co"]
    assert host_allowed("https://huggingface.co/x", allowed)
    assert host_allowed("https://cdn.hf.co/x", allowed)
    assert not host_allowed("http://huggingface.co/x", allowed)  # no plain HTTP off this machine
    assert not host_allowed("https://evil.example/x", allowed)
    assert not host_allowed("https://huggingface.co.evil.example/x", allowed)
    assert host_allowed("http://127.0.0.1:9/x", [])


# --- downloads -------------------------------------------------------------------------------


def test_download_verifies_and_skips_when_already_installed(origin, tmp_path):
    data = b"x" * 3_000_000
    origin.files["/m.gguf"] = data
    dest = tmp_path / "m.gguf"
    seen = []
    download(origin.base + "/m.gguf", dest, sha256=sha(data), size=len(data), allowed_hosts=[],
             progress=lambda d, t: seen.append(d))  # fmt: skip
    assert dest.read_bytes() == data and is_installed(dest, sha(data), len(data))
    assert seen[-1] == len(data) and not dest.with_name("m.gguf.part").exists()
    origin.files.clear()  # a second call must not need the network
    download(origin.base + "/m.gguf", dest, sha256=sha(data), size=len(data), allowed_hosts=[])


def test_download_resumes_after_cancel(origin, tmp_path):
    data = bytes(range(256)) * 20_000  # about 5 MB
    origin.files["/m.gguf"] = data
    dest, cancel = tmp_path / "m.gguf", threading.Event()
    with pytest.raises(DownloadCancelled):
        download(origin.base + "/m.gguf", dest, sha256=sha(data), size=len(data), allowed_hosts=[],
                 cancel=cancel, progress=lambda d, t: cancel.set())  # fmt: skip
    part = dest.with_name("m.gguf.part")
    partial = part.stat().st_size
    assert 0 < partial < len(data)
    got = []
    download(origin.base + "/m.gguf", dest, sha256=sha(data), size=len(data), allowed_hosts=[],
             progress=lambda d, t: got.append(d))  # fmt: skip
    assert dest.read_bytes() == data and got[0] > partial  # it continued, not restarted


def test_a_wrong_checksum_discards_the_file(origin, tmp_path):
    origin.files["/m"] = b"hello world"
    dest = tmp_path / "m"
    with pytest.raises(DownloadError, match="checksum"):
        download(origin.base + "/m", dest, sha256=sha(b"other"), size=11, allowed_hosts=[])
    assert not dest.exists() and not dest.with_name("m.part").exists()


def test_a_wrong_size_and_missing_disk_are_refused(origin, tmp_path):
    origin.files["/m"] = b"hello world"
    with pytest.raises(DownloadError, match="received"):
        download(
            origin.base + "/m",
            tmp_path / "m",
            sha256=sha(b"hello world"),
            size=20,
            allowed_hosts=[],
        )
    with pytest.raises(DownloadError, match="disk space"):
        download(origin.base + "/m", tmp_path / "n", sha256=sha(b"hello world"), size=11,
                 allowed_hosts=[], min_free_gb=10**9)  # fmt: skip


def test_unlisted_hosts_and_redirects_to_them_are_refused(origin, tmp_path):
    with pytest.raises(DownloadError, match="allowed"):
        download(
            "https://evil.example/m",
            tmp_path / "m",
            sha256=sha(b"x"),
            size=1,
            allowed_hosts=["a.example"],
        )
    origin.redirects["/m"] = "https://evil.example/m"
    with pytest.raises(DownloadError, match="redirected"):
        download(origin.base + "/m", tmp_path / "m", sha256=sha(b"x"), size=1, allowed_hosts=[])
    origin.files["/real"] = b"data"
    origin.redirects["/m2"] = origin.base + "/real"
    download(origin.base + "/m2", tmp_path / "m2", sha256=sha(b"data"), size=4, allowed_hosts=[])
    assert (tmp_path / "m2").read_bytes() == b"data"


def test_archives_cannot_write_outside_their_folder(tmp_path):
    z = tmp_path / "bad.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("../escape.txt", "x")
    with pytest.raises(DownloadError, match="unsafe"):
        extract_archive(z, tmp_path / "out", "zip")
    t = tmp_path / "bad.tar.gz"
    with tarfile.open(t, "w:gz") as f:
        info = tarfile.TarInfo("../escape.txt")
        info.size = 1
        f.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(tarfile.TarError):
        extract_archive(t, tmp_path / "out2", "tar.gz")
    assert not (tmp_path / "escape.txt").exists()


# --- the supervised server -------------------------------------------------------------------


def make_fake_binary(path: Path) -> Path:
    path.write_text(FAKE_SERVER)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_llama_server_starts_answers_and_stops(tmp_path):
    binary = make_fake_binary(tmp_path / "llama-server")
    srv = LlamaServer(binary, tmp_path / "m.gguf", "qwen3-coder:30b", log=tmp_path / "log.txt")
    assert (
        "--host" in srv.command() and "127.0.0.1" in srv.command() and "--no-webui" in srv.command()
    )
    srv.start(timeout_s=20)
    try:
        assert srv.running and srv.endpoint.startswith("http://127.0.0.1:")
        assert httpx.get(srv.endpoint + "/v1/models").json()["data"][0]["id"] == "qwen3-coder:30b"
    finally:
        srv.stop()
    assert not srv.running


def test_llama_server_reports_why_it_failed(tmp_path):
    bad = tmp_path / "llama-server"
    bad.write_text(f"#!{sys.executable}\nimport sys\nprint('model file is broken')\nsys.exit(3)\n")
    bad.chmod(0o755)
    srv = LlamaServer(bad, tmp_path / "m.gguf", "m", log=tmp_path / "log.txt")
    with pytest.raises(ServerError, match="model file is broken"):
        srv.start(timeout_s=20)


# --- manager and setup API --------------------------------------------------------------------


def make_manifest(origin: Origin) -> Manifest:
    archive, model, emb = runtime_archive(), b"M" * 400_000, b"E" * 100_000
    origin.files.update({"/rt.tar.gz": archive, "/m.gguf": model, "/e.gguf": emb})
    host = origin.base
    return Manifest(
        created_at="2026-10-05", allowed_hosts=[],
        packs=[
            Pack(id="rt", kind="runtime", url=host + "/rt.tar.gz", size=len(archive), sha256=sha(archive),
                 filename="rt.tar.gz", version="b1", platform="macos-arm64", archive="tar.gz"),
            Pack(id="big", kind="model", url=host + "/m.gguf", size=len(model), sha256=sha(model),
                 filename="m.gguf", profile="best", alias="qwen3-coder:30b", context_tokens=8192),
            Pack(id="emb", kind="embedding", url=host + "/e.gguf", size=len(emb), sha256=sha(emb),
                 filename="e.gguf", alias="nomic-embed-text"),
        ],
    )  # fmt: skip


HW = Hardware("macos", "arm64", 32.0, 500.0, "metal", "Apple silicon")


@pytest.fixture
def rt(origin, tmp_path):
    m = RuntimeManager(tmp_path / "data", make_manifest(origin), HW)
    m.attach(Config(data={"dir": str(tmp_path / "data")}))
    yield m
    m.stop()


def noop(_d, _t):
    return None


def test_manager_installs_starts_and_points_the_config_at_the_engine(rt):
    assert not rt.managed() and rt.recommended() == "big"
    with pytest.raises(RuntimeError_, match="not installed"):
        rt.start_chat("big")
    rt.install_runtime(noop)
    rt.install_model("big", noop)
    assert rt.managed() and rt.status()["runtime"]["installed"]
    original = rt._base.llm.endpoint
    rt.start_chat("big")
    cfg = rt._base
    assert cfg.llm.backend == "openai" and cfg.llm.endpoint.startswith("http://127.0.0.1:")
    assert cfg.llm.endpoint != original and cfg.llm.model == "qwen3-coder:30b"
    assert rt.status()["active"] == "big"
    rt.stop_chat()
    assert (
        cfg.llm.endpoint == original and cfg.llm.backend == "ollama"
    )  # back to the user's own setup


def test_prepare_starts_the_engine_for_a_run(rt):
    rt.install_runtime(noop)
    rt.install_model("big", noop)
    run_cfg = Config(data={"dir": "x"}).model_copy(deep=True)
    rt.prepare(run_cfg)
    assert rt.chat.running and run_cfg.llm.endpoint == rt.chat.endpoint


def test_embedding_server_is_separate_and_optional(rt):
    rt.install_runtime(noop)
    rt.install_model("emb", noop)
    rt.start_embedding()
    assert rt.embed.running and rt._base.llm.embedding_endpoint == rt.embed.endpoint
    rt.stop_embedding()
    assert rt._base.llm.embedding_endpoint == ""


def test_removing_a_model_deletes_its_files(rt):
    rt.install_model("big", noop)
    assert rt.installed(rt.manifest.pack("big"))
    rt.remove_model("big")
    assert (
        not rt.installed(rt.manifest.pack("big"))
        and not rt.model_path(rt.manifest.pack("big")).exists()
    )


@pytest.fixture
def setup_env(origin, tmp_path):
    cfg = Config(data={"dir": str(tmp_path / "data")},
                 scanners={"osv": {"db_dir": str(tmp_path / "o")}, "trivy": {"cache_dir": str(tmp_path / "t")}})  # fmt: skip
    runtime = RuntimeManager(tmp_path / "data", make_manifest(origin), HW)
    server = build_server(cfg, port=0, pipeline=FakePipeline(), runtime=runtime)
    server._manager_html = "<!doctype html><title>m</title>"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = Client(server, server.jobs.pipeline)
    yield client
    server.shutdown()
    server.jobs.stop()
    server.server_close()


def wait_task(c, tid):
    for _ in range(400):
        t = c.get(f"/api/tasks/{tid}").json()
        if t["status"] != "running":
            return t
        time.sleep(0.05)
    raise AssertionError("task never finished")


def test_setup_api_walks_through_the_steps(setup_env):
    c = setup_env
    st = c.get("/api/setup").json()
    assert st["hardware"]["gpu"] == "metal" and st["recommended"] == "big" and not st["running"]
    assert st["runtime"]["installed"] is False and st["embedding"]["installed"] is False
    for step, pack in [("engine", ""), ("model", "big"), ("embedding", "")]:
        t = wait_task(c, c.req("POST", "/api/setup/run", {"step": step, "pack": pack}).json()["id"])
        assert t["status"] == "done", t["log"]
        assert t["progress"]["done"] == t["progress"]["total"] > 0 or step == "engine"
    t = wait_task(c, c.req("POST", "/api/setup/run", {"step": "start", "pack": "big"}).json()["id"])
    assert t["status"] == "done", t["log"]
    st = c.get("/api/setup").json()
    assert st["running"] and st["active"] == "big" and all(x["installed"] for x in st["tiers"])
    models = c.get("/api/models").json()
    assert any(
        m["name"] == "qwen3-coder:30b" for m in models["installed"]
    )  # the app now talks to it
    t = wait_task(c, c.req("POST", "/api/setup/run", {"step": "stop"}).json()["id"])
    assert t["status"] == "done" and not c.get("/api/setup").json()["running"]


def test_setup_api_refuses_bad_requests_and_overlap(setup_env):
    c = setup_env
    assert c.req("POST", "/api/setup/run", {"step": "format-disk"}).status_code == 400
    assert c.req("POST", "/api/setup/run", {"step": "model"}).status_code == 400
    t = wait_task(
        c, c.req("POST", "/api/setup/run", {"step": "model", "pack": "nope"}).json()["id"]
    )
    assert t["status"] == "failed" and "unknown model" in t["log"][-1]
    t = wait_task(c, c.req("POST", "/api/setup/run", {"step": "start", "pack": "big"}).json()["id"])
    assert t["status"] == "failed" and "not installed" in t["log"][-1]
    assert c.req("POST", "/api/tasks/ffffffff/cancel").status_code == 404


# --- reuse of a model Ollama already has ------------------------------------------------------


def fake_ollama(
    root: Path, alias: str = "qwen3-coder:30b", size: int = 60_000_000, magic: bytes = b"GGUF"
) -> Path:
    name, tag = alias.split(":")
    digest = "a" * 64
    blob = root / "blobs" / f"sha256-{digest}"
    blob.parent.mkdir(parents=True, exist_ok=True)
    with blob.open("wb") as f:
        f.write(magic)
        f.truncate(size)
    mf = root / "manifests" / "registry.ollama.ai" / "library" / name / tag
    mf.parent.mkdir(parents=True, exist_ok=True)
    mf.write_text(json.dumps({"layers": [
        {"mediaType": "application/vnd.ollama.image.model", "digest": "sha256:" + digest, "size": size},
        {"mediaType": "application/vnd.ollama.image.license", "digest": "sha256:" + "b" * 64, "size": 3},
    ]}))  # fmt: skip
    return blob


def test_finds_only_genuine_gguf_models_in_ollama_store(tmp_path):
    from gapscan.runtime import ollama

    blob = fake_ollama(tmp_path)
    assert ollama.find_model("qwen3-coder:30b", tmp_path) == blob
    assert ollama.find_model("qwen3-coder:14b", tmp_path) is None  # not stored
    assert ollama.find_model("qwen3-coder", tmp_path) is None  # no tag
    assert ollama.find_model("../x:1", tmp_path) is None
    bad = tmp_path / "bad"
    fake_ollama(bad, magic=b"NOPE")
    assert ollama.find_model("qwen3-coder:30b", bad) is None  # not a GGUF file
    small = tmp_path / "small"
    fake_ollama(small, size=1000)
    assert ollama.find_model("qwen3-coder:30b", small) is None


def test_model_step_reuses_ollama_first_and_never_touches_its_files(rt, tmp_path, monkeypatch):
    store = tmp_path / "ollama"
    blob = fake_ollama(store)
    monkeypatch.setenv("OLLAMA_MODELS", str(store))
    pack = rt.manifest.pack("big")
    assert [t for t in rt.tiers() if t["id"] == "big"][0]["ollama"] is True
    rt.install_runtime(noop)
    said = []
    rt.install_model("big", noop, say=said.append)  # no origin file is needed: it must not download
    assert rt.installed(pack) and rt.model_path(pack) == blob
    assert (
        any("stored by Ollama" in m for m in said) and not (rt.root / "models" / "m.gguf").exists()
    )
    t = [t for t in rt.tiers() if t["id"] == "big"][0]
    assert t["linked"] and t["installed"] and not t["ollama"]
    rt.start_chat("big")
    assert str(blob) in rt.chat.command()
    rt.remove_model("big")  # removes the link only
    assert blob.exists() and not rt.installed(pack)


def test_model_step_downloads_when_ollama_does_not_have_it(rt, tmp_path, monkeypatch):
    monkeypatch.setenv("OLLAMA_MODELS", str(tmp_path / "empty-ollama"))
    said = []
    rt.install_model("big", noop, say=said.append)
    assert any("not found in Ollama" in m for m in said)
    assert (rt.root / "models" / "m.gguf").exists() and not rt.linked(rt.manifest.pack("big"))


def test_embedding_is_always_downloaded_not_linked(rt, tmp_path, monkeypatch):
    store = tmp_path / "ollama"
    fake_ollama(store, alias="nomic-embed-text:latest")
    monkeypatch.setenv("OLLAMA_MODELS", str(store))
    assert rt.ollama_copy(rt.manifest.pack("emb")) is None


def test_shipped_manifest_offers_every_scanner_pack_for_each_platform():
    m = load_manifest()
    for platform in ("macos-arm64", "macos-x64", "linux-x64", "windows-x64"):
        packs = [p for p in m.packs if p.kind == "scanner" and p.platform == platform]
        assert {x for p in packs for x in p.provides} == {"trivy", "gitleaks", "osv-scanner"}, (
            platform
        )
        assert {p.provides[0] for p in packs if p.bundled} == {
            "gitleaks",
            "osv-scanner",
        }  # the small ones ship inside
        assert all(p.archive or p.binary for p in packs)


def test_shipped_manifest_pins_python_scanners_with_hashes_for_each_supported_platform():
    m = load_manifest()
    assert set(m.launchers) >= {
        "semgrep",
        "pysemgrep",
        "checkov",
        "bandit",
    }  # semgrep's engine starts pysemgrep by name
    for platform in ("macos-arm64", "linux-x64", "windows-x64"):
        wheels = m.wheels[platform]
        assert any(w.filename.startswith("semgrep-") for w in wheels) and any(
            w.filename.startswith("bandit-") for w in wheels
        )
        assert all(
            w.url.startswith("https://files.pythonhosted.org/") and w.filename.endswith(".whl")
            for w in wheels
        )
        assert all(host_allowed(w.url, m.allowed_hosts) for w in wheels)
        assert any(p.kind == "python" and p.platform == platform for p in m.packs)


# --- the data pack ---------------------------------------------------------------------------------


def _bundle(tmp_path):
    from gapscan.offline.bundle import BundleOptions, build_bundle

    from .test_bundle import make_data

    out = tmp_path / "pack.tar.gz"
    build_bundle(make_data(tmp_path / "src"), out, BundleOptions())
    return out


def test_the_manifest_can_pin_a_data_pack(origin, tmp_path):
    bundle = _bundle(tmp_path)
    data = bundle.read_bytes()
    origin.files["/data.tar.gz"] = data
    m = make_manifest(origin)
    m.packs.append(
        Pack(
            id="data",
            kind="data",
            url=origin.base + "/data.tar.gz",
            size=len(data),
            sha256=sha(data),
            filename="pack.tar.gz",
        )
    )
    assert m.data() is not None and m.data().size == len(data)
    rt = RuntimeManager(tmp_path / "data", m, HW)
    st = rt.status()
    assert st["data"]["pack"]["size"] == len(data) and st["data"]["installed"] is False


def test_the_data_step_downloads_the_pack_and_installs_it_with_the_checked_importer(
    origin, tmp_path
):
    import threading

    from gapscan.server import build_server

    bundle = _bundle(tmp_path)
    data = bundle.read_bytes()
    origin.files["/data.tar.gz"] = data
    m = make_manifest(origin)
    m.packs.append(
        Pack(
            id="data",
            kind="data",
            url=origin.base + "/data.tar.gz",
            size=len(data),
            sha256=sha(data),
            filename="pack.tar.gz",
        )
    )
    cfg = Config(data={"dir": str(tmp_path / "data")}, scanners={"osv": {"db_dir": str(tmp_path / "o")}, "trivy": {"cache_dir": str(tmp_path / "t")}})  # fmt: skip
    server = build_server(
        cfg, port=0, pipeline=FakePipeline(), runtime=RuntimeManager(tmp_path / "data", m, HW)
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        c = Client(server, server.jobs.pipeline)
        plan = {s["step"]: s for s in c.get("/api/setup").json()["plan"]}
        assert plan["data"]["size"] == len(data) and plan["data"]["done"] is False
        t = wait_task(c, c.req("POST", "/api/setup/run", {"step": "data"}).json()["id"])
        assert t["status"] == "done", t["log"]
        assert (
            any("installed:" in line for line in t["log"])
            and t["progress"]["done"] == t["progress"]["total"]
        )
        assert (
            tmp_path / "data" / "bundle-state.json"
        ).is_file()  # the same marker `gapscan update` writes
        assert {s["step"]: s for s in c.get("/api/setup").json()["plan"]}["data"]["done"] is True
        assert not list(
            (tmp_path / "data" / "runtime" / "downloads").glob("pack.tar.gz*")
        )  # the download is cleaned up
    finally:
        server.shutdown()
        server.jobs.stop()
        server.server_close()


def test_a_manifest_can_be_chosen_by_environment_variable(tmp_path, monkeypatch):
    import json

    mine = tmp_path / "mine.json"
    data = json.loads(MANIFEST_FILE.read_text())
    data["created_at"] = "2099-01-01"
    mine.write_text(json.dumps(data))
    monkeypatch.setenv("GAPSCAN_MANIFEST", str(mine))
    assert load_manifest().created_at == "2099-01-01"
    monkeypatch.delenv("GAPSCAN_MANIFEST")
    assert load_manifest().created_at != "2099-01-01"


def test_engine_waits_longer_for_bigger_models(tmp_path):
    from gapscan.runtime.server import LlamaServer

    small, big = tmp_path / "s.gguf", tmp_path / "b.gguf"
    small.write_bytes(b"x")
    with big.open("wb") as fh:  # a sparse 9 GB file: nothing is written to disk
        fh.truncate(9_000_000_000)
    wait = {
        p.name: LlamaServer(tmp_path / "llama-server", p, "m", log=tmp_path / "l").ready_timeout()
        for p in (small, big)
    }
    assert wait["s.gguf"] >= 120 and wait["b.gguf"] >= 600  # the 9 GB model that needed 295 s fits


def test_engine_starts_from_a_relative_data_folder(tmp_path, monkeypatch):
    """Default config uses data dir `data` (relative); the engine runs with cwd = its own folder."""
    import stat

    from gapscan.runtime.server import LlamaServer

    monkeypatch.chdir(tmp_path)
    folder = Path("data/runtime/bin/llama/llama-b1")
    folder.mkdir(parents=True)
    fake = folder / "llama-server"
    fake.write_text("#!/bin/sh\nexec sleep 30\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    srv = LlamaServer(
        fake, Path("data/runtime/models/m.gguf"), "m", log=Path("data/runtime/logs/chat.log")
    )
    assert srv.binary.is_absolute() and srv.model.is_absolute() and srv.log.is_absolute()
    with pytest.raises(ServerError, match="did not become ready"):
        srv.start(timeout_s=1)  # it launches (no "No such file"), then times out: no real engine
