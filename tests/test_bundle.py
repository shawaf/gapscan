from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from gapscan.offline.bundle import (
    MANIFEST_NAME,
    BundleError,
    BundleOptions,
    build_bundle,
    collect_snapshots,
    model_files,
    sha256_file,
)
from gapscan.offline.update import (
    UpdateError,
    import_bundle,
    read_manifest,
    read_state,
    verify_bundle,
)


def make_data(root: Path, osv_date="2026-10-02", kev_date="2026-10-02T00:00:00Z") -> Path:
    d = root / "data"
    files = {
        "owasp/manifest.json": "{}",
        "owasp/top10-2025/A01.md": "# A01",
        "mitre/cwe/cwec.zip": "zip",
        "kb/kb.sqlite": "sqlite",
        "kb/meta.json": "{}",
        "enrichment/kev.json": json.dumps({"dateReleased": kev_date, "vulnerabilities": []}),
        "enrichment/epss.csv": "#model_version:v1,score_date:2026-10-01T00:00:00Z\ncve,epss,percentile\n",
        "osv-db/SNAPSHOT_DATE": osv_date + "\n",
        "osv-db/osv-scalibr/PyPI/all.zip": "zipdata",
        "trivy-cache/db/trivy.db": "trivydb",
        "trivy-cache/db/metadata.json": json.dumps({"UpdatedAt": "2026-10-02T13:01:27Z"}),
        "trivy-cache/java-db/trivy-java.db": "javadb",
        "trivy-cache/fanal/cache.db": "layer cache",
        "semgrep-rules/LICENSE": "Semgrep Rules License v1.0\n...",
        "semgrep-rules/python/r.yaml": "rules: []",
        "semgrep-rules/.git/HEAD": "a" * 40 + "\n",
        "eval-targets/benchmark/Test.java": "GPL code",
        "cache/llm.sqlite": "answers",
    }
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


def names(bundle: Path) -> set[str]:
    with tarfile.open(bundle) as t:
        return set(t.getnames())


def test_bundle_contains_the_right_sections_and_nothing_else(tmp_path):
    data = make_data(tmp_path)
    m = build_bundle(data, tmp_path / "b.tar.gz", BundleOptions(versions={"asvs": "5.0.0"}))
    n = names(tmp_path / "b.tar.gz")
    assert {MANIFEST_NAME, "NOTICES.md", "data/owasp/top10-2025/A01.md", "data/kb/kb.sqlite", "data/osv-db/osv-scalibr/PyPI/all.zip",
            "data/trivy-cache/db/trivy.db", "data/enrichment/kev.json"} <= n  # fmt: skip
    assert not any(
        "java-db" in x or "fanal" in x for x in n
    )  # big/scan-time caches excluded by default
    assert not any(
        x.startswith(("data/eval-targets", "data/cache")) for x in n
    )  # GPL benchmark code + answers never ship
    assert not any("semgrep" in x for x in n)  # community rules are opt-in
    assert m.versions == {"asvs": "5.0.0"} and not m.includes.semgrep_community_rules
    assert (tmp_path / "b.tar.gz.sha256").read_text().split()[0] == sha256_file(
        tmp_path / "b.tar.gz"
    )


def test_manifest_lists_every_file_with_checksum_and_snapshot_dates(tmp_path):
    data = make_data(tmp_path)
    m = build_bundle(data, tmp_path / "b.tar", BundleOptions(compress=False))
    by = {f.path: f for f in m.files}
    assert (
        by["data/kb/kb.sqlite"].sha256 == sha256_file(data / "kb" / "kb.sqlite")
        and by["data/kb/kb.sqlite"].bytes == 6
    )
    assert m.snapshots == {
        "osv_db": "2026-10-02",
        "trivy_db": "2026-10-02",
        "cisa_kev": "2026-10-02",
        "epss": "2026-10-01",
    }
    assert sum(m.sections.values()) == len(m.files) and m.sections["osv-db"] == 2
    assert read_manifest(tmp_path / "b.tar").files == m.files  # the first tar entry is the manifest


def test_bundles_are_reproducible_apart_from_the_timestamp(tmp_path):
    data = make_data(tmp_path)
    a = build_bundle(data, tmp_path / "a.tar", BundleOptions(compress=False))
    b = build_bundle(data, tmp_path / "b.tar", BundleOptions(compress=False))
    assert [(f.path, f.sha256) for f in a.files] == [(f.path, f.sha256) for f in b.files]


def test_semgrep_community_rules_need_an_explicit_license_acceptance(tmp_path):
    data = make_data(tmp_path)
    with pytest.raises(BundleError, match="Semgrep Rules License"):
        build_bundle(data, tmp_path / "x.tar.gz", BundleOptions(include_semgrep_rules=True))
    assert not (tmp_path / "x.tar.gz").exists()
    m = build_bundle(
        data,
        tmp_path / "y.tar.gz",
        BundleOptions(include_semgrep_rules=True, accept_semgrep_license=True),
    )
    n = names(tmp_path / "y.tar.gz")
    assert "data/semgrep-rules/python/r.yaml" in n and not any("/.git/" in x for x in n)
    assert m.includes.semgrep_community_rules and m.versions["semgrep_rules"] == "a" * 40
    with tarfile.open(tmp_path / "y.tar.gz") as t:
        notice = t.extractfile("NOTICES.md").read().decode()
    assert "Semgrep Rules License v1.0" in notice and "Do not publish this bundle" in notice
    assert (
        "CC BY-SA 4.0" in notice and "CISA" in notice and "EPSS" in notice
    )  # attribution always travels with the data


def test_java_db_only_on_request(tmp_path):
    data = make_data(tmp_path)
    build_bundle(data, tmp_path / "j.tar.gz", BundleOptions(include_java_db=True))
    assert "data/trivy-cache/java-db/trivy-java.db" in names(tmp_path / "j.tar.gz")


def test_missing_required_data_fails_loudly(tmp_path):
    data = make_data(tmp_path)
    for p in (data / "osv-db").rglob("*"):
        if p.is_file():
            p.unlink()
    with pytest.raises(BundleError, match="osv-db"):
        build_bundle(data, tmp_path / "z.tar.gz", BundleOptions())


def test_snapshot_collection_tolerates_missing_files(tmp_path):
    assert collect_snapshots(tmp_path) == {}


# --- model export ---------------------------------------------------------------------------


def make_ollama(root: Path) -> Path:
    o = root / "ollama"
    (o / "blobs").mkdir(parents=True)
    mf = o / "manifests" / "registry.ollama.ai" / "library" / "tiny"
    mf.mkdir(parents=True)
    layers = []
    for i, body in enumerate((b"config", b"weights-bytes")):
        import hashlib

        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        (o / "blobs" / digest.replace(":", "-")).write_bytes(body)
        layers.append({"digest": digest, "size": len(body), "mediaType": f"m{i}"})
    (mf / "3b").write_text(json.dumps({"config": layers[0], "layers": layers[1:]}))
    return o


def test_model_export_includes_manifest_and_every_blob(tmp_path):
    o = make_ollama(tmp_path)
    files = dict(model_files("tiny:3b", o))
    assert "models/ollama/manifests/registry.ollama.ai/library/tiny/3b" in files and len(files) == 3
    with pytest.raises(BundleError, match="not installed"):
        model_files("nope:1b", o)
    (o / "blobs" / next(p.name for p in (o / "blobs").iterdir())).unlink()
    with pytest.raises(BundleError, match="incomplete"):
        model_files("tiny:3b", o)


# --- importing ------------------------------------------------------------------------------


@pytest.fixture
def bundle(tmp_path):
    data = make_data(tmp_path / "src")
    path = tmp_path / "b.tar.gz"
    build_bundle(data, path, BundleOptions(versions={"asvs": "5.0.0"}))
    return path


def test_import_installs_every_section_and_writes_the_state(tmp_path, bundle):
    target = tmp_path / "air-gapped" / "data"
    res = import_bundle(target, bundle)
    assert set(res.sections) == {"owasp", "mitre", "kb", "enrichment", "osv-db", "trivy-cache"}
    assert (target / "kb" / "kb.sqlite").read_text() == "sqlite"
    assert (target / "osv-db" / "osv-scalibr" / "PyPI" / "all.zip").read_text() == "zipdata"
    state = read_state(target)
    assert state["snapshots"]["osv_db"] == "2026-10-02" and state["versions"] == {"asvs": "5.0.0"}
    assert not [
        p for p in target.parent.iterdir() if p.name.startswith(".gapscan-staging")
    ]  # staging cleaned up
    assert verify_bundle(bundle).files  # and a plain verify also passes


def test_import_replaces_a_section_completely_and_leaves_other_data_alone(tmp_path, bundle):
    target = tmp_path / "data"
    (target / "osv-db").mkdir(parents=True)
    (target / "osv-db" / "stale.zip").write_text("old")
    (target / "semgrep-rules").mkdir()
    (target / "semgrep-rules" / "mine.yaml").write_text("my own rules")  # not part of the bundle
    import_bundle(target, bundle)
    assert (
        not (target / "osv-db" / "stale.zip").exists()
        and (target / "osv-db" / "SNAPSHOT_DATE").exists()
    )
    assert (target / "semgrep-rules" / "mine.yaml").read_text() == "my own rules"


def rewrite(bundle: Path, out: Path, mutate) -> Path:
    """Copy a bundle, letting `mutate(name, data) -> data | None | list` alter or drop members."""
    with tarfile.open(bundle) as src, tarfile.open(out, "w:gz") as dst:
        for m in src:
            data = src.extractfile(m).read() if m.isreg() else b""
            result = mutate(m.name, data)
            for name, payload in (
                result
                if isinstance(result, list)
                else ([] if result is None else [(m.name, result)])
            ):
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                dst.addfile(info, io.BytesIO(payload))
    return out


def test_tampered_content_is_rejected_and_installed_data_is_untouched(tmp_path, bundle):
    target = tmp_path / "data"
    import_bundle(target, bundle)
    before = (target / "kb" / "kb.sqlite").read_text()
    evil = rewrite(
        bundle, tmp_path / "evil.tar.gz", lambda n, d: b"HACKED" if n == "data/kb/kb.sqlite" else d
    )
    with pytest.raises(UpdateError, match="checksum mismatch|size mismatch"):
        import_bundle(target, evil)
    assert (target / "kb" / "kb.sqlite").read_text() == before
    assert not [p for p in tmp_path.iterdir() if p.name.startswith((".gapscan-staging", ".old-"))]
    with pytest.raises(UpdateError):
        verify_bundle(evil)


def test_same_size_tampering_is_caught_by_the_checksum(tmp_path, bundle):
    evil = rewrite(
        bundle, tmp_path / "e.tar.gz", lambda n, d: b"X" * len(d) if n == "data/kb/kb.sqlite" else d
    )
    with pytest.raises(UpdateError, match="checksum mismatch"):
        verify_bundle(evil)


@pytest.mark.parametrize(
    "bad", ["../escape.txt", "/etc/cron.d/evil", "data/../../escape", "C:/evil", "data\\..\\x"]
)
def test_path_traversal_members_are_rejected(tmp_path, bundle, bad):
    evil = rewrite(
        bundle,
        tmp_path / "e.tar.gz",
        lambda n, d: [(n, d), (bad, b"pwned")] if n == "NOTICES.md" else d,
    )
    with pytest.raises(UpdateError, match="unsafe path|does not list"):
        import_bundle(tmp_path / "data", evil)
    assert not (tmp_path / "escape.txt").exists() and not (tmp_path / "data").exists()


def test_unlisted_extra_files_symlinks_and_duplicates_are_rejected(tmp_path, bundle):
    extra = rewrite(
        bundle,
        tmp_path / "x.tar.gz",
        lambda n, d: [(n, d), ("data/kb/extra.bin", b"x")] if n == "NOTICES.md" else d,
    )
    with pytest.raises(UpdateError, match="does not list"):
        verify_bundle(extra)
    dup = rewrite(
        bundle,
        tmp_path / "d.tar.gz",
        lambda n, d: [(n, d), (n, d)] if n == "data/kb/meta.json" else d,
    )
    with pytest.raises(UpdateError, match="duplicate"):
        verify_bundle(dup)
    link = tmp_path / "l.tar.gz"
    with tarfile.open(bundle) as src, tarfile.open(link, "w:gz") as dst:
        for m in src:
            dst.addfile(m, src.extractfile(m) if m.isreg() else None)
        info = tarfile.TarInfo("data/kb/evil-link")
        info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
        dst.addfile(info)
    with pytest.raises(UpdateError, match="non-regular"):
        verify_bundle(link)


def test_missing_members_and_foreign_archives_are_rejected(tmp_path, bundle):
    short = rewrite(
        bundle, tmp_path / "s.tar.gz", lambda n, d: None if n == "data/kb/meta.json" else d
    )
    with pytest.raises(UpdateError, match="incomplete"):
        verify_bundle(short)
    foreign = tmp_path / "f.tar.gz"
    with tarfile.open(foreign, "w:gz") as t:
        info = tarfile.TarInfo("hello.txt")
        info.size = 2
        t.addfile(info, io.BytesIO(b"hi"))
    with pytest.raises(UpdateError, match="not a GapScan bundle"):
        read_manifest(foreign)


def test_unsupported_schema_version_is_rejected(tmp_path, bundle):
    def bump(n, d):
        return (
            json.dumps({**json.loads(d), "schema_version": 99}).encode()
            if n == MANIFEST_NAME
            else d
        )

    with pytest.raises(UpdateError, match="schema 99"):
        read_manifest(rewrite(bundle, tmp_path / "v.tar.gz", bump))


def test_downgrade_is_refused_unless_forced(tmp_path):
    new = tmp_path / "new.tar.gz"
    old = tmp_path / "old.tar.gz"
    build_bundle(make_data(tmp_path / "n", osv_date="2026-10-02"), new, BundleOptions())
    build_bundle(
        make_data(tmp_path / "o", osv_date="2026-08-01", kev_date="2026-08-01T00:00:00Z"),
        old,
        BundleOptions(),
    )
    target = tmp_path / "data"
    import_bundle(target, new)
    with pytest.raises(UpdateError, match="older snapshots.*osv_db"):
        import_bundle(target, old)
    assert (target / "osv-db" / "SNAPSHOT_DATE").read_text().strip() == "2026-10-02"
    res = import_bundle(target, old, force=True)
    assert any("forced downgrade" in w for w in res.warnings)
    assert (target / "osv-db" / "SNAPSHOT_DATE").read_text().strip() == "2026-08-01"


def test_a_failure_while_swapping_rolls_back_to_the_previous_data(tmp_path, bundle, monkeypatch):
    target = tmp_path / "data"
    import_bundle(target, bundle)
    (target / "kb" / "marker").write_text("previous install")
    real_rename = Path.rename
    calls = {"n": 0}

    def flaky(self, dst):
        if self.name == "osv-db" and "staging" in str(self):
            calls["n"] += 1
            raise OSError("disk went away")
        return real_rename(self, dst)

    monkeypatch.setattr(Path, "rename", flaky)
    with pytest.raises(OSError, match="disk went away"):
        import_bundle(target, bundle)
    monkeypatch.undo()
    assert calls["n"] == 1
    assert (
        target / "kb" / "marker"
    ).read_text() == "previous install"  # sections swapped before the failure are restored
    assert (target / "osv-db" / "SNAPSHOT_DATE").exists()
    assert not [p for p in tmp_path.iterdir() if p.name.startswith((".gapscan-staging", ".old-"))]


def test_model_travels_with_the_bundle_and_is_imported_into_the_ollama_store(tmp_path):
    o = make_ollama(tmp_path)
    data = make_data(tmp_path / "src")
    path = tmp_path / "m.tar.gz"
    m = build_bundle(data, path, BundleOptions(model="tiny:3b", ollama_dir=o))
    assert m.includes.model == "tiny:3b" and m.sections["models"] == 3
    target_ollama = tmp_path / "airgap-ollama"
    res = import_bundle(tmp_path / "data", path, ollama_dir=target_ollama)
    assert res.model == "tiny:3b"
    assert (
        target_ollama / "manifests" / "registry.ollama.ai" / "library" / "tiny" / "3b"
    ).is_file()
    assert sorted(p.name for p in (target_ollama / "blobs").iterdir()) == sorted(
        p.name for p in (o / "blobs").iterdir()
    )
    skipped = import_bundle(tmp_path / "data2", path, ollama_dir=target_ollama, install_model=False)
    assert skipped.model is None


# --- refresh orchestration ------------------------------------------------------------------


def test_refresh_stops_before_downloading_anything_when_a_new_edition_appears(
    tmp_path, monkeypatch
):
    import gapscan.offline.refresh as r
    from gapscan.config import Config

    downloads = []
    monkeypatch.setattr(
        r,
        "resolve_versions",
        lambda: {
            "top10": "2029",
            "asvs": "5.0.0",
            "api_top10": "2023",
            "genai_llm_top10": "2026",
            "masvs": "2.1.0",
        },
    )
    for name in (
        "fetch_owasp",
        "fetch_kb_sources",
        "fetch_enrichment",
        "fetch_osv_db",
        "fetch_trivy_db",
    ):
        monkeypatch.setattr(r, name, lambda *a, _n=name, **k: downloads.append(_n))
    with pytest.raises(BundleError, match="(?s)new OWASP edition detected.*2029"):
        r.refresh_all(Config(data={"dir": str(tmp_path)}))
    assert downloads == []  # failed loudly, before any network download


def test_refresh_runs_every_step_in_order_and_reports_changes(tmp_path, monkeypatch):
    import gapscan.offline.refresh as r
    from gapscan.config import Config

    order = []
    ok = {
        "top10": "2025",
        "asvs": "5.0.0",
        "api_top10": "2023",
        "genai_llm_top10": "2026",
        "masvs": "2.1.0",
        "cheatsheets": "snapshot@x",
    }
    monkeypatch.setattr(r, "resolve_versions", lambda: ok)
    monkeypatch.setattr(r, "fetch_owasp", lambda store: order.append("owasp"))
    monkeypatch.setattr(r, "fetch_kb_sources", lambda a, b: order.append("kb-sources"))
    monkeypatch.setattr(r, "check_tables_current", lambda store: order.append("tables"))
    monkeypatch.setattr(
        r,
        "fetch_enrichment",
        lambda store: (
            order.append("enrichment") or {"cisa_kev": "2026-10-02", "epss": "2026-10-02"}
        ),
    )
    monkeypatch.setattr(r, "fetch_osv_db", lambda d: order.append("osv") or "2026-10-03")
    monkeypatch.setattr(
        r, "fetch_trivy_db", lambda c, java_db=False: order.append("trivy") or "2026-10-03"
    )
    monkeypatch.setattr(r, "build_kb", lambda cfg, embed=True: order.append("kb"))
    (tmp_path / "bundle-state.json").write_text(
        json.dumps({"versions": {"asvs": "5.0.0", "masvs": "2.0.0"}})
    )
    said = []
    v = r.refresh_all(Config(data={"dir": str(tmp_path)}), progress=said.append)
    assert order == ["owasp", "kb-sources", "tables", "enrichment", "osv", "trivy", "kb"]
    assert any("masvs: 2.0.0 -> 2.1.0" in s for s in said) and not any(
        "last bundle: asvs" in s for s in said
    )  # only real changes are printed
    assert v["osv_date"] == "2026-10-03" and v["kev_date"] == "2026-10-02" and v["masvs"] == "2.1.0"


def test_committed_mapping_tables_must_match_the_downloaded_owasp_data(tmp_path):
    import shutil

    from gapscan.offline.refresh import check_tables_current
    from gapscan.owasp.build import MAPPINGS_DIR
    from gapscan.store.raw import RawStore

    raw = Path(__file__).resolve().parent.parent / "data" / "owasp"
    if not (raw / "manifest.json").is_file():
        pytest.skip("raw OWASP data not downloaded")
    check_tables_current(RawStore(raw))  # the committed tables are current
    stale = tmp_path / "tables"
    shutil.copytree(MAPPINGS_DIR, stale)
    (stale / "cwe_to_top10.csv").write_text(
        "cwe,category,category_name,cwe_name\nCWE-1,A01:2025,x,y\n"
    )
    with pytest.raises(BundleError, match="cwe_to_top10.csv.*Regenerate and review"):
        check_tables_current(RawStore(raw), committed=stale)


def test_download_wheels_uses_argument_lists_with_timeouts(tmp_path, monkeypatch):
    import subprocess

    from gapscan.offline.refresh import download_wheels

    calls = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kw: calls.append((argv, kw)) or subprocess.CompletedProcess(argv, 0),
    )
    download_wheels(tmp_path / "w", timeout_s=5)
    assert [c[0][0] for c in calls] == ["uv", "uv"] and all(
        isinstance(c[0], list) and c[1]["timeout"] == 5 and "shell" not in c[1] for c in calls
    )
    assert "--only-binary=:all:" in calls[1][0] and "--no-dev" in calls[0][0]


# --- command line ---------------------------------------------------------------------------


def test_cli_bundle_and_update_roundtrip(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from gapscan.cli import app

    src = make_data(tmp_path / "src")
    (tmp_path / "src.toml").write_text(f'[data]\ndir = "{src}"\n')
    out = tmp_path / "out.tar.gz"
    runner = CliRunner()
    res = runner.invoke(
        app, ["bundle", "--no-refresh", "-o", str(out), "-c", str(tmp_path / "src.toml")]
    )
    assert res.exit_code == 0, res.stdout
    flat = " ".join(res.stdout.split())
    assert "sha256" in flat and out.is_file() and out.with_suffix(".gz.sha256").is_file()
    refused = runner.invoke(
        app,
        [
            "bundle",
            "--no-refresh",
            "--include-semgrep-community-rules",
            "-o",
            str(tmp_path / "r.tar.gz"),
            "-c",
            str(tmp_path / "src.toml"),
        ],
    )
    assert refused.exit_code == 1 and "accept-semgrep-rules-license" in " ".join(
        refused.stdout.split()
    )
    dst = tmp_path / "dst" / "data"
    (tmp_path / "dst.toml").write_text(f'[data]\ndir = "{dst}"\n')
    ok = runner.invoke(
        app, ["update", "--from", str(out), "--verify-only", "-c", str(tmp_path / "dst.toml")]
    )
    assert ok.exit_code == 0 and "Bundle intact" in " ".join(ok.stdout.split()) and not dst.exists()
    done = runner.invoke(app, ["update", "--from", str(out), "-c", str(tmp_path / "dst.toml")])
    assert done.exit_code == 0 and (dst / "kb" / "kb.sqlite").is_file()
    evil = rewrite(
        out, tmp_path / "evil.tar.gz", lambda n, d: b"HACKED" if n == "data/kb/kb.sqlite" else d
    )
    bad = runner.invoke(app, ["update", "--from", str(evil), "-c", str(tmp_path / "dst.toml")])
    assert (
        bad.exit_code == 1
        and "checksum mismatch" in " ".join(bad.stdout.split())
        or "size mismatch" in " ".join(bad.stdout.split())
    )


def test_table_check_ignores_line_endings_but_not_content(tmp_path, monkeypatch):
    """OWASP ships the ASVS CSV with CRLF; git stores it with LF. That is not a change."""
    from gapscan.offline import refresh

    committed = tmp_path / "committed"
    committed.mkdir()
    for t in refresh.TABLES:
        (committed / t).write_bytes(b"a,b\nc,d\n")

    def fake_build(store, out_dir, body=b"a,b\r\nc,d\r\n"):
        for t in refresh.TABLES:
            (out_dir / t).write_bytes(body)

    monkeypatch.setattr(refresh, "build", fake_build)
    refresh.check_tables_current(None, committed=committed)  # CRLF vs LF: same table
    monkeypatch.setattr(refresh, "build", lambda s, o: fake_build(s, o, b"a,b\r\nc,X\r\n"))
    with pytest.raises(BundleError, match="Regenerate and review"):
        refresh.check_tables_current(None, committed=committed)
