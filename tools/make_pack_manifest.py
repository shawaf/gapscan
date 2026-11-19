"""Regenerate packages/gapscan-local/src/gapscan/runtime/manifest.json (maintainer tool, needs network, reads metadata only).

It asks GitHub for the pinned llama.cpp release's assets and Hugging Face for the model files' sizes and
sha256, and writes them into the manifest the app ships. No model or engine file is downloaded here.

    uv run python tools/make_pack_manifest.py [--llama-tag b11403]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from packaging.tags import Tag, compatible_tags, cpython_tags, mac_platforms
from packaging.utils import parse_wheel_filename

OUT = Path(__file__).resolve().parents[1] / "packages/gapscan-local/src/gapscan/runtime/manifest.json"
HOSTS = [
    "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
    "huggingface.co", "*.huggingface.co", "*.hf.co", "files.pythonhosted.org",
]  # fmt: skip
PYTHON = (3, 12)
TOOLS_IN = Path(__file__).resolve().parents[1] / "packages/gapscan-local/src/gapscan/runtime/python-tools.in"
LAUNCHERS = {  # semgrep's engine starts `pysemgrep` by name, so it needs a launcher too
    "semgrep": "semgrep.console_scripts.entrypoint:main",
    "pysemgrep": "semgrep.console_scripts.pysemgrep:main",
    "checkov": "checkov.main",
    "bandit": "bandit",
}
SCANNER_PLATFORMS = ["macos-arm64", "macos-x64", "linux-x64", "windows-x64"]
GO_TOOLS = [  # id, repo, programs, asset per platform ({v} = version without the leading v), bundled in the installer
    ("trivy", "aquasecurity/trivy", ["trivy"], {
        "macos-arm64": "trivy_{v}_macOS-ARM64.tar.gz", "macos-x64": "trivy_{v}_macOS-64bit.tar.gz",
        "linux-x64": "trivy_{v}_Linux-64bit.tar.gz", "windows-x64": "trivy_{v}_windows-64bit.zip"}, False),
    ("gitleaks", "gitleaks/gitleaks", ["gitleaks"], {
        "macos-arm64": "gitleaks_{v}_darwin_arm64.tar.gz", "macos-x64": "gitleaks_{v}_darwin_x64.tar.gz",
        "linux-x64": "gitleaks_{v}_linux_x64.tar.gz", "windows-x64": "gitleaks_{v}_windows_x64.zip"}, True),
    ("osv-scanner", "google/osv-scanner", ["osv-scanner"], {
        "macos-arm64": "osv-scanner_darwin_arm64", "macos-x64": "osv-scanner_darwin_amd64",
        "linux-x64": "osv-scanner_linux_amd64", "windows-x64": "osv-scanner_windows_amd64.exe"}, True),
]  # fmt: skip
PBS_TRIPLE = {"macos-arm64": "aarch64-apple-darwin", "macos-x64": "x86_64-apple-darwin",
              "linux-x64": "x86_64-unknown-linux-gnu", "windows-x64": "x86_64-pc-windows-msvc"}  # fmt: skip
UV_PLATFORM = PBS_TRIPLE  # uv uses the same target names
RUNTIMES = {  # platform key -> (asset suffix, archive kind)
    "macos-arm64": ("bin-macos-arm64.tar.gz", "tar.gz"),
    "macos-x64": ("bin-macos-x64.tar.gz", "tar.gz"),
    "linux-x64": ("bin-ubuntu-x64.tar.gz", "tar.gz"),
    "linux-vulkan-x64": ("bin-ubuntu-vulkan-x64.tar.gz", "tar.gz"),
    "windows-x64": ("bin-win-cpu-x64.zip", "zip"),
    "windows-vulkan-x64": ("bin-win-vulkan-x64.zip", "zip"),
}
MODELS = [  # id, repo, file, profile, alias, context, note
    ("qwen3-coder-30b-q4", "unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF", "Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf",
     "best", "qwen3-coder:30b", 32768, "Best measured. MoE with 3B active parameters, code-specific."),
    ("qwen25-coder-14b-q4", "bartowski/Qwen2.5-Coder-14B-Instruct-GGUF", "Qwen2.5-Coder-14B-Instruct-Q4_K_M.gguf",
     "balanced", "qwen2.5-coder:14b", 16384, "For 16 GB machines. Not yet benchmarked by GapScan."),
]  # fmt: skip
EMBEDDING = (
    "nomic-embed-text-q8",
    "nomic-ai/nomic-embed-text-v1.5-GGUF",
    "nomic-embed-text-v1.5.Q8_0.gguf",
)


def accepted_tags(platform: str) -> list[Tag]:
    """The wheel tags a Python 3.12 on `platform` accepts, best first."""
    if platform == "macos-arm64":
        plats = list(mac_platforms((15, 0), "arm64"))
    elif platform == "macos-x64":
        plats = list(mac_platforms((15, 0), "x86_64"))
    elif platform == "linux-x64":
        plats = [f"manylinux_2_{m}_x86_64" for m in range(40, 16, -1)] + [
            "manylinux2014_x86_64",
            "manylinux2010_x86_64",
            "manylinux1_x86_64",
            "linux_x86_64",
        ]
    else:
        plats = ["win_amd64"]
    return [*cpython_tags(PYTHON, platforms=plats), *compatible_tags(PYTHON, "cp312", plats)]


def resolve_wheels(http: httpx.Client, platform: str) -> list[dict[str, Any]]:
    """Every Python package the scanners need on `platform`, as the one wheel to download for each."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            ["uv", "pip", "compile", str(TOOLS_IN), "--python-version", "3.12", "--python-platform", UV_PLATFORM[platform],
             "--generate-hashes", "--no-header", "--no-annotate", "-q", "-o", f"{tmp}/r.txt"],
            capture_output=True, text=True, check=True,
        )  # fmt: skip
        text = Path(tmp, "r.txt").read_text()
    pinned: dict[str, tuple[str, set[str]]] = {}
    for block in text.replace("\\\n", " ").splitlines():
        if "==" in block and not block.lstrip().startswith("#"):
            spec, *rest = block.strip().split()
            name, version = spec.split("==")
            pinned[name] = (
                version,
                {h.removeprefix("--hash=sha256:") for h in rest if h.startswith("--hash=")},
            )
    rank = {t: i for i, t in enumerate(accepted_tags(platform))}
    wheels = []
    for name, (version, hashes) in sorted(pinned.items()):
        files = http.get(f"https://pypi.org/pypi/{name}/{version}/json").json()["urls"]
        best: tuple[int, dict[str, Any]] | None = None
        for f in files:
            if f["packagetype"] != "bdist_wheel" or f["digests"]["sha256"] not in hashes:
                continue
            tags = parse_wheel_filename(f["filename"])[3]
            ranks = [rank[t] for t in tags if t in rank]
            if ranks and (best is None or min(ranks) < best[0]):
                best = (min(ranks), f)
        if best is None:
            raise LookupError(
                f"{name}=={version} has no wheel for {platform} (a source-only package would need a build)"
            )
        f = best[1]
        wheels.append(
            {
                "filename": f["filename"],
                "url": f["url"],
                "size": f["size"],
                "sha256": f["digests"]["sha256"],
            }
        )
    return wheels


def scanner_packs(http: httpx.Client) -> list[dict[str, object]]:
    packs: list[dict[str, object]] = []
    for pid, repo, provides, assets, bundled in GO_TOOLS:
        rel = http.get(f"https://api.github.com/repos/{repo}/releases/latest").json()
        version = rel["tag_name"].lstrip("v")
        by_name = {a["name"]: a for a in rel["assets"]}
        for platform, pattern in assets.items():
            a = by_name[pattern.format(v=version)]
            archive = (
                "zip"
                if a["name"].endswith(".zip")
                else "tar.gz"
                if a["name"].endswith(".tar.gz")
                else ""
            )
            packs.append({
                "id": f"{pid}-{platform}", "kind": "scanner", "url": a["browser_download_url"], "size": a["size"],
                "sha256": a["digest"].removeprefix("sha256:"), "filename": a["name"], "version": version, "platform": platform,
                "archive": archive, "provides": provides, "binary": provides[0] if not archive else "", "bundled": bundled,
            })  # fmt: skip
    return packs


def python_packs(
    http: httpx.Client,
) -> tuple[list[dict[str, object]], dict[str, list[dict[str, Any]]]]:
    rel = http.get(
        "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"
    ).json()
    packs: list[dict[str, object]] = []
    wheels: dict[str, list[dict[str, Any]]] = {}
    for platform, triple in PBS_TRIPLE.items():
        try:
            platform_wheels = resolve_wheels(http, platform)
        except LookupError as exc:
            print(f"skipping the Python scanners on {platform}: {exc}")
            continue
        a = next(
            x
            for x in rel["assets"]
            if x["name"].startswith("cpython-3.12.")
            and x["name"].endswith(f"{triple}-install_only.tar.gz")
        )
        packs.append({"id": f"python-{platform}", "kind": "python", "url": a["browser_download_url"], "size": a["size"],
                      "sha256": a["digest"].removeprefix("sha256:"), "filename": a["name"], "version": a["name"].split("+")[0].removeprefix("cpython-"),
                      "platform": platform, "archive": "tar.gz"})  # fmt: skip
        wheels[platform] = platform_wheels
    return packs, wheels


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--llama-tag", default="b11403")
    ap.add_argument(
        "--skip-python",
        action="store_true",
        help="leave out the Python scanners (needs uv and downloads nothing, but is slow)",
    )
    args = ap.parse_args()
    tag = args.llama_tag
    http = httpx.Client(timeout=30, follow_redirects=True)
    packs: list[dict[str, object]] = []
    rel = http.get(f"https://api.github.com/repos/ggml-org/llama.cpp/releases/tags/{tag}").json()
    assets = {a["name"]: a for a in rel["assets"]}
    for key, (suffix, kind) in RUNTIMES.items():
        name = f"llama-{tag}-{suffix}"
        a = assets[name]
        packs.append({
            "id": f"llama-server-{key}", "kind": "runtime", "url": a["browser_download_url"], "size": a["size"],
            "sha256": a["digest"].removeprefix("sha256:"), "filename": name, "version": tag, "platform": key, "archive": kind,
        })  # fmt: skip

    def hf(repo: str, file: str) -> tuple[str, int]:
        tree = http.get(f"https://huggingface.co/api/models/{repo}/tree/main").json()
        f = next(x for x in tree if x["path"] == file)
        return f["lfs"]["oid"], f["size"]

    for pid, repo, file, profile, alias, ctx, note in MODELS:
        sha, size = hf(repo, file)
        packs.append({"id": pid, "kind": "model", "url": f"https://huggingface.co/{repo}/resolve/main/{file}", "size": size,
                      "sha256": sha, "filename": file, "profile": profile, "alias": alias, "context_tokens": ctx, "note": note})  # fmt: skip
    pid, repo, file = EMBEDDING
    sha, size = hf(repo, file)
    packs.append({"id": pid, "kind": "embedding", "url": f"https://huggingface.co/{repo}/resolve/main/{file}", "size": size,
                  "sha256": sha, "filename": file, "alias": "nomic-embed-text", "note": "Builds the knowledge base."})  # fmt: skip
    previous = json.loads(OUT.read_text()) if OUT.exists() else {}
    packs += scanner_packs(http)
    packs += [
        p for p in previous.get("packs", []) if p["kind"] == "data"
    ]  # a pinned data pack (tools/make_data_pack.py) is kept
    wheels: dict[str, list[dict[str, Any]]] = {}
    if not args.skip_python:
        py, wheels = python_packs(http)
        packs += py
    manifest = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        "allowed_hosts": HOSTS,
        "packs": packs,
        "wheels": wheels,
        "launchers": {} if args.skip_python else LAUNCHERS,
    }
    OUT.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} with {len(packs)} packs (llama.cpp {tag})")


if __name__ == "__main__":
    main()
