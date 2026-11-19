"""The pinned list of everything the wizard may download: URL, size and sha256 for each file.

The manifest ships inside the app. The downloader only talks to hosts listed in `allowed_hosts` (and
checks every redirect hop), and a file is installed only when its size and sha256 match. The maintainer
regenerates it with `tools/make_pack_manifest.py`; nothing here is looked up at run time."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from .hardware import Hardware

MANIFEST_PATH = Path(__file__).with_name("manifest.json")


class Pack(BaseModel):
    id: str
    kind: Literal["runtime", "model", "embedding", "scanner", "python", "data"]
    url: str
    size: int
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    filename: str
    version: str = ""
    platform: str = ""  # runtime only: macos-arm64, linux-x64, ...
    archive: Literal["", "tar.gz", "zip"] = ""  # runtime only
    profile: str = ""  # model only: the GapScan profile it serves (best, balanced)
    alias: str = ""  # the model name GapScan sends; equals the Ollama-style name used in profiles
    context_tokens: int = 0
    note: str = ""
    # scanners and the Python runtime they run on
    provides: list[str] = Field(default_factory=list)  # programs this pack puts on the PATH
    binary: str = ""  # a raw (not archived) program is installed under this name
    bundled: bool = False  # shipped inside the installer; the wizard downloads it only when missing


class Wheel(BaseModel):
    filename: str
    url: str
    size: int
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Manifest(BaseModel):
    schema_version: int = 1
    created_at: str
    allowed_hosts: list[str]
    packs: list[Pack]
    wheels: dict[str, list[Wheel]] = Field(
        default_factory=dict
    )  # platform -> pinned Python packages
    launchers: dict[str, str] = Field(default_factory=dict)  # program name -> `python -m` module

    def pack(self, pack_id: str) -> Pack:
        for p in self.packs:
            if p.id == pack_id:
                return p
        raise KeyError(pack_id)

    def models(self) -> list[Pack]:
        return sorted((p for p in self.packs if p.kind == "model"), key=lambda p: -p.size)

    def data(self) -> Pack | None:
        """The prebuilt security-data bundle, when one is published (an offline bundle made by `gapscan bundle`)."""
        return next((p for p in self.packs if p.kind == "data"), None)

    def embedding(self) -> Pack | None:
        return next((p for p in self.packs if p.kind == "embedding"), None)


MANIFEST_ENV = "GAPSCAN_MANIFEST"


def load_manifest(path: Path | None = None) -> Manifest:
    """The pinned manifest shipped with the app, or the file named by GAPSCAN_MANIFEST (an organization's own mirror of the
    packs, or a test). Downloads still go only to the hosts the chosen manifest lists."""
    import os

    chosen = path or Path(os.environ.get(MANIFEST_ENV) or MANIFEST_PATH)
    return Manifest.model_validate(json.loads(chosen.read_text(encoding="utf-8")))


def platform_key(hw: Hardware) -> str:
    """The runtime build to use. Windows and Linux with an NVIDIA card get the Vulkan build, which
    needs no CUDA install; everyone else gets the plain CPU build (macOS always uses Metal)."""
    if hw.os == "macos":
        return f"macos-{hw.arch}"
    if hw.arch != "x64":
        return f"{hw.os}-{hw.arch}"
    return f"{hw.os}-vulkan-x64" if hw.gpu == "nvidia" else f"{hw.os}-x64"


def scanner_platform(hw: Hardware) -> str:
    """Scanner builds exist per system and CPU only (no GPU variants)."""
    return f"{hw.os}-{hw.arch}"


def runtime_pack(manifest: Manifest, hw: Hardware) -> Pack | None:
    wanted = platform_key(hw)
    for p in manifest.packs:
        if p.kind == "runtime" and p.platform == wanted:
            return p
    return None
