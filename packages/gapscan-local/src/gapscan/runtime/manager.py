"""Owns the managed AI runtime on this machine: what is installed, what fits, and the running servers."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..config import Config
from ..offline.bundle import STATE_FILE
from . import ollama
from .download import (
    Progress,
    download,
    extract_archive,
    find_binary,
    is_installed,
)
from .hardware import Hardware, detect, needs_gb, usable_gb
from .manifest import Manifest, Pack, load_manifest, platform_key, runtime_pack
from .server import LlamaServer, ServerError
from .tools import ToolManager

log = logging.getLogger(__name__)
EMBED_CONTEXT = 2048  # the knowledge-base chunks are short
Report = Callable[[str], None]


class RuntimeError_(RuntimeError):
    """A setup step that cannot proceed; the message is shown to the user as is."""


class RuntimeManager:
    def __init__(self, data_dir: Path, manifest: Manifest | None = None, hw: Hardware | None = None,
                 client_factory: Callable[[], Any] | None = None) -> None:  # fmt: skip
        self.root = (data_dir / "runtime").absolute()  # independent of later chdir / subprocess cwd
        self.manifest = manifest or load_manifest()
        self._hw = hw
        self._client_factory = client_factory
        self.chat: LlamaServer | None = None
        self.chat_pack: Pack | None = None
        self.embed: LlamaServer | None = None
        self._lock = threading.RLock()
        self._base: Config | None = None
        self._original: dict[str, str] = {}

    def attach(self, cfg: Config) -> None:
        """The server's own configuration: it follows the running servers and returns to what the
        user configured (for example their own Ollama) when they stop."""
        self._base = cfg
        self._original = {
            k: getattr(cfg.llm, k) for k in ("backend", "endpoint", "model", "embedding_endpoint")
        }

    def _sync(self) -> None:
        if self._base is None:
            return
        for k, v in self._original.items():
            setattr(self._base.llm, k, v)
        self.apply(self._base)

    # --- facts ------------------------------------------------------------------------------

    @property
    def hw(self) -> Hardware:
        if self._hw is None:
            self._hw = detect(self.root)
        return self._hw

    @property
    def tools(self) -> ToolManager:
        return ToolManager(self.root, self.manifest, self.hw, self._client_factory)

    @property
    def state_file(self) -> Path:
        return self.root / "state.json"

    def state(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def welcome(self) -> str | None:
        """None until the person has finished or skipped the welcome page ("done" or "skipped")."""
        value = self.state().get("welcome")
        return value if value in ("done", "skipped") else None

    def set_welcome(self, value: str) -> None:
        self._save(welcome=value)

    def _save(self, **changes: Any) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        data = {**self.state(), **changes}
        self.state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def linked(self, pack: Pack) -> Path | None:
        """The Ollama file this model is linked to, if the link is still good."""
        raw = self.state().get("linked", {}).get(pack.id)
        path = Path(raw) if raw else None
        return path if path and path.is_file() and path.stat().st_size >= ollama.MIN_BYTES else None

    def ollama_copy(self, pack: Pack) -> Path | None:
        """A copy of this chat model that Ollama already stored (never offered for embeddings)."""
        return ollama.find_model(pack.alias) if pack.kind == "model" and pack.alias else None

    def model_path(self, pack: Pack) -> Path:
        return self.linked(pack) or self.root / "models" / pack.filename

    def binary(self) -> Path | None:
        rel = self.state().get("runtime", {}).get("binary")
        path = self.root / "bin" / rel if rel else None
        return path if path and path.is_file() else None

    def installed(self, pack: Pack) -> bool:
        if pack.kind == "runtime":
            return (
                self.binary() is not None and self.state().get("runtime", {}).get("id") == pack.id
            )
        return self.linked(pack) is not None or is_installed(
            self.root / "models" / pack.filename, pack.sha256, pack.size
        )

    # --- what fits ----------------------------------------------------------------------------

    def tiers(self) -> list[dict[str, Any]]:
        avail = usable_gb(self.hw)
        out = []
        for p in self.manifest.models():
            need = needs_gb(p.size)
            out.append({
                "id": p.id, "profile": p.profile, "alias": p.alias, "size": p.size, "note": p.note,
                "needs_gb": round(need, 1), "fits": need <= avail, "installed": self.installed(p),
                "linked": self.linked(p) is not None,
                "ollama": not self.installed(p) and self.ollama_copy(p) is not None,
                "running": bool(self.chat and self.chat.running and self.chat_pack and self.chat_pack.id == p.id),
            })  # fmt: skip
        return out

    def recommended(self) -> str | None:
        return next((t["id"] for t in self.tiers() if t["fits"]), None)

    def runtime(self) -> Pack | None:
        return runtime_pack(self.manifest, self.hw)

    def data_installed(self) -> bool:
        """True once a data bundle has been imported into this data folder."""
        return (self.root.parent / STATE_FILE).is_file()

    def status(self) -> dict[str, Any]:
        rt, emb, data = self.runtime(), self.manifest.embedding(), self.manifest.data()
        st = self.state()
        return {
            "hardware": self.hw.as_dict(),
            "platform": platform_key(self.hw),
            "runtime": {"pack": rt.model_dump() if rt else None, "installed": bool(rt and self.installed(rt))},
            "embedding": {"pack": emb.model_dump() if emb else None, "installed": bool(emb and self.installed(emb))},
            "data": {"pack": data.model_dump() if data else None, "installed": self.data_installed()},
            "tiers": self.tiers(),
            "recommended": self.recommended(),
            "selected": st.get("selected"),
            "welcome": self.welcome(),
            "running": bool(self.chat and self.chat.running),
            "active": self.chat_pack.id if self.chat and self.chat.running and self.chat_pack else None,
            "scanners": self.tools.status(),
            "scanner_plan": self.tools.plan(),
            "hosts": self.manifest.allowed_hosts,
            "manifest_created": self.manifest.created_at,
        }  # fmt: skip

    # --- installing ---------------------------------------------------------------------------

    def _fetch(
        self, pack: Pack, dest: Path, progress: Progress, cancel: threading.Event | None
    ) -> Path:
        client = self._client_factory() if self._client_factory else None
        return download(pack.url, dest, sha256=pack.sha256, size=pack.size,
                        allowed_hosts=self.manifest.allowed_hosts, progress=progress, cancel=cancel,
                        client=client, min_free_gb=1.0)  # fmt: skip

    def fetch_pack(
        self, pack: Pack, progress: Progress, cancel: threading.Event | None = None
    ) -> Path:
        """Download one pack into the downloads folder (resumable, checksum-verified) and return its path."""
        return self._fetch(pack, self.root / "downloads" / pack.filename, progress, cancel)

    def install_runtime(self, progress: Progress, cancel: threading.Event | None = None,
                        say: Report = lambda _m: None) -> None:  # fmt: skip
        pack = self.runtime()
        if pack is None:
            raise RuntimeError_(
                f"there is no AI engine build for this system ({platform_key(self.hw)})"
            )
        if self.installed(pack):
            say("the AI engine is already installed")
            return
        say(f"downloading the AI engine {pack.version} for {pack.platform}")
        archive = self._fetch(pack, self.root / "downloads" / pack.filename, progress, cancel)
        target = self.root / "bin" / pack.id
        say("unpacking")
        extract_archive(archive, target, pack.archive)
        binary = find_binary(target)
        if binary is None:
            raise RuntimeError_("the engine archive does not contain llama-server")
        self._save(
            runtime={
                "id": pack.id,
                "version": pack.version,
                "binary": str(binary.relative_to(self.root / "bin")),
            }
        )
        archive.unlink(missing_ok=True)
        archive.with_name(archive.name + ".ok").unlink(missing_ok=True)

    def install_model(self, pack_id: str, progress: Progress, cancel: threading.Event | None = None,
                      say: Report = lambda _m: None) -> None:  # fmt: skip
        try:
            pack = self.manifest.pack(pack_id)
        except KeyError:
            raise RuntimeError_(f"unknown model {pack_id!r}") from None
        if pack.kind not in ("model", "embedding"):
            raise RuntimeError_(f"{pack_id!r} is not a model")
        if self.installed(pack):
            say(f"{pack.alias or pack.id} is already installed")
        elif self.ollama_copy(pack) is not None:  # reuse before downloading
            say(f"{pack.alias} is already stored by Ollama on this machine")
            self.link_ollama(pack.id, say)
        else:
            say(
                f"{pack.alias or pack.id} was not found in Ollama; downloading it ({pack.size / 1e9:.1f} GB)"
            )
            self._fetch(pack, self.model_path(pack), progress, cancel)
        if pack.kind == "model":
            self._save(selected=pack.id)

    def link_ollama(self, pack_id: str, say: Report = lambda _m: None) -> None:
        """Use the model file Ollama already has instead of downloading one. Nothing is copied."""
        try:
            pack = self.manifest.pack(pack_id)
        except KeyError:
            raise RuntimeError_(f"unknown model {pack_id!r}") from None
        path = self.ollama_copy(pack)
        if path is None:
            raise RuntimeError_(f"Ollama does not have {pack.alias} stored on this machine")
        linked = dict(self.state().get("linked", {}))
        linked[pack.id] = str(path)
        self._save(linked=linked, selected=pack.id)
        say(
            f"using Ollama's copy of {pack.alias} ({path.stat().st_size / 1e9:.1f} GB), nothing was downloaded or copied"
        )

    def remove_model(self, pack_id: str) -> None:
        pack = self.manifest.pack(pack_id)
        if self.chat and self.chat_pack and self.chat_pack.id == pack.id:
            self.stop_chat()
        if self.linked(pack) is not None or pack.id in self.state().get("linked", {}):
            linked = {k: v for k, v in self.state().get("linked", {}).items() if k != pack.id}
            self._save(linked=linked)  # only the link goes: the file belongs to Ollama
            return
        path = self.root / "models" / pack.filename
        for p in (path, path.with_name(path.name + ".ok"), path.with_name(path.name + ".part")):
            p.unlink(missing_ok=True)

    # --- running ------------------------------------------------------------------------------

    def _server(self, pack: Pack, *, embedding: bool, context: int) -> LlamaServer:
        binary = self.binary()
        if binary is None:
            raise RuntimeError_("the AI engine is not installed yet")
        if not self.installed(pack):
            raise RuntimeError_(f"{pack.alias or pack.id} is not downloaded yet")
        name = "embed" if embedding else "chat"
        return LlamaServer(binary, self.model_path(pack), pack.alias or pack.id,
                           log=self.root / "logs" / f"{name}.log", context=context, embedding=embedding)  # fmt: skip

    def start_chat(self, pack_id: str | None = None, context: int | None = None) -> None:
        with self._lock:
            pack = self.manifest.pack(
                pack_id or self.state().get("selected") or self.recommended() or ""
            )
            if self.chat and self.chat.running and self.chat_pack and self.chat_pack.id == pack.id:
                return
            self.stop_chat()
            server = self._server(
                pack, embedding=False, context=context or pack.context_tokens or 16384
            )
            try:
                server.start()
            except ServerError as exc:
                raise RuntimeError_(str(exc)) from exc
            self.chat, self.chat_pack = server, pack
            self._save(selected=pack.id)
            self._sync()

    def stop_chat(self) -> None:
        with self._lock:
            if self.chat:
                self.chat.stop()
            self.chat = self.chat_pack = None
            self._sync()

    def start_embedding(self) -> None:
        with self._lock:
            emb = self.manifest.embedding()
            if emb is None:
                raise RuntimeError_("this build has no embedding model")
            if self.embed and self.embed.running:
                return
            server = self._server(emb, embedding=True, context=EMBED_CONTEXT)
            try:
                server.start(timeout_s=120)
            except ServerError as exc:
                raise RuntimeError_(str(exc)) from exc
            self.embed = server
            self._sync()

    def stop_embedding(self) -> None:
        with self._lock:
            if self.embed:
                self.embed.stop()
            self.embed = None
            self._sync()

    def stop(self) -> None:
        self.stop_chat()
        self.stop_embedding()

    # --- wiring into the scan configuration -----------------------------------------------------

    def managed(self) -> bool:
        """True once the wizard has installed an engine and a model: scans then use it."""
        return self.binary() is not None and self.state().get("selected") is not None

    def apply(self, cfg: Config) -> None:
        """Point `cfg` at the running managed servers."""
        if (self.chat and self.chat.running) or (self.embed and self.embed.running):
            cfg.llm.backend = "openai"
        if self.chat and self.chat.running and self.chat_pack:
            cfg.llm.endpoint = self.chat.endpoint
            cfg.llm.model = self.chat_pack.alias or self.chat_pack.id
        if self.embed and self.embed.running:
            cfg.llm.embedding_endpoint = self.embed.endpoint

    def prepare(self, cfg: Config) -> None:
        """Before an AI review: make sure the model this run asks for is the one being served."""
        if not self.managed():
            return
        wanted = next(
            (p for p in self.manifest.models() if p.alias == cfg.llm.model and self.installed(p)),
            None,
        )
        if wanted is None:
            wanted = self.chat_pack or next(
                (p for p in self.manifest.models() if self.installed(p)), None
            )
        if wanted is None:
            return
        self.start_chat(wanted.id)
        self.apply(cfg)


def first_run_plan(status: dict[str, Any]) -> list[dict[str, Any]]:
    """What a first-time setup would do on this machine, in order, with sizes (None: size not known up front)."""
    steps: list[dict[str, Any]] = []
    rt = status["runtime"]
    if rt["pack"] is not None:
        steps.append(
            {
                "step": "engine",
                "label": "AI engine",
                "size": rt["pack"]["size"],
                "done": rt["installed"],
                "optional": False,
            }
        )
    tier = next(
        (t for t in status["tiers"] if t["id"] == (status["selected"] or status["recommended"])),
        None,
    )
    if tier is not None and tier["fits"]:
        size = 0 if (tier["installed"] or tier["ollama"]) else tier["size"]
        note = (
            "found in Ollama, nothing to download"
            if tier["ollama"] and not tier["installed"]
            else ""
        )
        steps.append(
            {
                "step": "model",
                "pack": tier["id"],
                "label": f"AI model {tier['alias']}",
                "size": size,
                "done": tier["installed"],
                "note": note,
                "optional": False,
            }
        )
        emb = status["embedding"]
        if emb["pack"] is not None:
            steps.append(
                {
                    "step": "embedding",
                    "label": "Knowledge-base model",
                    "size": emb["pack"]["size"],
                    "done": emb["installed"],
                    "optional": False,
                }
            )
    plan = status["scanner_plan"]
    steps.append({"step": "scanners", "label": "Scanners", "size": plan["size"], "done": not plan["missing"] or plan["size"] == 0, "optional": False,
                  "note": ", ".join(plan["unavailable"]) + " not offered for this system" if plan["unavailable"] else ""})  # fmt: skip
    data = status["data"]
    steps.append(
        {
            "step": "data",
            "label": "Security data (vulnerability databases, advisories)",
            "size": data["pack"]["size"] if data["pack"] else None,
            "done": data["installed"],
            "optional": True,
        }
    )
    return steps
