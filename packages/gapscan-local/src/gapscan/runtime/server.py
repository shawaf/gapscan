"""A supervised local `llama-server`: started on a free loopback port, never reachable from the network,
stopped with the manager. One process serves one model; the small embedding model gets its own."""

from __future__ import annotations

import contextlib
import socket
import subprocess
import time
from pathlib import Path

import httpx


class ServerError(RuntimeError):
    pass


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class LlamaServer:
    def __init__(self, binary: Path, model: Path, alias: str, *, log: Path, context: int = 16384,
                 embedding: bool = False, gpu_layers: int = 99) -> None:  # fmt: skip
        # Absolute paths: the engine is started from its own folder (cwd), so a relative path such
        # as data/runtime/bin/... would no longer resolve there.
        self.binary, self.model = binary.absolute(), model.absolute()
        self.alias, self.log = alias, log.absolute()
        self.context, self.embedding, self.gpu_layers = context, embedding, gpu_layers
        self.port = 0
        self._proc: subprocess.Popen[bytes] | None = None

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def command(self) -> list[str]:
        cmd = [
            str(self.binary), "-m", str(self.model), "--host", "127.0.0.1", "--port", str(self.port),
            "--alias", self.alias, "-c", str(self.context), "-ngl", str(self.gpu_layers),
            "-np", "1", "--no-webui",
        ]  # fmt: skip
        return [*cmd, "--embeddings"] if self.embedding else cmd

    def ready_timeout(self) -> float:
        """Loading time grows with the model file and the machine: 2 minutes plus 1 per GB (a 9 GB
        model took 48 s on one 4-core machine and 295 s on another). A crash is still noticed at once."""
        try:
            gb = self.model.stat().st_size / 1e9
        except OSError:
            gb = 0.0
        return 120.0 + 60.0 * gb

    def start(self, timeout_s: float | None = None) -> None:
        if self.running:
            return
        timeout_s = timeout_s if timeout_s is not None else self.ready_timeout()
        self.port = free_port()
        self.log.parent.mkdir(parents=True, exist_ok=True)
        with self.log.open("ab") as out:
            self._proc = subprocess.Popen(  # noqa: S603 - our own pinned binary, argument list
                self.command(), stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                cwd=self.binary.parent,
            )  # fmt: skip
        self._wait_ready(timeout_s)

    def _wait_ready(self, timeout_s: float) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self._proc is None or self._proc.poll() is not None:
                raise ServerError("the AI engine stopped while starting. " + self.tail())
            with contextlib.suppress(httpx.HTTPError):
                if httpx.get(f"{self.endpoint}/health", timeout=2).status_code == 200:
                    return
            time.sleep(0.3)
        self.stop()
        raise ServerError(
            f"the AI engine did not become ready within {int(timeout_s)} s. " + self.tail()
        )

    def tail(self, lines: int = 6) -> str:
        try:
            text = self.log.read_text(errors="replace").strip().splitlines()[-lines:]
        except OSError:
            return ""
        return "Last log lines: " + " | ".join(text) if text else ""

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
