"""What this machine can run: operating system, memory, free disk and GPU. Reads local facts only."""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Share of memory a model can really use: unified memory on Apple silicon is capped by the OS, and a
# CPU-only run must leave room for the system and the scanners.
METAL_SHARE = 0.75
CPU_SHARE = 0.6
OVERHEAD = 1.15  # weights plus the context cache


@dataclass(frozen=True)
class Hardware:
    os: str  # macos | linux | windows
    arch: str  # arm64 | x64
    ram_gb: float
    disk_free_gb: float
    gpu: str  # metal | nvidia | none
    gpu_name: str = ""
    vram_gb: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "usable_gb": round(usable_gb(self), 1)}


def _ram_gb() -> float:
    if sys.platform == "win32":

        class Status(ctypes.Structure):
            _fields_ = [  # noqa: RUF012 - ctypes layout
                ("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
                ("total", ctypes.c_ulonglong), ("avail", ctypes.c_ulonglong),
                ("ptotal", ctypes.c_ulonglong), ("pavail", ctypes.c_ulonglong),
                ("vtotal", ctypes.c_ulonglong), ("vavail", ctypes.c_ulonglong),
                ("ext", ctypes.c_ulonglong),
            ]  # fmt: skip

        s = Status()
        s.length = ctypes.sizeof(Status)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s))  # type: ignore[attr-defined]
        return s.total / 1e9
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9
    except (ValueError, OSError, AttributeError):
        return 0.0


def _nvidia() -> tuple[str, float]:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return "", 0.0
    try:
        out = subprocess.run(  # noqa: S603 - fixed arguments, a local hardware query
            [exe, "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.splitlines()  # fmt: skip
        name, mib = (p.strip() for p in out[0].rsplit(",", 1))
        return name, float(mib) * 1.048576 / 1000
    except (subprocess.SubprocessError, OSError, ValueError, IndexError):
        return "", 0.0


def detect(path: Path | str = ".") -> Hardware:
    system = {"darwin": "macos", "win32": "windows"}.get(sys.platform, "linux")
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    target = Path(path)
    while not target.exists() and target != target.parent:
        target = target.parent
    free = shutil.disk_usage(target).free / 1e9
    gpu, name, vram = "none", "", 0.0
    if system == "macos" and arch == "arm64":
        gpu, name = "metal", "Apple silicon"
    else:
        n, v = _nvidia()
        if n:
            gpu, name, vram = "nvidia", n, v
    return Hardware(system, arch, round(_ram_gb(), 1), round(free, 1), gpu, name, round(vram, 1))


def usable_gb(hw: Hardware) -> float:
    """Memory a model can use. With an NVIDIA card the layers that fit go there and the rest stay in RAM."""
    if hw.gpu == "metal":
        return hw.ram_gb * METAL_SHARE
    if hw.gpu == "nvidia":
        return hw.vram_gb + hw.ram_gb * 0.4
    return hw.ram_gb * CPU_SHARE


def needs_gb(size_bytes: int) -> float:
    return size_bytes / 1e9 * OVERHEAD
