"""The scanners GapScan runs, and how they get onto this machine.

Hybrid delivery: the small Go programs (Gitleaks, OSV-Scanner) ship inside the installer; the larger or faster
changing ones (Trivy, and Semgrep, Checkov and Bandit on a pinned Python) are downloaded once by the setup
wizard from the pinned manifest. Every scanner is found through the PATH, so installing one is only a matter
of putting its folder on the PATH of this process (managed copies come first, so the pinned version wins)."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .download import (
    DownloadError,
    Progress,
    download,
    extract_archive,
    is_installed,
)
from .hardware import Hardware
from .manifest import Manifest, Pack, scanner_platform

Report = Callable[[str], None]
SCANNERS = ("semgrep", "osv-scanner", "trivy", "gitleaks", "checkov", "bandit")
EXE = ".exe" if sys.platform == "win32" else ""


def bundled_dir() -> Path | None:
    """The folder of programs shipped inside the packaged app, if this is the packaged app."""
    base = getattr(sys, "_MEIPASS", None)
    path = Path(base) / "tools" if base else None
    return path if path and path.is_dir() else None


def pack_bin(base: Path) -> list[Path]:
    return [base / "bin"] if (base / "bin").is_dir() else [base] if base.is_dir() else []


def managed_dirs(runtime_root: Path) -> list[Path]:
    """Folders in front of the PATH: bundled programs first, then the ones the wizard installed."""
    found: list[Path] = []
    if (b := bundled_dir()) is not None:
        found.append(b)
    tools = runtime_root / "tools"
    if tools.is_dir():
        for pack in sorted(tools.iterdir()):
            if (pack / ".installed").is_file():
                found += pack_bin(pack)
    return found


def activate(runtime_root: Path) -> None:
    """Put the managed folders on this process's PATH (idempotent). Managed copies win over the system's."""
    current = os.environ.get("PATH", "").split(os.pathsep)
    extra = [str(d) for d in managed_dirs(runtime_root) if str(d) not in current]
    if extra:
        os.environ["PATH"] = os.pathsep.join([*extra, *current])


def executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


class Overall:
    """Turns several downloads into one progress bar."""

    def __init__(self, progress: Progress, total: int) -> None:
        self.progress, self.total, self.done = progress, total, 0

    def sub(self) -> Progress:
        base = self.done
        return lambda d, _t: self.progress(min(base + d, self.total), self.total)

    def add(self, size: int) -> None:
        self.done += size
        self.progress(min(self.done, self.total), self.total)


class ToolManager:
    def __init__(self, root: Path, manifest: Manifest, hw: Hardware,
                 client_factory: Callable[[], Any] | None = None) -> None:  # fmt: skip
        self.root, self.manifest, self.hw = root / "tools", manifest, hw
        self._client_factory = client_factory
        self.platform = scanner_platform(hw)

    # --- what the manifest offers for this machine ------------------------------------------------

    def packs(self) -> list[Pack]:
        return [
            p for p in self.manifest.packs if p.kind == "scanner" and p.platform == self.platform
        ]

    def python_pack(self) -> Pack | None:
        return next(
            (p for p in self.manifest.packs if p.kind == "python" and p.platform == self.platform),
            None,
        )

    def wheels(self) -> list[Any]:
        return self.manifest.wheels.get(self.platform, [])

    def python_available(self) -> bool:
        return (
            self.python_pack() is not None and bool(self.wheels()) and bool(self.manifest.launchers)
        )

    # --- where installed programs are --------------------------------------------------------------

    def _marker(self, pack_id: str) -> Path:
        return self.root / pack_id / ".installed"

    def dirs(self) -> list[Path]:
        return managed_dirs(self.root.parent)

    def activate(self) -> None:
        activate(self.root.parent)

    def where(self, name: str) -> tuple[str, str]:
        """(how it is provided, path): bundled, managed, path (the system's own) or missing."""
        for label, folder in [("bundled", bundled_dir()), *[("managed", d) for d in self.dirs()]]:
            if folder and executable(folder / (name + EXE)):
                return label, str(folder / (name + EXE))
        found = shutil.which(name)
        return ("path", found) if found else ("missing", "")

    def status(self) -> list[dict[str, Any]]:
        out = []
        for name in SCANNERS:
            how, path = self.where(name)
            out.append({"name": name, "via": how, "path": path})
        return out

    def missing(self) -> list[str]:
        return [s["name"] for s in self.status() if s["via"] == "missing"]

    # --- installing ---------------------------------------------------------------------------------

    def _fetch(self, url: str, dest: Path, sha256: str, size: int, progress: Progress,
               cancel: threading.Event | None) -> Path:  # fmt: skip
        client = self._client_factory() if self._client_factory else None
        return download(url, dest, sha256=sha256, size=size, allowed_hosts=self.manifest.allowed_hosts,
                        progress=progress, cancel=cancel, client=client, min_free_gb=1.0)  # fmt: skip

    def plan(self) -> dict[str, Any]:
        """What installing would download: the packs for scanners that are missing, and their total size."""
        missing = set(self.missing())
        packs = [p for p in self.packs() if missing & set(p.provides)]
        python = (
            []
            if not (missing & set(self.manifest.launchers))
            else ([self.python_pack()] if self.python_available() else [])
        )
        python_size = sum(p.size for p in python if p) + (
            sum(w.size for w in self.wheels()) if python else 0
        )
        return {"missing": sorted(missing), "packs": [p.id for p in packs],
                "python": bool(python), "size": sum(p.size for p in packs) + python_size,
                "unavailable": sorted(m for m in missing if not (any(m in p.provides for p in packs) or (python and m in self.manifest.launchers)))}  # fmt: skip

    def install(
        self,
        progress: Progress,
        cancel: threading.Event | None = None,
        say: Report = lambda _m: None,
    ) -> None:
        plan = self.plan()
        if not plan["packs"] and not plan["python"]:
            say(
                "every scanner is already available"
                if not plan["missing"]
                else "this build has nothing to install for: " + ", ".join(plan["missing"])
            )
            return
        overall = Overall(progress, plan["size"])
        for pack in (p for p in self.packs() if p.id in plan["packs"]):
            say(f"downloading {', '.join(pack.provides)} {pack.version} ({pack.size / 1e6:.0f} MB)")
            self._install_scanner(pack, overall.sub(), cancel)
            overall.add(pack.size)
        if plan["python"]:
            self._install_python(overall, cancel, say)
        progress(plan["size"], plan["size"])

    def _install_scanner(
        self, pack: Pack, progress: Progress, cancel: threading.Event | None
    ) -> None:
        archive = self._fetch(
            pack.url,
            self.root / "downloads" / pack.filename,
            pack.sha256,
            pack.size,
            progress,
            cancel,
        )
        target = self.root / pack.id
        shutil.rmtree(target, ignore_errors=True)
        if pack.archive:
            extract_archive(archive, target, pack.archive)
            self._expose(target, pack.provides)
        else:  # a single program, not an archive
            (target / "bin").mkdir(parents=True, exist_ok=True)
            dest = target / "bin" / ((pack.binary or pack.provides[0]) + EXE)
            shutil.copy2(archive, dest)
            dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self._marker(pack.id).parent.mkdir(parents=True, exist_ok=True)
        self._marker(pack.id).write_text(f"{pack.sha256}\n")
        archive.unlink(missing_ok=True)
        archive.with_name(archive.name + ".ok").unlink(missing_ok=True)

    def _expose(self, target: Path, names: list[str]) -> None:
        """Make sure the named programs sit in `bin/` and are executable (archives differ in layout)."""
        (target / "bin").mkdir(exist_ok=True)
        for name in names:
            hits = [p for p in sorted(target.rglob(name + EXE)) if p.is_file()]
            if not hits:
                raise DownloadError(f"the archive does not contain {name}")
            src = hits[0]
            dest = target / "bin" / (name + EXE)
            if src != dest:
                shutil.move(str(src), dest)
            dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _install_python(
        self, overall: Overall, cancel: threading.Event | None, say: Report
    ) -> None:
        pack, wheels = self.python_pack(), self.wheels()
        assert pack is not None
        target = self.root / "python-tools"
        shutil.rmtree(target, ignore_errors=True)
        say(f"downloading Python {pack.version} ({pack.size / 1e6:.0f} MB)")
        archive = self._fetch(
            pack.url,
            self.root / "downloads" / pack.filename,
            pack.sha256,
            pack.size,
            overall.sub(),
            cancel,
        )
        extract_archive(archive, target, pack.archive or "tar.gz")
        archive.unlink(missing_ok=True)
        archive.with_name(archive.name + ".ok").unlink(missing_ok=True)
        overall.add(pack.size)
        say(
            f"downloading {len(wheels)} Python packages ({sum(w.size for w in wheels) / 1e6:.0f} MB)"
        )
        wheel_dir = self.root / "downloads" / "wheels"
        for w in wheels:
            self._fetch(w.url, wheel_dir / w.filename, w.sha256, w.size, overall.sub(), cancel)
            overall.add(w.size)
        python = self._python_exe(target)
        say("installing the packages offline from the verified files")
        env = {
            **os.environ,
            "PYTHONNOUSERSITE": "1",
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        proc = subprocess.run(  # noqa: S603 - our own pinned interpreter, fixed arguments
            [str(python), "-m", "pip", "install", "--no-index", "--no-deps", "--no-compile", "--quiet", "--target", str(target / "site-packages"),
             *[str(wheel_dir / w.filename) for w in wheels]],
            capture_output=True, text=True, timeout=1800, env=env, check=False,
        )  # fmt: skip
        if proc.returncode != 0:
            raise DownloadError(
                "installing the Python packages failed: " + (proc.stderr or proc.stdout)[-400:]
            )
        self._write_launchers(target, python)
        self._marker("python-tools").write_text(f"{pack.sha256}\n")
        shutil.rmtree(wheel_dir, ignore_errors=True)

    def _python_exe(self, target: Path) -> Path:
        for rel in ("python/bin/python3", "python/python.exe", "bin/python3"):
            if (target / rel).is_file():
                return target / rel
        raise DownloadError("the Python archive does not contain an interpreter")

    def _write_launchers(self, target: Path, python: Path) -> None:
        """One small script per scanner that runs it on the pinned interpreter. (pip's own scripts hold the
        absolute path of the folder they were installed in, which would break if the app folder moves.)"""
        bin_dir = target / "bin"
        bin_dir.mkdir(exist_ok=True)
        rel = os.path.relpath(python, bin_dir)
        for name, spec in self.manifest.launchers.items():
            # "pkg.module" runs `python -m pkg.module`; "pkg.module:function" calls that function (a console script)
            if ":" in spec:
                mod, func = spec.split(":", 1)
                module = f'-c "import sys; from {mod} import {func}; sys.exit({func}())"'
            else:
                module = f"-m {spec}"
            if sys.platform == "win32":
                (bin_dir / f"{name}.cmd").write_text(
                    "@echo off\r\nset PYTHONNOUSERSITE=1\r\nset PYTHONPATH=%~dp0..\\site-packages\r\n"
                    f'"%~dp0{rel}" {module} %*\r\n'
                )
            else:
                script = bin_dir / name
                script.write_text(
                    '#!/bin/sh\nd="${0%/*}"\nexport PYTHONNOUSERSITE=1\nexport PYTHONPATH="$d/../site-packages"\n'
                    f'exec "$d/{rel}" {module} "$@"\n'
                )
                script.chmod(0o755)

    def installed_packs(self) -> list[str]:
        return [
            p.name
            for p in (self.root.iterdir() if self.root.is_dir() else [])
            if self._marker(p.name).is_file()
        ]

    def is_pack_installed(self, pack: Pack) -> bool:
        return (
            is_installed(self.root / "downloads" / pack.filename, pack.sha256, pack.size)
            or self._marker(pack.id).is_file()
        )
