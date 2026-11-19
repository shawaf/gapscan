"""The local app's link to a team workspace: send a finished run there as a signed "local run".

This is the only code in the manager that talks to a team server, and only when a person asks:
saving the connection checks it (`GET /api/v1/me`), the project picker lists the workspace's
projects, and "Send to workspace" posts one signed report (`POST .../imports`). It never runs
during a scan (hard rule 2), never follows a redirect, and talks only to the address saved here.

The address and the chosen workspace project of each local project are saved in the manager's
settings. The token is saved in its own file in the data folder, readable by its owner only, and
is never sent back to the browser or written to a log.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..models import ScanResult
from ..services import InvalidInput, NotReady
from ..signing import KEY_FILE, create_key, fingerprint, load_key, public_key_text, sign_report

TOKEN_FILE = "workspace-token"
_PROJECT_ID = re.compile(r"^[0-9a-f]{1,64}$")
TIMEOUT_S = 30


def check_url(raw: str) -> str:
    """The team server's base URL, or why it is refused. HTTPS, except on this machine or a
    private network address, because the token travels with every request."""
    url = raw.strip().rstrip("/")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise InvalidInput("give the team server's address, e.g. https://gapscan.example.internal")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise InvalidInput("the address must not carry a user name, password, query or fragment")
    if parts.scheme == "http" and not _local_or_private(parts.hostname):
        raise InvalidInput("use https: the token would cross the network unencrypted")
    return url


def _local_or_private(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


class Workspace:
    """The saved connection, the install key, and the three calls to the team server."""

    def __init__(self, data_dir: Path, url: str = "") -> None:
        self.data_dir, self.url = data_dir, url

    # --- local state ---

    @property
    def token_path(self) -> Path:
        return self.data_dir / TOKEN_FILE

    def token(self) -> str:
        try:
            return self.token_path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def save_token(self, token: str) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.token_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token)
        os.replace(tmp, self.token_path)

    def forget(self) -> None:
        self.token_path.unlink(missing_ok=True)

    def key(self) -> dict[str, str] | None:
        path = self.data_dir / KEY_FILE
        if not path.is_file():
            return None
        public = public_key_text(load_key(path))
        return {"public_key": public, "fingerprint": fingerprint(public)}

    def create_key(self) -> dict[str, str]:
        """This install's signing key, made once (kept in the data folder)."""
        if self.key() is None:
            create_key(self.data_dir / KEY_FILE)
        key = self.key()
        assert key is not None
        return key

    # --- the team server ---

    def _call(self, method: str, path: str, *, token: str | None = None,
              content: bytes | None = None) -> Any:  # fmt: skip
        if not self.url:
            raise NotReady("connect to a team workspace first (Settings)")
        secret = token if token is not None else self.token()
        if not secret:
            raise NotReady("save a token for the team workspace first (Settings)")
        try:
            resp = httpx.request(method, f"{self.url}{path}", content=content, timeout=TIMEOUT_S,
                                 follow_redirects=False,
                                 headers={"Authorization": f"Bearer {secret}",
                                          "Content-Type": "application/json"})  # fmt: skip
        except httpx.HTTPError as exc:
            raise InvalidInput(f"could not reach the team server at {self.url}: {exc}") from exc
        try:
            data = resp.json()
        except ValueError:
            data = None
        if resp.status_code >= 300:
            reason = data.get("error") if isinstance(data, dict) else ""
            raise InvalidInput(f"the team server answered {resp.status_code}"
                               + (f": {reason}" if reason else ""))  # fmt: skip
        return data

    def check(self, token: str) -> dict[str, Any]:
        """Who this token is on the team server; raises if it does not work there."""
        me = self._call("GET", "/api/v1/me", token=token)
        if not isinstance(me, dict) or "workspace_id" not in me:
            raise InvalidInput("that address did not answer like a GapScan Platform server")
        return {k: me.get(k) for k in ("name", "role", "workspace_id")}

    def projects(self) -> list[dict[str, Any]]:
        rows = self._call("GET", "/api/v1/projects")
        return [{"id": p["id"], "name": p["name"], "team_id": p.get("team_id")}
                for p in rows if isinstance(p, dict)]  # fmt: skip

    def send(self, scan: ScanResult, project_id: str) -> dict[str, Any]:
        """Sign the run with this install's key and import it as a "local run"."""
        if not _PROJECT_ID.match(project_id):
            raise InvalidInput("pick a project of the workspace")
        if not self.url or not self.token():
            raise NotReady("connect to a team workspace first (Settings)")
        path = self.data_dir / KEY_FILE
        if not path.is_file():
            raise NotReady("create this install's key first and have an admin register it")
        signed = sign_report(scan, project_id, load_key(path))
        result: dict[str, Any] = self._call("POST", f"/api/v1/projects/{project_id}/imports",
                                            content=signed.model_dump_json().encode())  # fmt: skip
        return result
