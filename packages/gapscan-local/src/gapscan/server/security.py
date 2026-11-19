"""Security for the local management server.

The server can start scans of local folders and read their findings, so a web page the user happens
to visit must never be able to drive it. Defenses, all enforced before any route runs:

* it binds to loopback only (`require_loopback`);
* DNS rebinding: the Host header must be this server's own loopback address;
* a random per-launch token, sent by the browser as an HttpOnly SameSite=Strict cookie, is required
  for the whole API (compared in constant time);
* CSRF: state-changing requests must be same-origin JSON (Origin header equal to the server's origin,
  Content-Type application/json), which a cross-site form or fetch cannot produce;
* strict response headers (nosniff, no referrer, no caching) and a CSP on every page.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
from http.cookies import SimpleCookie

COOKIE = "gapscan_session"
MAX_BODY = 1_000_000
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "[::1]", "::1"}

CSP_APP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
    "connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
)
CSP_REPORT = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
)
BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Frame-Options": "SAMEORIGIN",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class Forbidden(Exception):
    def __init__(self, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.status = status


def new_token() -> str:
    return secrets.token_urlsafe(24)


def require_loopback(host: str) -> None:
    if host in LOOPBACK_NAMES:
        return
    try:
        if ipaddress.ip_address(host.strip("[]")).is_loopback:
            return
    except ValueError:
        pass
    raise ValueError(
        f"refusing to listen on {host!r}: the management server only accepts loopback addresses"
    )


def split_host(header: str) -> tuple[str, str]:
    """ "127.0.0.1:8765" -> ("127.0.0.1", "8765"); "[::1]:8765" -> ("[::1]", "8765"); no port -> ""."""
    h = header.strip().lower()
    if h.startswith("["):
        end = h.find("]")
        if end == -1:
            return h, ""
        rest = h[end + 1 :]
        return h[: end + 1], rest[1:] if rest.startswith(":") else ""
    if h.count(":") == 1:
        name, port = h.split(":")
        return name, port
    return h, ""


def check_host(host_header: str | None, port: int) -> None:
    """Reject requests whose Host is not our own loopback address (DNS rebinding)."""
    name, p = split_host(host_header or "")
    if name not in LOOPBACK_NAMES or (p and p != str(port)):
        raise Forbidden("unexpected Host header", 421)


def check_token(cookie_header: str | None, auth_header: str | None, token: str) -> None:
    supplied = ""
    if auth_header and auth_header.startswith("Bearer "):
        supplied = auth_header[7:]
    elif cookie_header:
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(cookie_header)
        except Exception:  # noqa: BLE001 - a malformed cookie is simply "no token"
            jar = SimpleCookie()
        if COOKIE in jar:
            supplied = jar[COOKIE].value
    if not supplied or not hmac.compare_digest(supplied.encode(), token.encode()):
        raise Forbidden("missing or invalid session", 401)


def check_csrf(method: str, origin: str | None, content_type: str | None, port: int) -> None:
    """State-changing requests must be same-origin JSON."""
    if method in ("GET", "HEAD", "OPTIONS"):
        return
    allowed = {f"http://127.0.0.1:{port}", f"http://localhost:{port}", f"http://[::1]:{port}"}
    if origin not in allowed:
        raise Forbidden("cross-origin request refused")
    if not (content_type or "").lower().startswith("application/json"):
        raise Forbidden("state-changing requests must be application/json", 415)


def session_cookie(token: str) -> str:
    return f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/"
