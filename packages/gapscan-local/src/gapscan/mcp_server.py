"""A small MCP (Model Context Protocol) server over stdio, so an AI coding assistant can scan the
code it just wrote before it is committed.

Newline-delimited JSON-RPC 2.0 on stdin/stdout, no extra dependency. Tools are read-only and
confined to the root directory the operator starts the server with (hard rule #3): file paths are
resolved inside the root, snippets are scanned in a temporary directory that is deleted afterwards.
Only the fast scanners run (see `ci.FAST_SCANNERS`), and nothing leaves the machine.

    gapscan mcp --root .
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, TextIO

from .ci import FAST_SCANNERS
from .config import Config
from .core.version import __version__
from .models import Finding
from .pipeline import run_scan

PROTOCOL = "2024-11-05"
EXTENSIONS = {"python": "py", "javascript": "js", "typescript": "ts", "java": "java", "go": "go",
              "kotlin": "kt", "swift": "swift", "dart": "dart", "csharp": "cs", "php": "php"}  # fmt: skip
MAX_SNIPPET = 200_000
MAX_RESULTS = 25

TOOLS: list[dict[str, Any]] = [
    {
        "name": "gapscan_scan_snippet",
        "description": (
            "Scan a piece of code you just wrote for security weaknesses (injection, path "
            "traversal, SSRF, XSS, hard-coded secrets, unsafe deserialization) before committing "
            "it. Offline; nothing leaves the machine."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "language": {"type": "string", "enum": sorted(EXTENSIONS)},
                "code": {"type": "string"},
            },
            "required": ["language", "code"],
        },
    },
    {
        "name": "gapscan_scan_file",
        "description": (
            "Scan the project for security weaknesses and report those in one file, including "
            "data flows that cross into it from other files. Path is relative to the project root."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
]


def _fast(config: Config) -> Config:
    cfg = config.model_copy(deep=True)
    cfg.scanners.enabled = [s for s in config.scanners.enabled if s in FAST_SCANNERS]
    return cfg


def _render(findings: list[Finding]) -> str:
    if not findings:
        return "GapScan found no security issues in scope."
    lines = [f"GapScan found {len(findings)} issue(s):"]
    for f in findings[:MAX_RESULTS]:
        where = f"{f.file}:{f.start_line}" if f.start_line else (f.file or "")
        lines.append(f"- [{f.severity.value}] {where} {f.title} ({f.rule_id})")
        if f.raw.get("taint_path"):
            lines.append("  flow: " + " -> ".join(str(s) for s in f.raw["taint_path"][:6]))
        elif f.message:
            lines.append("  " + " ".join(f.message.split())[:240])
    if len(findings) > MAX_RESULTS:
        lines.append(f"...and {len(findings) - MAX_RESULTS} more.")
    return "\n".join(lines)


def scan_snippet(config: Config, language: str, code: str) -> str:
    ext = EXTENSIONS.get(language)
    if ext is None:
        raise ValueError(f"unsupported language {language!r}; use one of {sorted(EXTENSIONS)}")
    if len(code) > MAX_SNIPPET:
        raise ValueError("snippet too large")
    with tempfile.TemporaryDirectory(prefix="gapscan-mcp-") as tmp:
        root = Path(tmp)
        (root / f"snippet.{ext}").write_text(code, encoding="utf-8")
        return _render(run_scan(_fast(config), root).findings)


def scan_file(config: Config, root: Path, rel: str) -> str:
    root = root.resolve()
    path = (root / rel).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("path must be a file inside the project root")
    want = str(path.relative_to(root))
    findings = run_scan(_fast(config), root).findings
    mine = [
        f for f in findings
        if f.file == want or any(f":{want}:" in f":{s}" or f" {want}:" in str(s) for s in f.raw.get("taint_path", []))
    ]  # fmt: skip
    return _render(mine)


def handle(config: Config, root: Path, msg: dict[str, Any]) -> dict[str, Any] | None:
    """One JSON-RPC message in, the response out (None for notifications)."""
    mid, method = msg.get("id"), msg.get("method", "")
    params = msg.get("params") or {}

    def ok(result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def err(code: int, text: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": text}}

    if mid is None:  # a notification (e.g. notifications/initialized): no answer
        return None
    if method == "initialize":
        return ok({
            "protocolVersion": params.get("protocolVersion", PROTOCOL),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "gapscan", "version": __version__},
        })  # fmt: skip
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        try:
            if name == "gapscan_scan_snippet":
                text = scan_snippet(
                    config, str(args.get("language", "")), str(args.get("code", ""))
                )
            elif name == "gapscan_scan_file":
                text = scan_file(config, root, str(args.get("path", "")))
            else:
                return err(-32602, f"unknown tool {name!r}")
        except ValueError as exc:
            return ok({"content": [{"type": "text", "text": str(exc)}], "isError": True})
        return ok({"content": [{"type": "text", "text": text}], "isError": False})
    return err(-32601, f"method not found: {method}")


def serve(
    config: Config, root: Path, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout
) -> None:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            if not isinstance(msg, dict):
                raise ValueError("not an object")
        except ValueError:
            stdout.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "parse error"},
                    }
                )
                + "\n"
            )
            stdout.flush()
            continue
        resp = handle(config, root, msg)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
