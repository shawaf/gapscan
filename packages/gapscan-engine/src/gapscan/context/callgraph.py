"""Lightweight caller lookup: grep for the symbol name, then confirm with tree-sitter that
the match is a real call expression. No type resolution (documented limitation)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..models import Caller
from .treesitter import (
    calls,
    class_ranges,
    detect_language,
    enclosing_function,
    family,
    functions,
    imports,
    parse,
)

SKIP_DIRS = {".git", "node_modules", "vendor", "third_party", "Pods", "Carthage", "build", "dist",
             ".dart_tool", ".venv", "venv", "__pycache__", ".gradle", ".idea"}  # fmt: skip
MAX_FILE_BYTES = 1_000_000
MAX_FILES_CONFIRMED = 300
_TEST_HINT = re.compile(
    r"(^|/)(tests?|__tests__|spec|androidTest)/|_test\.|\.test\.|\.spec\.|Tests?\."
)


def _candidate_files(target: Path, language: str) -> list[str]:
    fam = family(language)
    found: list[str] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            full = Path(root) / name
            lang = detect_language(name)
            if lang and family(lang) == fam:
                found.append(str(full.relative_to(target)))
    return sorted(found)


def find_callers(
    target: Path,
    symbol: str,
    language: str,
    defined_in: str,
    max_callers: int = 3,
    exclude_lines: tuple[int, int] | None = None,
) -> list[Caller]:
    """Up to `max_callers` call sites of `symbol`. Same-file and non-test callers come first.
    `exclude_lines` skips the function's own body so recursion is not reported."""
    if not symbol or symbol.startswith("<"):
        return []
    word = re.compile(rf"(?<![\w$]){re.escape(symbol)}(?![\w$])")
    files = _candidate_files(target, language)
    files.sort(key=lambda f: (f != defined_in, bool(_TEST_HINT.search(f)), f))
    callers: list[Caller] = []
    confirmed = 0
    for rel in files:
        path = target / rel
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            source = path.read_bytes()
        except OSError:
            continue
        if not word.search(source.decode("utf-8", "replace")):
            continue
        confirmed += 1
        if confirmed > MAX_FILES_CONFIRMED:
            break
        pf = parse(rel, source, detect_language(rel))
        if pf is None:
            continue
        for site in calls(pf):
            if site.name != symbol:
                continue
            if (
                rel == defined_in
                and exclude_lines
                and exclude_lines[0] <= site.line <= exclude_lines[1]
            ):
                continue
            fn = enclosing_function(pf, site.line)
            callers.append(
                Caller(
                    file=rel,
                    line=site.line,
                    function=fn.qualified_name if fn else None,
                    snippet=site.text[:200],
                )
            )
            if len(callers) >= max_callers:
                return callers
    return callers


# PyPI distribution name -> the module name(s) code imports. Only the common mismatches.
IMPORT_ALIASES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",), "pillow": ("PIL",), "beautifulsoup4": ("bs4",),
    "scikit-learn": ("sklearn",), "python-dateutil": ("dateutil",), "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",), "protobuf": ("google.protobuf",),
    "pycryptodome": ("Crypto",), "pycryptodomex": ("Cryptodome",), "pyjwt": ("jwt",),
    "python-jose": ("jose",), "attrs": ("attr",),
    "mysqlclient": ("MySQLdb",), "psycopg2-binary": ("psycopg2",), "gitpython": ("git",),
    "pyopenssl": ("OpenSSL",), "pyserial": ("serial",), "setuptools": ("pkg_resources",),
    "python-magic": ("magic",), "msgpack-python": ("msgpack",), "pymongo": ("bson",),
    "ruamel.yaml": ("ruamel",), "google-cloud-storage": ("google.cloud",),
    "python-multipart": ("multipart",), "pycurl": ("pycurl",), "pyzmq": ("zmq",),
}  # fmt: skip


def _name_variants(package: str) -> set[str]:
    """Spellings a package may take in source: pip names use '-' but modules use '_', Maven
    uses group:artifact, Go uses a module path, scoped npm names keep their scope."""
    base = package.lower()
    variants = {base, base.replace("-", "_"), base.replace("-", "")}
    variants |= {a.lower() for a in IMPORT_ALIASES.get(base, ())}
    if ":" in base:  # Maven group:artifact
        group, _, artifact = base.partition(":")
        variants |= {group, artifact}
    if "/" in base and not base.startswith("@"):
        variants.add(base.rsplit("/", 1)[-1])
    return {v for v in variants if len(v) >= 2}


def find_import_sites(target: Path, package: str, limit: int = 8) -> list[tuple[str, int, str]]:
    """(file, line, import text) for source files whose import statements mention `package`.
    Parsed with tree-sitter so strings and comments do not count."""
    variants = _name_variants(package)
    hits: list[tuple[str, int, str]] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            rel = str((Path(root) / name).relative_to(target))
            if detect_language(name) is None:
                continue
            try:
                path = target / rel
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                source = path.read_bytes()
            except OSError:
                continue
            text = source.decode("utf-8", "replace").lower()
            if not any(v in text for v in variants):
                continue
            pf = parse(rel, source, detect_language(rel))
            if pf is None:
                continue
            for stmt in imports(pf):
                low = stmt.lower()
                if any(re.search(rf"(?<![\w-]){re.escape(v)}(?![\w-])", low) for v in variants):
                    line = next(
                        (i + 1 for i, ln in enumerate(pf.lines) if stmt.splitlines()[0] in ln), 1
                    )
                    hits.append((rel, line, stmt.splitlines()[0][:160]))
                    if len(hits) >= limit:
                        return hits
    return hits


MAX_DEFINITION_LINES = 40


def find_definitions(
    target: Path, symbol: str, language: str, near: str = "", limit: int = 3
) -> list[tuple[str, int, int]]:
    """Where a function, method or class named `symbol` is defined: (file, first line, last line).

    Definitions in the same directory as `near` come first, because helpers usually sit next to the
    code that calls them. Names are matched exactly (a method also matches `Class.method`)."""
    if not symbol or not re.fullmatch(r"[A-Za-z_$][\w$]*", symbol):
        return []
    word = re.compile(rf"(?<![\w$]){re.escape(symbol)}(?![\w$])")
    near_dir = str(Path(near).parent) if near else ""
    files = _candidate_files(target, language)
    files.sort(key=lambda f: (str(Path(f).parent) != near_dir, bool(_TEST_HINT.search(f)), f))
    found: list[tuple[str, int, int]] = []
    seen = 0
    for rel in files:
        path = target / rel
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            source = path.read_bytes()
        except OSError:
            continue
        if not word.search(source.decode("utf-8", "replace")):
            continue
        seen += 1
        if seen > MAX_FILES_CONFIRMED:
            break
        pf = parse(rel, source, detect_language(rel))
        if pf is None:
            continue
        for fn in functions(pf):
            if fn.name == symbol:
                found.append((rel, fn.start_line, fn.end_line))
        found += [(rel, lo, hi) for name, lo, hi in class_ranges(pf) if name == symbol]
        if len(found) >= limit:
            break
    return found[:limit]
