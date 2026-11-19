"""The tools the triage agent may call. Small, bounded and read-only (hard rule #3):

- everything is confined to the target directory (no `..`, no symlink escapes),
- nothing writes, executes, builds or fetches anything,
- results are size-capped and secret-masked,
- tool output is untrusted data and is wrapped as such by the agent loop.

The model can ask for these by name and nothing else; unknown tools are refused.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..context.callgraph import (
    MAX_DEFINITION_LINES,
    MAX_FILE_BYTES,
    SKIP_DIRS,
    find_callers,
    find_definitions,
    find_import_sites,
)
from ..context.treesitter import detect_language
from ..context.variants import describe as describe_variants
from ..models import Finding
from ..owasp.classify import load_tables, normalize_cwe
from ..redact import mask

MAX_READ_LINES = 120
MAX_READ_BYTES = 2_000_000
MAX_RESULT_CHARS = 6000
MAX_CALLERS = 5
# Files the model may not read even inside the target: they hold credentials, not code to judge.
_SENSITIVE_NAME = re.compile(
    r"(^\.env($|\.)|\.(pem|key|p12|pfx|jks|keystore|kdbx)$|^id_(rsa|dsa|ecdsa|ed25519)|"
    r"^\.netrc$|^\.pgpass$|^credentials(\.json)?$|^secrets?\.(json|ya?ml|toml)$|\.tfvars$)",
    re.IGNORECASE,
)
_SYMBOL = re.compile(r"^[A-Za-z_$][\w$]*$")
_PACKAGE = re.compile(r"^[@\w][\w./:@-]{0,100}$")
MAX_IMPORT_HITS = 8
MAX_SEARCH_HITS = 20
MAX_SEARCH_FILES = 20_000
MAX_LISTED_FILES = 100
_SEARCH_TEXT = re.compile(r"^[^\n]{2,120}$")
# Regex syntax in a literal search finds nothing, which would then "prove" absence.
_REGEX_SYNTAX = re.compile(r"\.\*|\.\+|\.\?|\\[dswbDSWB.]|\|")
_GLOB = re.compile(r"^[\w*?.\[\]/{}-]{1,100}$")
MAX_CONFIG_LINES = 20
_CONFIG_KEY = re.compile(r"^[\w.\-:@/]{1,80}$")
_WHOLE_PROJECT_GLOBS = {"*", "**", "**/*", "./**", "./**/*", "**/*.*", "*.*"}
MAX_MANIFEST_LINES = 5

TOOL_DESCRIPTIONS = {
    "read_code": 'read_code {"file": "<path in the project>", "start": <line>, "end": <line>} '
    f"- numbered source lines (at most {MAX_READ_LINES} per call).",
    "find_callers": 'find_callers {"symbol": "<function or method name>"} '
    "- places that call it, matched by name (receiver types are not resolved).",
    "find_definition": 'find_definition {"symbol": "<function, method or class>"} - where it is '
    "defined, with its code. Use it to follow a helper, sanitizer or validator the code calls "
    "instead of guessing what it does.",
    "find_imports": 'find_imports {"package": "<package name>"} - source files that import/use a '
    "dependency (answers whether a vulnerable package is used directly at all; a package that "
    "is never imported may still be a transitive dependency).",
    "lookup_cwe": 'lookup_cwe {"id": "CWE-89"} - the CWE name and its Top 10:2025 / ASVS links.',
    "search_kb": 'search_kb {"query": "<text>"} - search the local security knowledge base '
    "(OWASP Cheat Sheets, CWE, policies).",
}
TOOL_NAMES = tuple(TOOL_DESCRIPTIONS)

# Extra tools for the deep-dive pass (Phase 11): finding every place a root cause shows up, and
# proving that something is absent, needs a whole-project search.
DEEP_TOOL_DESCRIPTIONS = {
    **TOOL_DESCRIPTIONS,
    "search_repo": 'search_repo {"text": "<literal text>", "glob": "<optional path glob>"} - '
    "every line in the project containing the text (case-insensitive, literal, not a regex; "
    f"at most {MAX_SEARCH_HITS} hits). Says whether the search covered every file, which is "
    "required before you claim something is missing. With a glob, absence is proven only for "
    "the files the glob matched.",
    "list_files": 'list_files {"glob": "<glob, e.g. **/*.xml or *network_security*>"} - project '
    f"files whose path or name matches (at most {MAX_LISTED_FILES}).",
    "build_variants": 'build_variants {"file": "<optional path in the project>"} - Android build '
    "variants from the Gradle files: flavors, build types, what each sets (buildConfigField, "
    "minify, debuggable...) and, for a file, which variants ship it (app/src/main: all; "
    "app/src/dev: dev builds only). Use it to state which builds a finding affects.",
    "read_config": 'read_config {"file": "<config file>", "key": "<setting or attribute name>"} - '
    "the numbered lines of one config file (XML such as AndroidManifest.xml or "
    "network_security_config.xml, Gradle, .properties, YAML, TOML, JSON) that set or mention "
    f"that key (at most {MAX_CONFIG_LINES}).",
}
DEEP_TOOL_NAMES = tuple(DEEP_TOOL_DESCRIPTIONS)


@dataclass
class ToolResult:
    ok: bool
    text: str
    evidence_ref: str | None = None
    outcome: str | None = None  # short machine-readable result, e.g. "imports_found"
    # Every (file, first line, last line) shown to the model in `text`; deep-dive evidence may
    # only cite these lines.
    seen: list[tuple[str, int, int]] = field(default_factory=list)
    scope: str = ""  # search_repo: the glob a complete empty search covered ("" = whole project)


class KnowledgeBase(Protocol):
    def search(self, query: str, limit: int = 3) -> list[str]: ...
    def lookup(self, doc_id: str) -> str | None: ...
    def references_for(
        self, cwes: list[str], limit: int = 2, *, dependency: bool = False
    ) -> list[str]: ...


class NullKnowledgeBase:
    """Placeholder until `gapscan kb build` exists (Phase 6)."""

    def search(self, query: str, limit: int = 3) -> list[str]:
        return []

    def lookup(self, doc_id: str) -> str | None:
        return None

    def references_for(
        self, cwes: list[str], limit: int = 2, *, dependency: bool = False
    ) -> list[str]:
        return []


class ToolBox:
    def __init__(self, target: Path, language: str | None = None,
                 kb: KnowledgeBase | None = None) -> None:  # fmt: skip
        self.target = target.resolve()
        self.language = language
        self.kb = kb or NullKnowledgeBase()

    # --- dispatch ------------------------------------------------------------------

    def execute(self, name: str, args: dict[str, str | int]) -> ToolResult:
        try:
            if name == "read_code":
                return self._read_code(args)
            if name == "find_callers":
                return self._find_callers(args)
            if name == "find_definition":
                return self._find_definition(args)
            if name == "find_imports":
                return self._find_imports(args)
            if name == "lookup_cwe":
                return self._lookup_cwe(args)
            if name == "search_kb":
                return self._search_kb(args)
            if name == "search_repo":
                return self._search_repo(args)
            if name == "list_files":
                return self._list_files(args)
            if name == "build_variants":
                return self._build_variants(args)
            if name == "read_config":
                return self._read_config(args)
        except (KeyError, ValueError, TypeError) as exc:
            return ToolResult(False, f"bad arguments for {name}: {exc}")
        return ToolResult(False, f"unknown tool {name!r}; available: {', '.join(TOOL_NAMES)}")

    # --- tools ---------------------------------------------------------------------

    def _safe_file(self, rel: str) -> Path | None:
        p = (self.target / rel).resolve()
        ok = p.is_relative_to(self.target) and p.is_file() and p.stat().st_size <= MAX_READ_BYTES
        return p if ok else None

    def _read_code(self, args: dict[str, str | int]) -> ToolResult:
        rel = str(args["file"])
        start, end = int(args["start"]), int(args.get("end", args["start"]))
        if start < 1 or end < start:
            return ToolResult(False, "start must be >= 1 and end >= start")
        path = self._safe_file(rel)
        if path is None:
            return ToolResult(False, f"file not found inside the project: {rel}")
        if _SENSITIVE_NAME.search(path.name):
            return ToolResult(
                False, "refused: this file type holds credentials and is not readable"
            )
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if start > len(lines):
            return ToolResult(False, f"{rel} has only {len(lines)} lines")
        end = min(end, start + MAX_READ_LINES - 1, len(lines))
        body = "\n".join(f"{n:>5} | {mask(lines[n - 1])}" for n in range(start, end + 1))
        text = body[:MAX_RESULT_CHARS]
        end = _last_shown_line(text, end)
        return ToolResult(True, text, f"{rel}:{start}-{end}", seen=[(rel, start, end)])

    def _find_callers(self, args: dict[str, str | int]) -> ToolResult:
        symbol = str(args["symbol"]).strip()
        if not _SYMBOL.match(symbol):
            return ToolResult(False, "symbol must be a plain identifier")
        lang = detect_language(str(args["file"])) if "file" in args else self.language
        if lang is None:
            return ToolResult(False, "unknown language; pass the file the symbol is defined in")
        callers = find_callers(self.target, symbol, lang, defined_in="", max_callers=MAX_CALLERS)
        if not callers:
            return ToolResult(True, f"no callers of {symbol}() found by name match")
        out = [
            f"{c.file}:{c.line} in {c.function or 'module level'}: {mask(c.snippet)}"
            for c in callers
        ]
        return ToolResult(
            True, "\n".join(out)[:MAX_RESULT_CHARS], f"{callers[0].file}:{callers[0].line}",
            seen=[(c.file, c.line, c.line) for c in callers],
        )  # fmt: skip

    def _find_definition(self, args: dict[str, str | int]) -> ToolResult:
        symbol = (
            str(args["symbol"]).strip().rstrip("()").rsplit(".", 1)[-1]
        )  # a.b.Class.method -> method
        if not _SYMBOL.match(symbol):
            return ToolResult(False, "symbol must be a plain identifier")
        lang = detect_language(str(args["file"])) if "file" in args else self.language
        if lang is None:
            return ToolResult(False, "unknown language; pass the file the symbol is used in")
        defs = find_definitions(self.target, symbol, lang, near=str(args.get("file", "")))
        if not defs:
            return ToolResult(True, f"no definition of {symbol!r} found in the project (it may be "
                                    "a library function)", outcome="not_found")  # fmt: skip
        parts = []
        seen: list[tuple[str, int, int]] = []
        for rel, lo, hi in defs:
            path = self._safe_file(rel)
            if path is None or _SENSITIVE_NAME.search(path.name):
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            end = min(hi, lo + MAX_DEFINITION_LINES - 1)
            body = "\n".join(f"{n:>5} | {mask(lines[n - 1])}" for n in range(lo, end + 1))
            parts.append(f"{rel}:{lo}-{end}\n{body}")
            seen.append((rel, lo, end))
        if not parts:
            return ToolResult(False, "definition is in a file that cannot be read")
        first = defs[0]
        ref = f"{first[0]}:{first[1]}-{first[2]}"
        text = "\n\n".join(parts)[:MAX_RESULT_CHARS]
        return ToolResult(True, text, ref, outcome="found", seen=_still_shown(seen, text))

    def _find_imports(self, args: dict[str, str | int]) -> ToolResult:
        package = str(args["package"]).strip()
        if not _PACKAGE.match(package):
            return ToolResult(False, "package must be a plain package name")
        hits = find_import_sites(self.target, package, limit=MAX_IMPORT_HITS)
        if not hits:
            text = (f"no source file imports {package!r} (it may still be a transitive "
                    "dependency or used by tooling)")  # fmt: skip
            return ToolResult(True, text, outcome="no_imports")
        out = [f"{file}:{line}: {mask(text)}" for file, line, text in hits]
        return ToolResult(True, "\n".join(out)[:MAX_RESULT_CHARS], f"{hits[0][0]}:{hits[0][1]}",
                          outcome="imports_found",
                          seen=[(f, ln, ln) for f, ln, _ in hits])  # fmt: skip

    def _lookup_cwe(self, args: dict[str, str | int]) -> ToolResult:
        cwe = normalize_cwe(str(args["id"]))
        if cwe is None:
            return ToolResult(False, "id must look like CWE-89")
        t = load_tables()
        full = self.kb.lookup(cwe)  # full MITRE entry when the knowledge base is built
        name = t.cwe_names.get(cwe)
        cats = [f"{c} {t.top10_names.get(c, '')}".strip() for c in t.top10.get(cwe, [])]
        asvs = t.asvs.get(cwe, [])[:5]
        if full:
            parts = [
                full[: MAX_RESULT_CHARS - 600],
                "OWASP Top 10:2025: " + (", ".join(cats) or "none"),
            ]
            if asvs:
                parts.append("ASVS 5.0.0: " + ", ".join(asvs))
            return ToolResult(True, "\n".join(parts))
        if not (name or cats or asvs):
            return ToolResult(True, f"{cwe}: no entry in the local data (the full CWE database "
                                    "arrives with the knowledge base)")  # fmt: skip
        parts = [f"{cwe}: {name or 'name not in local data'}"]
        parts.append("OWASP Top 10:2025: " + (", ".join(cats) or "none"))
        if asvs:
            parts.append("ASVS 5.0.0: " + ", ".join(asvs))
        return ToolResult(True, "\n".join(parts))

    def _search_kb(self, args: dict[str, str | int]) -> ToolResult:
        query = str(args["query"]).strip()[:200]
        if not query:
            return ToolResult(False, "query is empty")
        hits = self.kb.search(query, limit=3)
        if not hits:
            return ToolResult(
                True, "no results (the local knowledge base is empty or not built yet)"
            )
        return ToolResult(True, "\n---\n".join(h[:1500] for h in hits)[:MAX_RESULT_CHARS])

    def _walk(self) -> list[str]:
        """Regular files under the target (relative paths, sorted), skipping vendored and
        build directories. Symlinks are never followed, so nothing outside the target is read."""
        found: list[str] = []
        for root, dirs, files in os.walk(self.target):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                full = Path(root) / name
                if not full.is_symlink():
                    found.append(full.relative_to(self.target).as_posix())
        return found

    def _search_repo(self, args: dict[str, str | int]) -> ToolResult:
        text = str(args["text"]).strip()
        if not _SEARCH_TEXT.match(text):
            return ToolResult(False, "text must be 2-120 characters on one line")
        if _REGEX_SYNTAX.search(text):
            return ToolResult(False, "text is literal, not a regex (.* | \\d are not supported): "
                                     "run one search per plain word or phrase instead")  # fmt: skip
        glob = str(args.get("glob", "") or "").strip()
        if glob in _WHOLE_PROJECT_GLOBS:  # matches every file: the same as no glob
            glob = ""
        if glob and (not _GLOB.match(glob) or ".." in glob):
            return ToolResult(False, "glob may use letters, digits, / . - _ * ? [ ] { } only")
        needle = text.lower()
        hits: list[tuple[str, int, str]] = []
        skipped: list[str] = []  # files that could hold the text but were not searched
        sensitive = searched = 0
        files = self._walk()
        too_many = len(files) > MAX_SEARCH_FILES
        files = files[:MAX_SEARCH_FILES]
        hit_cap = False
        for rel in files:
            if glob and not _glob_match(rel, glob):
                continue
            if _SENSITIVE_NAME.search(Path(rel).name):
                sensitive += 1
                continue
            path = self.target / rel
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    skipped.append(rel)
                    continue
                data = path.read_bytes()
            except OSError:
                skipped.append(rel)
                continue
            if b"\0" in data[:8192]:
                continue  # binary
            searched += 1
            if needle.encode() not in data.lower():
                continue
            for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
                if needle in line.lower():
                    if len(hits) >= MAX_SEARCH_HITS:
                        hit_cap = True
                        break
                    hits.append((rel, n, mask(line.strip())[:200]))
            if hit_cap:
                break
        complete = not (hit_cap or too_many or skipped)
        cover = f"searched {searched} files" + (f" under {glob!r}" if glob else "")
        notes = [cover]
        if sensitive:
            notes.append(f"{sensitive} credential files not searched by design")
        if skipped:
            notes.append(f"{len(skipped)} files too large or unreadable, e.g. {skipped[0]}")
        if too_many:
            notes.append(f"only the first {MAX_SEARCH_FILES} files were searched")
        if hit_cap:
            notes.append("stopped at the hit limit; there may be more")
        # A glob that matched no file proves nothing (a typo would otherwise "prove" absence).
        complete = complete and searched > 0
        if glob and searched == 0:
            notes.append("no searchable file matched the glob")
        if complete:
            notes.append("search COMPLETE" + (" within the glob" if glob else ""))
        else:
            notes.append("search INCOMPLETE")
        footer = "(" + "; ".join(notes) + ")"
        if not hits:
            outcome = "no_matches" if complete else "no_matches_incomplete"
            return ToolResult(True, f"no line contains {text!r}. {footer}", outcome=outcome,
                              scope=glob)  # fmt: skip
        body = "\n".join(f"{f}:{n}: {t}" for f, n, t in hits)
        shown = body[: MAX_RESULT_CHARS - len(footer) - 1]
        seen = _still_shown([(f, n, n) for f, n, _ in hits], shown)
        return ToolResult(True, f"{shown}\n{footer}", f"{hits[0][0]}:{hits[0][1]}",
                          outcome="matches_found", seen=seen)  # fmt: skip

    def _build_variants(self, args: dict[str, str | int]) -> ToolResult:
        rel = str(args.get("file", "") or "").strip().lstrip("./") or None
        if rel is not None and self._safe_file(rel) is None:
            return ToolResult(False, f"file not found inside the project: {rel}")
        text, seen = describe_variants(self.target, rel)
        return ToolResult(True, mask(text)[:MAX_RESULT_CHARS], outcome="variants", seen=seen)

    def _read_config(self, args: dict[str, str | int]) -> ToolResult:
        rel, key = str(args["file"]).strip(), str(args["key"]).strip()
        if not _CONFIG_KEY.match(key):
            return ToolResult(False, "key must be a plain setting or attribute name")
        path = self._safe_file(rel)
        if path is None:
            return ToolResult(False, f"file not found inside the project: {rel}")
        if _SENSITIVE_NAME.search(path.name):
            return ToolResult(
                False, "refused: this file type holds credentials and is not readable"
            )
        word = re.compile(rf"(?<![\w.]){re.escape(key)}(?![\w])", re.IGNORECASE)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        hits = [n for n, line in enumerate(lines, 1) if word.search(line)][:MAX_CONFIG_LINES]
        if not hits:
            return ToolResult(True, f"{rel} does not mention {key!r} ({len(lines)} lines read)",
                              outcome="not_set")  # fmt: skip
        body = "\n".join(f"{n:>5} | {mask(lines[n - 1])[:200]}" for n in hits)
        return ToolResult(True, body, f"{rel}:{hits[0]}", outcome="found",
                          seen=[(rel, n, n) for n in hits])  # fmt: skip

    def _list_files(self, args: dict[str, str | int]) -> ToolResult:
        glob = str(args["glob"]).strip()
        if not _GLOB.match(glob) or ".." in glob:
            return ToolResult(False, "glob may use letters, digits, / . - _ * ? [ ] { } only")
        matched = [rel for rel in self._walk() if _glob_match(rel, glob)]
        if not matched:
            return ToolResult(True, f"no file matches {glob!r}", outcome="no_files")
        out = matched[:MAX_LISTED_FILES]
        more = f"\n(and {len(matched) - len(out)} more)" if len(matched) > len(out) else ""
        return ToolResult(True, "\n".join(out) + more, outcome="files_found")


def manifest_lines(box: ToolBox, rel: str, package: str) -> ToolResult:
    """Lines of a dependency manifest/lockfile that name `package`, so dependency findings
    can cite where the package is declared. Not a model tool (ToolBox.execute is the
    only entry point the model reaches): GapScan calls it while building the prompt."""
    path = box._safe_file(rel)
    if path is None or _SENSITIVE_NAME.search(path.name) or not package.strip():
        return ToolResult(False, "manifest not readable")
    name = re.compile(rf"(?<![\w-]){re.escape(package.strip())}(?![\w-])", re.IGNORECASE)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    hits = [n for n, line in enumerate(lines, 1) if name.search(line)][:MAX_MANIFEST_LINES]
    if not hits:
        return ToolResult(True, f"{package} is not named in {rel}", outcome="not_found")
    body = "\n".join(f"{n:>5} | {mask(lines[n - 1])[:200]}" for n in hits)
    return ToolResult(True, body, f"{rel}:{hits[0]}", outcome="found",
                      seen=[(rel, n, n) for n in hits])  # fmt: skip


def _glob_match(rel: str, glob: str) -> bool:
    """Match the whole relative path, or just the file name when the glob has no '/'.
    `**/` also matches files at the top level."""
    rel_l, glob_l = rel.lower(), glob.lower()
    if "/" not in glob_l:
        return fnmatch.fnmatchcase(rel_l.rsplit("/", 1)[-1], glob_l)
    return fnmatch.fnmatchcase(rel_l, glob_l) or (
        glob_l.startswith("**/") and fnmatch.fnmatchcase(rel_l, glob_l[3:])
    )


def _last_shown_line(text: str, end: int) -> int:
    """Last line number fully present in numbered output that may have been cut short."""
    nums = re.findall(r"^\s*(\d+) \|", text, re.MULTILINE)
    if not nums:
        return end
    last = int(nums[-1])
    return last if text.endswith("\n") or last == end else max(last - 1, int(nums[0]))


def _still_shown(seen: list[tuple[str, int, int]], text: str) -> list[tuple[str, int, int]]:
    """Drop entries whose location was cut off by the result size cap."""
    return [s for s in seen if f"{s[0]}:{s[1]}" in text]


_ECOSYSTEM_LANGUAGE = {"pypi": "python", "npm": "javascript", "maven": "java", "go": "go",
                       "pub": "dart", "swifturl": "swift", "packagist": "php"}  # fmt: skip


def language_for_finding(finding: Finding) -> str | None:
    """Language of the code the finding is about: from the file extension, or for dependency
    findings from the package ecosystem (OSV reports it)."""
    if finding.file and (lang := detect_language(finding.file)):
        return lang
    eco = str(finding.raw.get("ecosystem") or "").lower()
    return _ECOSYSTEM_LANGUAGE.get(eco)
