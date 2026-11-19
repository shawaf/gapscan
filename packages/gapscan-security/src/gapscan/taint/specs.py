"""Framework and language models for the taint engine, loaded from `models/*.toml`.

Each file describes sources, sinks, sanitizers and calls that never carry text through, for one
language or framework. A file with `requires` only applies to source files that match it (so the
Flask model is inactive in a project that never imports Flask). Adding a framework means adding a
TOML file, never touching the engine.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

MODELS_DIR = Path(__file__).parent / "models"


@dataclass(frozen=True)
class Source:
    kind: str
    pattern: re.Pattern[str]
    safe_for: frozenset[str] = frozenset()  # sink kinds this input cannot attack (a string route
    # parameter cannot carry a NoSQL operator object)


@dataclass(frozen=True)
class Sink:
    kind: str
    cwe: str
    severity: str
    title: str
    callee: re.Pattern[str]
    args: tuple[int, ...] | None = None  # None: every argument
    receiver: bool = False  # the object the method is called on is the dangerous input
    unless: re.Pattern[str] | None = None  # safe when an argument's text matches (an option)


@dataclass(frozen=True)
class AssignSink:
    kind: str
    cwe: str
    severity: str
    title: str
    target: re.Pattern[str]
    key: bool = False  # `session[key] = value`: a tainted key counts too


@dataclass(frozen=True)
class TemplateSink:
    """`render(request, "page.html", {"q": value})`: XSS only where the template prints the
    variable unescaped (`|safe`, or inside an autoescape-off block)."""

    callee: re.Pattern[str]
    template_arg: int
    context_arg: int | None  # None: keyword arguments are the context (Flask render_template)


@dataclass(frozen=True)
class ReturnSink:
    """What a request handler returns is the response body (e.g. a Flask view returning HTML)."""

    kind: str
    cwe: str
    severity: str
    title: str
    safe_calls: re.Pattern[str]  # returning these is fine (jsonify, redirect, render_template...)


@dataclass(frozen=True)
class Sanitizer:
    callee: re.Pattern[str]
    cleans: frozenset[str]  # sink kinds, or {"*"}


@dataclass
class Model:
    """All active rules for one language in one file."""

    sources: list[Source] = field(default_factory=list)
    param_sources: list[Source] = field(default_factory=list)
    handlers: list[re.Pattern[str]] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)
    assign_sinks: list[AssignSink] = field(default_factory=list)
    return_sinks: list[ReturnSink] = field(default_factory=list)
    template_sinks: list[TemplateSink] = field(default_factory=list)
    sanitizers: list[Sanitizer] = field(default_factory=list)
    deny: list[re.Pattern[str]] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    action_fields: list[tuple[str, re.Pattern[str]]] = field(
        default_factory=list
    )  # (kind, class test)


@cache
def _load_all() -> tuple[dict[str, Any], ...]:
    return tuple(tomllib.loads(p.read_text("utf-8")) for p in sorted(MODELS_DIR.glob("*.toml")))


def project_frameworks(files: list[tuple[str, str]]) -> frozenset[str]:
    """Names of the models with `requires` that some file of the project matches. A helper module
    that receives Flask's `request` object rarely imports Flask itself, so a framework that the
    project uses applies to all of its files of that language."""
    active: set[str] = set()
    for doc in _load_all():
        req = doc.get("requires")
        if not req:
            continue
        pat = re.compile(req)
        langs = set(doc.get("languages", []))
        if any(lang in langs and pat.search(text) for lang, text in files):
            active.add(doc.get("name", "?"))
    return frozenset(active)


def build_model(language: str, source_text: str, active: frozenset[str] | None = None) -> Model:
    """Merge every model file that applies to `language` and, if it has `requires`, to this file
    (or, when `active` is given, to the project: see `project_frameworks`)."""
    if active is not None:
        return _build_cached(language, active)
    return _build(language, lambda doc: bool(re.search(doc["requires"], source_text)))


@cache
def _build_cached(language: str, active: frozenset[str]) -> Model:
    return _build(language, lambda doc: doc.get("name", "?") in active)


def _build(language: str, wanted: Callable[[dict[str, Any]], bool]) -> Model:
    m = Model()
    for doc in _load_all():
        if language not in doc.get("languages", []):
            continue
        if doc.get("requires") and not wanted(doc):
            continue
        m.names.append(doc.get("name", "?"))
        for s in doc.get("source", []):
            m.sources.append(Source(s["kind"], re.compile(s["pattern"])))
        for s in doc.get("param_source", []):
            m.param_sources.append(
                Source(s["kind"], re.compile(s["pattern"]), frozenset(s.get("safe_for", [])))
            )
        for h in doc.get("handler", []):
            m.handlers.append(re.compile(h["header"]))
        for s in doc.get("sink", []):
            args = tuple(s["args"]) if "args" in s else None
            m.sinks.append(
                Sink(
                    s["kind"], s["cwe"], s["severity"], s["title"], re.compile(s["callee"]), args,
                    bool(s.get("receiver", False)),
                    re.compile(s["unless"]) if s.get("unless") else None,
                )
            )  # fmt: skip
        for s in doc.get("assign_sink", []):
            m.assign_sinks.append(
                AssignSink(
                    s["kind"], s["cwe"], s["severity"], s["title"], re.compile(s["target"]),
                    bool(s.get("key", False)),
                )
            )  # fmt: skip
        for s in doc.get("return_sink", []):
            m.return_sinks.append(
                ReturnSink(
                    s["kind"], s["cwe"], s["severity"], s["title"], re.compile(s["safe_calls"])
                )
            )
        for s in doc.get("sanitizer", []):
            m.sanitizers.append(Sanitizer(re.compile(s["callee"]), frozenset(s["cleans"])))
        for d in doc.get("deny", []):
            m.deny.append(re.compile(d["callee"]))
        for t in doc.get("template_sink", []):
            ctx = t.get("context_arg")
            m.template_sinks.append(
                TemplateSink(
                    re.compile(t["callee"]),
                    int(t["template_arg"]),
                    None if ctx is None else int(ctx),
                )
            )
        for a in doc.get("action_fields", []):
            m.action_fields.append((a["kind"], re.compile(a["action_class"])))
    return m
