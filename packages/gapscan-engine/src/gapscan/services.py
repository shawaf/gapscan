"""Engine services: the work the CLI, the local server and (later) a cloud API run the same way, so
each app only parses its input, wires its adapters and shows progress (ARCHITECTURE.md section 2).

`review_scan` is the model review of a scan: triage, an optional deep dive into the confirmed
issues, and the repository summary, returned as one `TriageOutput`. Apps follow it through
`ReviewHooks`. The steps themselves (`ReviewSteps`: triage, deep dive, summary) are a domain
pack's: apps pass the security pack's `gapscan.agent.review.AgentSteps` on the model provider they
wired, and tests pass fakes that need no model.

The run options and settings below are the one validation of what a person asks a run to do
(`InvalidInput` says why something is refused), and `effective_config` turns them into the config
the run uses.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any, Protocol

from .compare import compare_reports
from .config import Config
from .memory import Memory
from .models import Investigation, RepoSummary, ScanResult, Verdict
from .registry import background_scanners, selectable_scanners
from .stages import TriageOutput, digest

log = logging.getLogger(__name__)
OnVerdict = Callable[[Verdict], None]
OnInvestigation = Callable[[Investigation], None]


class ReviewStopped(Exception):
    """Raise from a hook to stop the review (for example, the user cancelled). Never swallowed."""


class ReviewSteps(Protocol):
    def triage(
        self,
        cfg: Config,
        result: ScanResult,
        target: Path,
        limit: int,
        on_verdict: OnVerdict,
        memories: list[Memory] | None = None,
    ) -> list[Verdict]: ...

    def deep_dive_count(
        self, cfg: Config, result: ScanResult, verdicts: list[Verdict], limit: int
    ) -> int:
        """How many root-cause groups a deep dive of at most `limit` would investigate."""
        ...

    def deep_dive(
        self,
        cfg: Config,
        result: ScanResult,
        target: Path,
        verdicts: list[Verdict],
        limit: int,
        on_investigation: OnInvestigation,
    ) -> list[Investigation]: ...

    def summarize(
        self, cfg: Config, result: ScanResult, verdicts: list[Verdict]
    ) -> RepoSummary: ...


class ReviewHooks:
    """Progress of a review. Every method does nothing by default; apps override what they show."""

    def message(self, text: str) -> None:
        """A progress line worth showing a person (the same words in every app)."""

    def triage_started(self, total: int) -> None: ...
    def verdict(self, verdict: Verdict) -> None: ...
    def deep_dive_started(self, groups: int) -> None: ...
    def investigation(self, investigation: Investigation) -> None: ...
    def summary_started(self) -> None: ...


def review_scan(
    config: Config,
    scan: ScanResult,
    target: Path,
    *,
    steps: ReviewSteps,
    limit: int,
    deep_dive_limit: int = 0,
    summary: bool = True,
    memories: list[Memory] | None = None,
    hooks: ReviewHooks | None = None,
) -> TriageOutput:
    """Triage the top `limit` findings, deep-dive up to `deep_dive_limit` confirmed root causes,
    and summarize the repository. The deep dive is extra depth: if it fails, the review keeps the
    investigations it has and goes on. A `ReviewStopped` from a hook always stops it."""
    hooks = hooks or ReviewHooks()
    if memories:
        hooks.message(f"{len(memories)} team memories available to the reviewer")
    total = min(limit, sum(1 for f in scan.findings if f.llm_triage))
    hooks.triage_started(total)
    hooks.message(f"model review of the top {total} findings ({config.llm.model})")
    verdicts = steps.triage(config, scan, target, limit, hooks.verdict, memories)

    investigations: list[Investigation] = []
    if deep_dive_limit and verdicts:
        groups = steps.deep_dive_count(config, scan, verdicts, deep_dive_limit)
        hooks.deep_dive_started(groups)
        if not groups:
            hooks.message(f"deep dive: no confirmed finding at priority >= "
                          f"{config.agent.deep_dive_min_priority:g}")  # fmt: skip
        else:
            hooks.message(f"deep dive into the top {groups} confirmed issues")
            done: list[Investigation] = []

            def on_investigation(inv: Investigation) -> None:
                done.append(inv)
                hooks.investigation(inv)

            try:
                investigations = steps.deep_dive(config, scan, target, verdicts, deep_dive_limit,
                                                 on_investigation)  # fmt: skip
            except ReviewStopped:
                raise
            except Exception as exc:  # noqa: BLE001 - extra depth must never fail the review
                log.exception("deep dive failed")
                hooks.message(f"deep dive stopped: {exc}"[:300])
                investigations = done

    repo = None
    if summary and verdicts:
        hooks.summary_started()
        hooks.message("writing the repository summary")
        repo = steps.summarize(config, scan, verdicts)
    return TriageOutput(verdicts=verdicts, summary=repo, investigations=investigations,
                        scan_digest=digest(scan))  # fmt: skip


# --- run options and settings: one validation for every app ------------------------------


class InvalidInput(ValueError):
    """Input from a person that was refused. The message says why, in their terms; apps show it
    as is (the local server answers 400 with it)."""


FINDING_ID = re.compile(r"^[A-Za-z0-9_.:\-]{1,80}$")
DEFAULT_TRIAGE_LIMIT = 40
DEFAULT_DEEP_DIVE_LIMIT = 5


def whole_number(value: Any, name: str, lo: int, hi: int, default: int) -> int:
    """`value` as a whole number in [lo, hi]; `default` when it is missing. Booleans are refused."""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise InvalidInput(f"{name} must be a whole number between {lo} and {hi}")
    return value


def _flag(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise InvalidInput(f"{name} must be true or false")
    return value


def scanner_choice(chosen: Any, known: Sequence[str]) -> list[str]:
    """A non-empty list of scanner names, each one a scanner a person may pick."""
    if not isinstance(chosen, list) or not chosen or any(x not in known for x in chosen):
        raise InvalidInput(f"scanners must be a non-empty list from {list(known)}")
    return sorted(set(chosen))


_GIT_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@+-]{0,199}")


def base_ref(value: Any) -> str:
    """A git ref to diff a scan against (e.g. 'origin/main'). Shape only: whether the checkout
    knows it is decided when the scan runs. The leading char may not be '-' so it can never be
    read as a git option, and the character set keeps it a plain ref name."""
    ref = str(value).strip()
    if not ref:
        return ""
    if not _GIT_REF.fullmatch(ref):
        raise InvalidInput("base must be a git branch or ref name (e.g. origin/main)")
    return ref


def _profile(value: Any, config: Config) -> str:
    if value not in config.llm.all_profiles:
        raise InvalidInput(f"unknown profile; choose one of {sorted(config.llm.all_profiles)}")
    return str(value)


def run_settings(saved: dict[str, Any], config: Config) -> dict[str, Any]:
    """The saved run defaults, with the config's values where nothing was saved."""
    return {"profile": saved.get("profile") or config.llm.profile,
            "triage_limit": saved.get("triage_limit", DEFAULT_TRIAGE_LIMIT),
            "use_tools": saved.get("use_tools", config.agent.use_tools),
            "max_tool_calls": saved.get("max_tool_calls", config.agent.max_tool_calls),
            "asvs_level": saved.get("asvs_level", config.general.asvs_level),
            "default_preset": saved.get("default_preset", "full"),
            "deep_dive": saved.get("deep_dive", True),
            "deep_dive_limit": saved.get("deep_dive_limit", DEFAULT_DEEP_DIVE_LIMIT),
            "scanners": saved.get("scanners") or list(config.scanners.enabled)}  # fmt: skip


def settings_update(body: dict[str, Any], config: Config, known: Sequence[str]) -> dict[str, Any]:
    """The run defaults a request changes, validated; keys it does not name are left out."""
    out: dict[str, Any] = {}
    if "profile" in body:
        out["profile"] = _profile(body["profile"], config)
    if "triage_limit" in body:
        out["triage_limit"] = whole_number(body["triage_limit"], "triage_limit", 0, 100_000,
                                           DEFAULT_TRIAGE_LIMIT)  # fmt: skip
    if "max_tool_calls" in body:
        out["max_tool_calls"] = whole_number(body["max_tool_calls"], "max_tool_calls", 0, 10, 4)
    if "asvs_level" in body:
        out["asvs_level"] = whole_number(body["asvs_level"], "asvs_level", 1, 3, 2)
    if "default_preset" in body:
        if body["default_preset"] not in ("full", "scanners"):
            raise InvalidInput("default_preset must be 'full' or 'scanners'")
        out["default_preset"] = body["default_preset"]
    if "scanners" in body:
        out["scanners"] = scanner_choice(body["scanners"], known)
    if "deep_dive" in body:
        out["deep_dive"] = _flag(body["deep_dive"], "deep_dive")
    if "deep_dive_limit" in body:
        out["deep_dive_limit"] = whole_number(body["deep_dive_limit"], "deep_dive_limit", 0, 100,
                                              DEFAULT_DEEP_DIVE_LIMIT)  # fmt: skip
    if "use_tools" in body:
        out["use_tools"] = _flag(body["use_tools"], "use_tools")
    return out


def run_options(
    body: dict[str, Any], saved: dict[str, Any], config: Config, known: Sequence[str]
) -> dict[str, Any]:
    """The options of one run, validated, with the saved defaults filled in. A `baseline` is only
    checked to be a run number: whether it is a finished run of the project is the app's to say."""
    opts: dict[str, Any] = {
        "triage": bool(body.get("triage", False)),
        "limit": whole_number(body.get("limit"), "limit", 0, 100_000,
                              int(saved.get("triage_limit", DEFAULT_TRIAGE_LIMIT))),
    }  # fmt: skip
    if body.get("scanners") is not None:
        opts["scanners"] = scanner_choice(body["scanners"], known)
    if body.get("profile"):
        opts["profile"] = _profile(body["profile"], config)
    if body.get("max_tool_calls") is not None:
        opts["max_tool_calls"] = whole_number(body["max_tool_calls"], "max_tool_calls", 0, 10, 4)
    if opts["triage"]:  # the deep dive only follows an AI review
        opts["deep_dive"] = _flag(body.get("deep_dive", saved.get("deep_dive", True)), "deep_dive")
        opts["deep_dive_limit"] = whole_number(
            body.get("deep_dive_limit"), "deep_dive_limit", 0, 100,
            int(saved.get("deep_dive_limit", DEFAULT_DEEP_DIVE_LIMIT)),
        )  # fmt: skip
    if body.get("asvs_level") is not None:
        opts["asvs_level"] = whole_number(body["asvs_level"], "asvs_level", 1, 3, 2)
    if body.get("baseline") is not None:
        opts["baseline"] = whole_number(body["baseline"], "baseline", 1, 10**9, 0)
    if body.get("base"):  # diff scope: only findings introduced since this git ref
        opts["base"] = base_ref(body["base"])
    return opts


def effective_config(
    base: Config, settings: dict[str, Any], options: dict[str, Any] | None = None
) -> Config:
    """The config with the saved settings and one run's options applied (model profile, tools,
    scanner subset, tool-call budget, ASVS level)."""
    options = options or {}
    settings = {
        **settings,
        **{k: v for k, v in options.items() if k in ("profile", "use_tools") and v},
    }
    data = base.model_dump(mode="json")
    llm = data["llm"]
    chosen = options.get("scanners") or settings.get(
        "scanners"
    )  # this run's choice, else the saved default
    if chosen:
        # The picker chooses among the selectable scanners. The others (built in: no binary,
        # offline, fast) always run when the base config enables them: leaving them out silently
        # removed all data-flow findings from scans started in the UI.
        packs = tuple(base.scanners.packs)
        data["scanners"]["enabled"] = [s for s in selectable_scanners(packs) if s in chosen] + [
            s for s in background_scanners(packs) if s in base.scanners.enabled
        ]
    for key, section, name in (
        ("max_tool_calls", "agent", "max_tool_calls"),
        ("asvs_level", "general", "asvs_level"),
    ):
        value = options.get(key, settings.get(key))  # this run's choice, else the saved default
        if value is not None:
            data[section][name] = int(value)
    if settings.get("profile"):
        # Re-resolve the model from the chosen profile, not the previously resolved one.
        for key in ("model", "context_tokens", "code_context_tokens"):
            llm.pop(key, None)
        llm["profile"] = settings["profile"]
        llm["model"] = ""
    if "use_tools" in settings:
        data["agent"]["use_tools"] = bool(settings["use_tools"])
    return Config.model_validate(data)


MAX_DIR_ENTRIES = 2000


def list_directory(raw: str, home: Path) -> dict[str, Any]:
    """The sub-folders of one directory, so the manager can offer a folder picker in the browser
    (the native dialog exists only in the desktop window). Read-only and directories only: file
    contents are never read or returned. Defaults to the user's home when no path is given.

    The server is loopback-only and token-gated, so this lists only for the local signed-in user,
    the same filesystem a native "choose folder" dialog would show them."""
    path = Path(raw).expanduser() if raw.strip() else home
    try:
        path = path.resolve()
    except OSError as exc:
        raise InvalidInput(f"cannot read that path: {exc}") from exc
    if not path.is_dir():
        raise InvalidInput(f"not a folder: {path}")
    entries: list[dict[str, Any]] = []
    truncated = False
    try:
        children = sorted(path.iterdir(), key=lambda p: p.name.lower())
    except (PermissionError, OSError) as exc:
        raise InvalidInput(f"cannot read that folder: {exc}") from exc
    for child in children:
        try:
            if not child.is_dir():
                continue
            entries.append({"name": child.name, "git": (child / ".git").exists()})
        except OSError:
            continue  # a folder we cannot stat (permission, broken symlink): skip it
        if len(entries) >= MAX_DIR_ENTRIES:
            truncated = True
            break
    parent = str(path.parent) if path.parent != path else None  # None at a filesystem root
    return {
        "path": str(path),
        "name": path.name or str(path),
        "parent": parent,
        "home": str(home),
        "entries": entries,
        "truncated": truncated,
    }


def check_project_folder(raw: str, data_dir: Path) -> Path:
    """The folder a person registered as a project, resolved, or the reason it is refused: a
    filesystem root, the whole home folder and GapScan's own data are never scanned."""
    if not raw or "\x00" in raw:
        raise InvalidInput("a folder path is required")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise InvalidInput("the folder path must be absolute")
    path = path.resolve()
    if not path.is_dir():
        raise InvalidInput(f"not a folder: {path}")
    if path == Path(path.anchor) or path == Path.home().resolve():
        raise InvalidInput(
            "refusing to scan a filesystem root or the whole home folder: choose a project folder"
        )
    if path == data_dir.resolve() or data_dir.resolve() in path.parents:
        raise InvalidInput("that folder holds GapScan's own data")
    return path


def check_finding_id(finding_id: str) -> str:
    if not FINDING_ID.match(finding_id):
        raise InvalidInput("invalid finding id")
    return finding_id


def report_findings(path: Path) -> list[dict[str, Any]]:
    """The finding rows of a saved report (`report.json`); empty when it cannot be read."""
    with contextlib.suppress(OSError, ValueError):
        rows = json.loads(path.read_text(encoding="utf-8")).get("findings", [])
        return rows if isinstance(rows, list) else []
    return []


HISTORY_FIELDS = ("status", "verdict", "confidence", "severity", "open", "decision")


def finding_history(
    finding_id: str, runs: Iterable[tuple[dict[str, Any], Path]]
) -> list[dict[str, Any]]:
    """How one finding looked in each finished run, newest first. `runs` pairs a run (with `id`
    and `finished_at`) with its saved report; stable finding IDs make the rows comparable."""
    out: list[dict[str, Any]] = []
    for run, report in runs:
        row = next((r for r in report_findings(report) if r.get("id") == finding_id), None)
        if row:
            out.append({"run": run["id"], "at": run["finished_at"],
                        **{k: row.get(k) for k in HISTORY_FIELDS}})  # fmt: skip
    return out


class NotReady(Exception):
    """The request is valid but cannot be answered yet (the local server answers 409)."""


class Missing(LookupError):
    """Something the request names does not exist (the local server answers 404)."""


RUN_HEAD = ("id", "finished_at", "score", "grade", "open_findings", "findings")


def compare_runs(
    done: Sequence[dict[str, Any]], a: str, b: str, report_of: Callable[[int], Path]
) -> dict[str, Any]:
    """New, fixed and unchanged findings between two finished runs of a project, plus its score
    series. `done` is the project's finished runs, newest first; `a` (older) and `b` (newer) are
    run numbers as a person typed them, empty for the two latest runs."""
    if len(done) < 2:
        raise NotReady("comparing needs two finished runs of this project")
    by_id = {x["id"]: x for x in done}

    def pick(name: str, raw: str, default: int) -> dict[str, Any]:
        try:
            wanted = int(raw) if raw else default
        except ValueError as exc:
            raise InvalidInput(f"{name} must be a run number") from exc
        run = by_id.get(wanted)
        if run is None:
            raise InvalidInput(f"{name} must be a finished run of this project")
        return run

    newer, older = pick("b", b, done[0]["id"]), pick("a", a, done[1]["id"])
    if older["id"] == newer["id"]:
        raise InvalidInput("pick two different runs")

    def findings(run: dict[str, Any]) -> list[dict[str, Any]]:
        path = report_of(run["id"])
        if not path.is_file():
            raise Missing(f"run #{run['id']} has no report data")
        rows: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8")).get(
            "findings", []
        )
        return rows

    series = [{"id": x["id"], "at": x["finished_at"], "score": x["score"],
               "open": x["open_findings"]} for x in reversed(done[:12])]  # fmt: skip
    diff = compare_reports(findings(older), findings(newer))
    return {"a": {k: older[k] for k in RUN_HEAD}, "b": {k: newer[k] for k in RUN_HEAD}, **diff,
            "series": series}  # fmt: skip
