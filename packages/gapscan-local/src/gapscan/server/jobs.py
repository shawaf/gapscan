"""Background execution of scans for the management UI.

One worker thread runs jobs one at a time (a scan plus model review uses the whole machine), so a queue
of scans is simply processed in order. Each job writes its artifacts under data/runs/<id>/ and keeps the
database row current (phase, progress, log) so the UI can show live progress. Cancelling is cooperative:
it takes effect between findings and between phases."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..agent.review import (
    deep_dive_findings,
    deep_dive_groups,
    summarize_scan,
    triage_top_findings,
)
from ..config import Config
from ..diffscan import GitError, changes_since, head_info, introduced_by_changes
from ..llm.bench import load_cases, run_case
from ..llm.bench import summarize as summarize_bench
from ..llm.client import LLMClient
from ..memory import Memory
from ..models import Investigation, RepoSummary, ScanResult, Verdict
from ..pipeline import run_scan
from ..registry import selectable_scanners
from ..report.build import PreviousRun, load_previous
from ..report.decisions import Decision, Decisions
from ..report.exports import write_exports
from ..report.schema import ReportData
from ..report.service import build_dashboard
from ..services import ReviewHooks, ReviewStopped, effective_config, review_scan
from ..stages import RunFolder, TriageOutput
from .db import Database, now
from .plan import build_plan, plan_lines

log = logging.getLogger(__name__)
SERVER_META = '<meta name="gapscan-server" content="/api/projects/{pid}">'


class Cancelled(ReviewStopped):
    """The user cancelled the run; stops the review wherever it is."""


class Pipeline:
    """The scan/triage/summary steps. Tests replace these with fakes; the defaults are the real engine."""

    def scan(self, cfg: Config, target: Path) -> ScanResult:
        return run_scan(cfg, target)

    def triage(self, cfg: Config, result: ScanResult, target: Path, limit: int,
               on_verdict: Callable[[Verdict], None],
               memories: list[Memory] | None = None) -> list[Verdict]:  # fmt: skip
        return triage_top_findings(cfg, result, target, limit=limit, client=LLMClient(cfg.llm),
                                   on_verdict=on_verdict, memories=memories)  # fmt: skip

    def deep_dive_count(
        self, cfg: Config, result: ScanResult, verdicts: list[Verdict], limit: int
    ) -> int:
        return len(deep_dive_groups(cfg, result, verdicts, limit))

    def deep_dive(self, cfg: Config, result: ScanResult, target: Path, verdicts: list[Verdict],
                  limit: int, on_investigation: Callable[[Investigation], None]) -> list[Investigation]:  # fmt: skip
        return deep_dive_findings(cfg, result, target, verdicts, limit=limit,
                                  client=LLMClient(cfg.llm), on_investigation=on_investigation)  # fmt: skip

    def summarize(self, cfg: Config, result: ScanResult, verdicts: list[Verdict]) -> RepoSummary:
        return summarize_scan(cfg, result, verdicts, client=LLMClient(cfg.llm))

    cases_path = Path("eval/triage_cases.json")  # the labeled cases shipped with GapScan

    def benchmark_cases(self) -> list[dict[str, Any]]:
        return load_cases(self.cases_path) if self.cases_path.is_file() else []

    def benchmark_case(self, cfg: Config, model: str, case: dict[str, Any]) -> dict[str, Any]:
        return run_case(LLMClient(cfg.llm), model, case)


KNOWN_SCANNERS = selectable_scanners()  # the default packs' picker choices


class _JobHooks(ReviewHooks):
    """Review progress written to the scan row: phase, counts, tokens, time left, deep-dive stats.
    Every update also checks for a cancel, which stops the review after the current finding."""

    def __init__(self, runner: JobRunner, scan_id: int) -> None:
        self.runner, self.scan_id = runner, scan_id
        self.db = runner.db
        self.total, self.done, self.tokens, self.started = 0, 0, 0, 0.0
        self.counts: dict[str, int] = {}
        self.base_stats: dict[str, Any] = {}
        self.dd_total = 0
        self.dd_done: list[Investigation] = []

    def message(self, text: str) -> None:
        self.runner._log(self.scan_id, text)

    def triage_started(self, total: int) -> None:
        self.total, self.started = total, time.monotonic()
        self.db.update_scan(self.scan_id, phase="triaging", progress_done=0, progress_total=total)
        self.base_stats = (self.db.scan(self.scan_id) or {}).get("stats", {})

    def verdict(self, v: Verdict) -> None:
        self.done += 1
        key = "failed" if v.triage_failed else v.verdict.value
        self.counts[key] = self.counts.get(key, 0) + 1
        self.tokens += v.tokens
        elapsed = time.monotonic() - self.started
        self.db.update_scan(
            self.scan_id,
            progress_done=self.done,
            stats=json.dumps(
                {
                    **self.base_stats,
                    "verdicts": self.counts,
                    "tokens": self.tokens,
                    "seconds_per_finding": round(elapsed / self.done, 1),
                    "seconds_left": round(elapsed / self.done * max(self.total - self.done, 0)),
                }
            ),
        )
        self.runner._check(self.scan_id)  # cancelling stops after the finding in progress

    def deep_dive_started(self, groups: int) -> None:
        if not groups:
            return
        # Progress lives in stats.deep_dive: progress_done/total stay the AI review's counts,
        # which the run views show as "N reviewed".
        self.dd_total = groups
        self.base_stats = (self.db.scan(self.scan_id) or {}).get("stats", {})
        empty = {"investigations": 0, "total": groups, "covers": 0, "failed": 0, "dropped": 0}
        self.db.update_scan(self.scan_id, phase="investigating",
                            stats=json.dumps({**self.base_stats, "deep_dive": empty}))  # fmt: skip

    def investigation(self, inv: Investigation) -> None:
        done = self.dd_done
        done.append(inv)
        stats = {"investigations": len(done), "total": self.dd_total,
                 "covers": sum(len(i.covers) for i in done),
                 "failed": sum(1 for i in done if i.failed),
                 "dropped": sum(len(i.dropped) for i in done)}  # fmt: skip
        self.db.update_scan(self.scan_id,
                            stats=json.dumps({**self.base_stats, "deep_dive": stats}))  # fmt: skip
        self.runner._check(self.scan_id)

    def summary_started(self) -> None:
        self.db.update_scan(self.scan_id, phase="summarizing")


@dataclass
class JobRunner:
    db: Database
    config: Config
    runs_dir: Path
    pipeline: Pipeline = field(default_factory=Pipeline)
    kb_loader: Callable[[Config], Any] | None = None
    engine: Any = None  # the managed AI runtime (starts the model a run asks for), when installed
    _queue: queue.Queue[tuple[str, int]] = field(default_factory=queue.Queue)
    _cancel: dict[int, threading.Event] = field(default_factory=dict)
    _bench_cancel: dict[int, threading.Event] = field(default_factory=dict)
    _thread: threading.Thread | None = None
    _stop: threading.Event = field(default_factory=threading.Event)

    # --- lifecycle ------------------------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="gapscan-jobs", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._queue.put(("stop", 0))
        if self._thread:
            self._thread.join(timeout=5)

    def submit(self, scan_id: int) -> None:
        self._cancel[scan_id] = threading.Event()
        self._queue.put(("scan", scan_id))

    def submit_benchmark(self, bench_id: int) -> None:
        self._bench_cancel[bench_id] = threading.Event()
        self._queue.put(("benchmark", bench_id))

    def cancel_benchmark(self, bench_id: int) -> bool:
        row = self.db.benchmark(bench_id)
        if row is None or row["status"] not in ("queued", "running"):
            return False
        if ev := self._bench_cancel.get(bench_id):
            ev.set()
        if row["status"] == "queued":
            self.db.update_benchmark(
                bench_id, status="cancelled", phase="cancelled", finished_at=now()
            )
        return True

    def cancel(self, scan_id: int) -> bool:
        ev = self._cancel.get(scan_id)
        row = self.db.scan(scan_id)
        if row is None or row["status"] not in ("queued", "running"):
            return False
        if ev:
            ev.set()
        if row["status"] == "queued":
            self.db.update_scan(scan_id, status="cancelled", phase="cancelled", finished_at=now())
        return True

    def wait_idle(self, timeout: float = 30) -> bool:
        """For tests: block until every queued job has finished."""
        import time

        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if (
                self._queue.empty()
                and not self.db.query("SELECT id FROM scans WHERE status IN ('queued','running')")
                and not self.db.query(
                    "SELECT id FROM benchmarks WHERE status IN ('queued','running')"
                )
            ):
                return True
            time.sleep(0.02)
        return False

    def run_dir(self, scan_id: int) -> Path:
        return self.runs_dir / str(scan_id)

    # --- worker ---------------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            kind, scan_id = self._queue.get()
            if kind == "stop" or self._stop.is_set():
                break
            if kind == "benchmark":
                self._benchmark(scan_id)
                continue
            row = self.db.scan(scan_id)
            if row is None or row["status"] != "queued":
                continue  # cancelled while waiting
            try:
                self._execute(scan_id)
            except Cancelled:
                self.db.append_log(scan_id, "cancelled")
                self.db.update_scan(
                    scan_id, status="cancelled", phase="cancelled", finished_at=now()
                )
            except Exception as exc:  # noqa: BLE001 - one failed job must never stop the worker
                log.exception("scan %s failed", scan_id)
                row = self.db.scan(scan_id) or {}
                stats = {
                    **row.get("stats", {}),
                    "failed_at": row.get("phase", ""),
                }  # which step it stopped in
                # Log the failure before flipping the status, so a reader that sees "failed"
                # always sees the reason too (watchers poll status, then read the log).
                self.db.append_log(
                    scan_id,
                    "FAILED: " + "".join(traceback.format_exception_only(type(exc), exc)).strip(),
                )
                self.db.update_scan(
                    scan_id,
                    status="failed",
                    phase="failed",
                    error=str(exc)[:500],
                    finished_at=now(),
                    stats=json.dumps(stats),
                )

    def _check(self, scan_id: int) -> None:
        ev = self._cancel.get(scan_id)
        if ev is not None and ev.is_set():
            raise Cancelled

    def _log(self, scan_id: int, message: str) -> None:
        self.db.append_log(scan_id, message)

    def _execute(self, scan_id: int) -> None:
        row = self.db.scan(scan_id)
        assert row is not None
        project = self.db.project(row["project_id"])
        if project is None:
            raise RuntimeError("the project was removed")
        target = Path(project["path"])
        opts = row["options"]
        cfg = effective_config(self.config, self.db.settings(), opts)
        if row["kind"] == "dryrun":
            return self._dry_run(scan_id, project, cfg, target, opts)
        if opts.get("triage") and self.engine is not None:
            self.db.update_scan(scan_id, status="running", phase="starting the AI engine")
            self.engine.prepare(cfg)
        run_dir = self.run_dir(scan_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        self.db.update_scan(
            scan_id,
            status="running",
            started_at=now(),
            phase="scanning",
            model=cfg.llm.model if opts.get("triage") else "",
        )
        rebuild = bool(opts.get("rebuild"))

        if rebuild:
            result = RunFolder(run_dir).load_scan()
            verdicts, summary, investigations = self._load_triage(run_dir, result)
            self._log(scan_id, "rebuilding the report with the current decisions")
        else:
            if not target.is_dir():
                raise RuntimeError(f"the project folder no longer exists: {target}")
            head = head_info(
                target
            )  # which branch/commit is checked out (read-only, never changed)
            if head.is_repo:
                self.db.update_scan(scan_id, branch=head.branch, commit_sha=head.commit)
                self._log(
                    scan_id,
                    "on branch "
                    + (head.branch or "(detached HEAD)")
                    + (f" at {head.commit}" if head.commit else "")
                    + (" with uncommitted changes" if head.dirty else ""),
                )
            self._log(scan_id, f"scanning {target}")
            result = self.pipeline.scan(cfg, target)
            base_ref = str(opts.get("base") or "")
            if base_ref:
                result = self._only_introduced(scan_id, result, target, base_ref)
            RunFolder(run_dir).save_scan(result)
            self._log(
                scan_id,
                f"{len(result.findings)} findings after merging; scanners: "
                + ", ".join(f"{r.scanner}={r.status}" for r in result.runs),
            )
            self.db.update_scan(
                scan_id,
                stats=json.dumps(
                    {
                        "raw": sum(r.finding_count for r in result.runs),
                        "merged": len(result.findings),
                        "scanners": [
                            {
                                "name": r.scanner,
                                "status": r.status,
                                "findings": r.finding_count,
                                "seconds": r.duration_s,
                            }
                            for r in result.runs
                        ],
                    }
                ),
            )
            self._check(scan_id)
            verdicts, summary, investigations = [], None, []
            if opts.get("triage"):
                limit = int(opts.get("limit", 40)) or 10**9  # 0 means review every finding
                dive = int(opts.get("deep_dive_limit", 0)) if opts.get("deep_dive") else 0
                verdicts, summary, investigations = self._triage(
                    scan_id, cfg, result, target, run_dir, limit, dive
                )

        self.db.update_scan(scan_id, phase="reporting")
        self._check(scan_id)
        data = self._report(scan_id, project, cfg, result, verdicts, summary, run_dir,
                            investigations)  # fmt: skip
        self._log(
            scan_id,
            f"done: risk {data.score.value:.0f}/100 (grade {data.score.grade}), {data.counts.open} open findings",
        )
        self.db.update_scan(
            scan_id, status="done", phase="done", finished_at=now(), findings=data.counts.total,
            open_findings=data.counts.open, score=data.score.value, grade=data.score.grade, model=data.freshness.model if verdicts else "",
        )  # fmt: skip

    def _only_introduced(
        self, scan_id: int, result: ScanResult, target: Path, base_ref: str
    ) -> ScanResult:
        """Keep only findings the change since `base_ref` introduced (diff-aware scope). Git is
        asked a read-only `diff`; the working tree is never touched. A ref git does not know stops
        the run with a clear message rather than silently scanning everything."""
        try:
            changes = changes_since(target, base_ref)
        except GitError as exc:
            raise RuntimeError(
                f"could not diff against {base_ref!r}: {exc}. Pick a branch or ref this checkout knows."
            ) from exc
        kept = introduced_by_changes(result.findings, changes)
        self._log(
            scan_id,
            f"diff scope: {len(kept)} of {len(result.findings)} findings introduced since {base_ref}",
        )
        return result.model_copy(update={"findings": kept})

    def _dry_run(
        self, scan_id: int, project: dict[str, Any], cfg: Config, target: Path, opts: dict[str, Any]
    ) -> None:
        """List what a run would do. Starts no scanner, calls no model, writes nothing to the project."""
        self.db.update_scan(scan_id, status="running", started_at=now(), phase="planning")
        similar = [
            x
            for x in self.db.scans(project["id"], 40)
            if x["kind"] == "scan"
            and x["status"] == "done"
            and bool(x["options"].get("triage")) == bool(opts.get("triage"))
            and x["started_at"]
            and x["finished_at"]
        ]
        last = None
        if similar:
            a, b = similar[0]["started_at"], similar[0]["finished_at"]
            last = max(
                0.0,
                (
                    datetime.fromisoformat(b.replace("Z", "+00:00"))
                    - datetime.fromisoformat(a.replace("Z", "+00:00"))
                ).total_seconds(),
            )
        plan = build_plan(cfg, target, opts, last)
        for line in plan_lines(plan):
            self._log(scan_id, line)
        self._check(scan_id)
        self.db.update_scan(
            scan_id,
            status="done",
            phase="done",
            finished_at=now(),
            stats=json.dumps({"plan": plan}),
        )

    def _benchmark(self, bench_id: int) -> None:
        """Run the shipped labeled cases through one model, one case at a time, on the shared queue."""
        row = self.db.benchmark(bench_id)
        if row is None or row["status"] != "queued":
            return  # cancelled while waiting
        cancel = self._bench_cancel.get(bench_id)
        try:
            cases = self.pipeline.benchmark_cases()
            if not cases:
                raise RuntimeError("no benchmark cases found (eval/triage_cases.json)")
            self.db.update_benchmark(
                bench_id,
                status="running",
                phase="benchmarking",
                started_at=now(),
                progress_total=len(cases),
            )
            cfg = effective_config(self.config, self.db.settings())
            if self.engine is not None:
                cfg.llm.model = row["model"]
                self.engine.prepare(cfg)
                if self.engine.managed() and cfg.llm.model != row["model"]:
                    raise RuntimeError(
                        f"{row['model']} is not downloaded; install it in Setup first"
                    )
            results: list[dict[str, Any]] = []
            for case in cases:
                if cancel is not None and cancel.is_set():
                    raise Cancelled
                results.append(self.pipeline.benchmark_case(cfg, row["model"], case))
                self.db.update_benchmark(bench_id, progress_done=len(results))
            summary = summarize_bench(row["model"], results)
            self.db.update_benchmark(
                bench_id,
                status="done",
                phase="done",
                finished_at=now(),
                summary=json.dumps({**summary, "cases": len(cases)}),
            )
        except Cancelled:
            self.db.update_benchmark(
                bench_id, status="cancelled", phase="cancelled", finished_at=now()
            )
        except Exception as exc:  # noqa: BLE001 - a failed benchmark must never stop the worker
            log.exception("benchmark %s failed", bench_id)
            self.db.update_benchmark(
                bench_id, status="failed", phase="failed", error=str(exc)[:300], finished_at=now()
            )

    def _triage(self, scan_id: int, cfg: Config, result: ScanResult, target: Path, run_dir: Path, limit: int,
                deep_dive_limit: int = 0) -> tuple[list[Verdict], RepoSummary | None, list[Investigation]]:  # fmt: skip
        """The model review (gapscan.services), with progress kept in the scan row."""
        row = self.db.scan(scan_id)
        memories = (
            [Memory.model_validate(m) for m in self.db.memories(row["project_id"])] if row else []
        )
        out = review_scan(cfg, result, target, steps=self.pipeline, limit=limit,
                          deep_dive_limit=deep_dive_limit, memories=memories,
                          hooks=_JobHooks(self, scan_id))  # fmt: skip
        self._check(scan_id)
        RunFolder(run_dir).save_triage(out)
        return out.verdicts, out.summary, out.investigations

    @staticmethod
    def _load_triage(
        run_dir: Path, scan: ScanResult
    ) -> tuple[list[Verdict], RepoSummary | None, list[Investigation]]:
        out = RunFolder(run_dir).load_triage(scan)
        return out.verdicts, out.summary, out.investigations

    def _baseline(self, scan_id: int, project_id: int) -> PreviousRun | None:
        wanted = (self.db.scan(scan_id) or {}).get("options", {}).get("baseline")
        prev = self.db.scan(int(wanted)) if wanted else None
        if prev is None or prev["project_id"] != project_id or prev["status"] != "done":
            prev = self.db.latest_done(project_id, before=scan_id)
        if prev is None:
            return None
        base = self.run_dir(prev["id"])
        for name in ("report.json", "scan.json"):  # the report form also carries the earlier score
            if (base / name).is_file():
                return load_previous(base / name)
        return None

    def _report(self, scan_id: int, project: dict[str, Any], cfg: Config, result: ScanResult, verdicts: list[Verdict], summary: RepoSummary | None, run_dir: Path,
                investigations: list[Investigation] | None = None) -> ReportData:  # fmt: skip
        decisions = Decisions(
            decisions=[
                Decision(
                    finding_id=d["finding_id"],
                    decision=d["decision"],
                    note=d["note"],
                    date=d["date"],
                )
                for d in self.db.decisions(project["id"])
            ]
        )
        kb = self.kb_loader(cfg) if self.kb_loader else None
        review = TriageOutput(
            verdicts=verdicts, summary=summary, investigations=investigations or []
        )
        data, html = build_dashboard(result, review, config=cfg, target=Path(project["path"]) if Path(project["path"]).is_dir() else None,
                                     baseline=self._baseline(scan_id, project["id"]), decisions=decisions, project=project["name"], kb=kb,
                                     head=SERVER_META.format(pid=project["id"]))  # fmt: skip
        (run_dir / "report.html").write_text(html, encoding="utf-8")
        (run_dir / "report.json").write_text(data.model_dump_json(), encoding="utf-8")
        write_exports(data, result, run_dir / "exports", "report")
        return data
