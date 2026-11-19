"""Run the Control Center against recorded data for UI development and screenshots.

No scanners and no model are needed: the scan and the verdicts come from tests/data/report, and the
AI review step is slowed down so the live run, queue and pipeline can be seen.

    uv run python tools/demo_manager.py            # prints the URL (with the session token)
    uv run python tools/demo_manager.py --seed 3   # also finishes 3 runs first, for history
"""

from __future__ import annotations

import argparse
import json
import tempfile
import threading
import time
from pathlib import Path

from gapscan.agent.review import deep_dive_groups
from gapscan.config import Config
from gapscan.models import Investigation, InvestigationAnswer, RepoSummary, ScanResult, Verdict
from gapscan.server import build_server
from gapscan.server.jobs import Pipeline

ROOT = Path(__file__).resolve().parent.parent
D = ROOT / "tests" / "data" / "report"


class DemoPipeline(Pipeline):
    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.scan_result = ScanResult.model_validate_json((D / "scan.json").read_text())
        tri = json.loads((D / "triage.json").read_text())
        self.verdicts = [Verdict.model_validate(v) for v in tri["verdicts"]]
        self.summary = RepoSummary.model_validate(tri["summary"])

    def scan(self, cfg, target):
        time.sleep(self.delay * 2)
        return self.scan_result.model_copy(deep=True)

    def triage(self, cfg, result, target, limit, on_verdict, memories=None):
        out = []
        for v in (self.verdicts * 20)[:limit]:
            time.sleep(self.delay)
            v = v.model_copy(update={"tokens": 2400, "seconds": self.delay})
            on_verdict(v)
            out.append(v)
        return out

    def deep_dive(self, cfg, result, target, verdicts, limit, on_investigation):
        """Canned investigations (no model) shaped like a real grounded one."""
        out = []
        for g in deep_dive_groups(cfg, result, verdicts, limit):
            time.sleep(self.delay * 3)
            f = g[0]
            where = f"{f.file}:{f.start_line}" if f.file and f.start_line else None
            answer = InvestigationAnswer.model_validate({
                "summary": f"{f.title[:200]}. No control in the project prevents it, and it is "
                           "reachable in every build.",
                "protection": "absent",
                "evidence": [{"claim": "the flagged code runs on untrusted input", "ref": where,
                              "effect": "undermines"}] if where else [],
                "remediation": ["Apply the fix suggested by the review.",
                                "Add a scanner rule in CI so it cannot come back."],
                "verification": ["Re-run the scan: the finding is gone."],
                "target_state": "Done when the scan no longer reports this issue.",
            })  # fmt: skip
            inv = Investigation(finding_id=f.id, covers=[m.id for m in g], answer=answer,
                                model="demo", prompt_version="investigate_v2",
                                tool_calls=[], tokens=5200, seconds=self.delay * 3)  # fmt: skip
            on_investigation(inv)
            out.append(inv)
        return out

    def summarize(self, cfg, result, verdicts):
        return self.summary

    def benchmark_cases(self):
        return [{"id": f"case{i}", "expected": "true_positive"} for i in range(8)]

    def benchmark_case(self, cfg, model, case):
        time.sleep(self.delay)
        ok = case["id"] not in ("case3", "case6")
        return {
            "id": case["id"],
            "expected": case["expected"],
            "status": "ok",
            "attempts": 1,
            "correct": ok,
            "seconds": 2.0 + self.delay,
            "verdict": "true_positive" if ok else "false_positive",
            "confidence": 0.9,
            "prompt_tokens": 100,
            "completion_tokens": 20,
        }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--delay", type=float, default=0.4, help="seconds per reviewed finding")
    ap.add_argument("--seed", type=int, default=0, help="finished runs to create first")
    args = ap.parse_args()
    tmp = Path(tempfile.mkdtemp(prefix="gapscan-demo-"))
    app = tmp / "payments-api"
    app.mkdir()
    import shutil

    shutil.copytree(
        ROOT / "eval" / "fixtures" / "vuln-app", app, dirs_exist_ok=True
    )  # real source to show
    cfg = Config(
        data={"dir": str(tmp / "data")},
        scanners={"osv": {"db_dir": str(tmp / "o")}, "trivy": {"cache_dir": str(tmp / "t")}},
    )
    server = build_server(cfg, port=args.port, pipeline=DemoPipeline(args.delay))
    project = server.db.add_project("payments-api", str(app))
    if args.seed:
        for i in range(args.seed):
            sid = server.db.create_scan(project["id"], {"triage": i % 2 == 0, "limit": 12})
            server.jobs.submit(sid)
        server.jobs.wait_idle(120)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(server.url(), flush=True)
    print("Press Ctrl-C to stop.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.jobs.stop()


if __name__ == "__main__":
    main()
