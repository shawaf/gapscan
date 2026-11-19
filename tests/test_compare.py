"""One definition of new, fixed and unchanged findings between two runs (gapscan/compare.py)."""

from __future__ import annotations

from gapscan.compare import RunDiff, compare_reports, diff_open


def test_diff_keeps_each_runs_order_and_ignores_repeats() -> None:
    assert diff_open(["a", "b", "c", "b"], ["d", "c", "a", "e"]) == RunDiff(
        new=["d", "e"], fixed=["b"], unchanged=["c", "a"]
    )
    assert diff_open([], ["x"]) == RunDiff(new=["x"], fixed=[], unchanged=[])


def test_comparing_reports_counts_open_findings_only() -> None:
    def row(i: str, open_: bool = True, **kw: object) -> dict[str, object]:
        return {"id": i, "title": f"t{i}", "severity": "high", "open": open_, **kw}

    older = [row("a", file="app.py", start_line=3), row("b"), row("c", open_=False)]
    newer = [row("b"), row("c"), row("d", package="lodash", severity_adjusted="low")]
    out = compare_reports(older, newer)
    # c was closed (decided) in the older run, so reopening it counts as new
    assert [r["id"] for r in out["new"]] == ["c", "d"] and out["unchanged"] == 1
    assert out["fixed"] == [{"id": "a", "title": "ta", "severity": "high",
                             "location": "app.py:3", "verdict": None}]  # fmt: skip
    assert out["new"][1]["location"] == "lodash" and out["new"][1]["severity"] == "low"
