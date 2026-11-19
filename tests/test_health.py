from __future__ import annotations

from datetime import date

from gapscan.config import Config
from gapscan.doctor import Check, Status
from gapscan.server import health


def test_a_missing_scanner_says_what_is_lost_and_how_to_fix_it():
    rows = health.rows(
        Config(),
        [
            Check("trivy", Status.MISSING, "trivy not on PATH"),
            Check("semgrep", Status.OK, "1.176.0"),
        ],
    )
    trivy, semgrep = rows
    assert (
        trivy["status"] == "problem"
        and trivy["component"] == "Trivy"
        and trivy["group"] == "Scanner"
    )
    assert "coverage is missing" in trivy["detail"] and "install" in trivy["fix"].lower()
    assert semgrep["status"] == "ok" and semgrep["version"] == "1.176.0" and semgrep["fix"] == ""


def test_model_and_data_rows_carry_actionable_hints():
    cfg = Config()
    rows = {r["name"]: r for r in health.rows(cfg, [
        Check("llm endpoint", Status.MISSING, "unreachable"), Check("llm model", Status.MISSING, "not pulled"),
        Check("kb index", Status.MISSING, "not found"), Check("osv db", Status.WARN, "empty"),
        Check("semgrep rules", Status.MISSING, "not found"),
    ])}  # fmt: skip
    assert "Setup" in rows["llm endpoint"]["fix"] and "ollama serve" in rows["llm endpoint"]["fix"]
    assert "ollama pull " in rows["llm model"]["fix"]
    assert "kb build" in rows["kb index"]["fix"] and rows["osv db"]["status"] == "warn"
    # the community rule folder is optional: GapScan's own rules still run, so it is a warning, not a problem
    assert (
        rows["semgrep rules"]["status"] == "warn" and "still run" in rows["semgrep rules"]["detail"]
    )


def test_summary_counts_by_status_and_own_rules_are_counted():
    items = [{"status": "ok"}, {"status": "ok"}, {"status": "warn"}, {"status": "problem"}]
    assert health.summary(items) == {"ok": 2, "warn": 1, "problem": 1}
    assert health.own_rule_count() >= 30


def test_freshness_shows_age_and_flags_stale_data():
    out = health.freshness(
        {"osv_db": "2026-09-21", "kev": "2026-08-01", "epss": "unknown"},
        30,
        today=date(2026, 10, 3),
    )
    by = {r["name"]: r for r in out}
    assert (
        by["osv_db"]["age_days"] == 12
        and by["osv_db"]["stale"] is False
        and 0.39 < by["osv_db"]["used"] < 0.41
    )
    assert by["kev"]["age_days"] == 63 and by["kev"]["stale"] is True and by["kev"]["used"] == 1.0
    assert by["epss"]["age_days"] is None and by["epss"]["stale"] is False


def test_plan_estimates_read_in_seconds_when_short_and_minutes_when_long():
    from gapscan.server.plan import plan_lines

    base = {"folder": "/x", "exists": True, "by_language": {}, "scannable": 0, "files": 0, "scanners": [],
            "ai": {"enabled": False}, "ignore": {"file": False, "paths": 0, "rules": 0}}  # fmt: skip
    assert (
        "about 7 s, from the last similar run" in plan_lines({**base, "estimate_seconds": 7.4})[-1]
    )
    assert (
        "about 21 min, from the last similar run"
        in plan_lines({**base, "estimate_seconds": 1260})[-1]
    )
    assert "from the last" not in " ".join(plan_lines({**base, "estimate_seconds": None}))
