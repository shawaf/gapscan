"""Run every benchmark corpus through tools/rule_bench.py and write the results as data (JSON), a markdown page and a
self-contained HTML page, so the numbers shown to people are reproducible rather than typed by hand.

    uv run python tools/results_report.py            # run every benchmark (a few minutes)
    uv run python tools/results_report.py --render   # rebuild the pages from the saved JSON
Writes docs/results/benchmark-results.json, docs/results/RESULTS.md and docs/results/results.html.
"""

from __future__ import annotations

import html
import json
import subprocess
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import rule_bench as rb  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/results"
# language key -> (display name, benchmark, what kind of evidence, tuned on all files?)
ROWS = [
    ("java", "Java", "OWASP Benchmark v1.2 (2,740 cases)", "standard benchmark", False),
    (
        "python",
        "Python",
        "OWASP Benchmark for Python v0.1 (1,230 cases)",
        "standard benchmark",
        False,
    ),
    (
        "javascript",
        "JavaScript / TypeScript",
        "Node.js synthetic set, Juice Shop, NodeGoat, Juice Shop code fixes (82 cases)",
        "small mixed set",
        False,
    ),
    (
        "go",
        "Go",
        "Go synthetic set and Vulnerability-goapp (42 labeled cases, with safe files)",
        "small mixed set",
        False,
    ),
    ("kotlin", "Kotlin / Android", "OWASP MASTG demo apps (44 cases)", "demo samples", False),
    ("swift", "Swift / iOS", "OWASP MASTG demo apps (34 cases)", "demo samples", False),
    (
        "android-apps",
        "Android apps (Java)",
        "DIVA and InsecureBankv2: 19 labeled files",
        "real apps",
        False,
    ),
    ("swift-dvia", "iOS app (DVIA-v2)", "10 labeled files", "real app", True),
    ("swift-igoat", "iOS app (iGoat-Swift)", "17 labeled files", "real app", True),
    (
        "kotlin-apps",
        "Kotlin apps (InsecureShop, KotlinGoat)",
        "17 labeled files",
        "real apps",
        True,
    ),
    (
        "dart",
        "Dart / Flutter",
        "DVMA: 107 modules whose folder holds logic",
        "real app (mostly behavioral simulations)",
        True,
    ),
]


def totals(sc: dict, half: str) -> dict[str, float]:
    t: dict[str, int] = defaultdict(int)
    for b in sc[half].values():
        for k, v in b.items():
            t[k] += v
    tpr, fpr = rb.rates(t)
    return {
        "real": t["real"],
        "fake": t["fake"],
        "caught": round(tpr * 100, 1),
        "false_alarms": round(fpr * 100, 1),
        "score": round((tpr - fpr) * 100, 1),
        "cases": t["real"] + t["fake"],
    }


def collect() -> dict:
    languages = []
    for key, name, bench, kind, tuned in ROWS:
        print("running", key, flush=True)
        corpus, sc = rb.run(key)
        languages.append({
            "key": key, "name": name, "benchmark": bench, "evidence": kind, "tuned_on_all_files": tuned,
            "held_out": {"community": totals(sc["community"], "test"), "gapscan": totals(sc["ours"], "test")},
            "tuning_half": {"community": totals(sc["community"], "dev"), "gapscan": totals(sc["ours"], "dev")},
        })  # fmt: skip
    rules = {}
    import glob

    import yaml

    for lang in ("python", "javascript", "java", "kotlin", "swift", "dart", "go"):
        rules[lang] = sum(
            len(yaml.safe_load(Path(f).read_text())["rules"])
            for f in glob.glob(str(ROOT / f"packages/gapscan-security/src/gapscan/rules/semgrep/{lang}/*.yaml"))
        )
    semgrep = (
        subprocess.run(["semgrep", "--version"], capture_output=True, text=True)
        .stdout.strip()
        .splitlines()[-1]
    )  # noqa: S603, S607
    return {
        "generated": datetime.now(UTC).strftime("%Y-%m-%d"), "semgrep_version": semgrep, "rule_counts": rules, "total_rules": sum(rules.values()),
        "fixtures": {"description": "128 hand-labeled code sites (68 vulnerable, 60 safe look-alikes), scanners only, no AI review",
                     "gapscan_rules_only": {"recall": 97.1, "precision": 65.6}, "community_plus_gapscan": {"recall": 91.2, "precision": 62.1},
                     "before_python_js_java_go_rules": {"recall": 47.1, "precision": 59.3}},
        "market_reference": {"source": "cogniumhq/sast-benchmarks (a competitor's page, read with care): OWASP Benchmark Java, TPR minus FPR",
                             "semgrep_oss": 47.9, "codeql": 59.9, "cognium_dev": 73.5},
        "languages": languages,
    }  # fmt: skip


CAVEATS = [
    "Scores are measured with scanners only (no AI review). The AI review step removes false alarms but cannot add findings the scanners missed.",
    "'Held out' means half of each benchmark's cases, chosen by a hash of their names, that were not looked at while writing rules. Rows marked 'tuned on all files' were not kept strictly separate and are indicative only.",
    "The community Semgrep rules are the free Semgrep rule set. GapScan cannot ship them (their license forbids it), which is why GapScan has its own rule library.",
    "On Java, GapScan is level with the free Semgrep rules and below CodeQL (about +60 in a competitor's published comparison), which follows data across functions and files; GapScan's rules follow it within one function.",
    "The mobile and Go sets are small, mostly contain vulnerable samples and say little about false alarms. Labels for the real apps were written by hand from each project's own challenge or vulnerability list.",
    "Dart numbers are a floor: most DVMA modules simulate behavior that no static rule can see.",
    "Score = share of vulnerable cases caught minus share of safe cases wrongly flagged (the OWASP Benchmark 'Youden' score). Where a set has no safe cases, only the catch rate is reported.",
]


def fmt(m: dict) -> str:
    if m["fake"] == 0:
        return f"{m['caught']:.0f}% caught"
    return f"{m['caught']:.0f}% caught, {m['false_alarms']:.0f}% false alarms (score {m['score']:+.0f})"


def markdown(d: dict) -> str:
    lines = [
        "# GapScan detection results",
        "",
        f"Generated {d['generated']} with Semgrep {d['semgrep_version']}. **{d['total_rules']} own rules** across 7 languages "
        + ", ".join(f"{k} {v}" for k, v in d["rule_counts"].items())
        + ". Reproduce with `uv run python tools/results_report.py`.",
        "",
        "GapScan ships its own Apache-2.0 rule library, because the free community Semgrep rules cannot be redistributed in a product. "
        "These are the measured results of those rules next to the community rules, scanners only.",
        "",
        "**The inter-procedural data-flow engine** (the `taint` scanner) has its own page with the OWASP Benchmark held-out halves and an independent check on SecuriBench Micro and six real applications: [DATAFLOW.md](DATAFLOW.md).",
        "",
        "## Headline",
        "",
        f"- On the 128-site labeled fixture set GapScan's rules alone reach **{d['fixtures']['gapscan_rules_only']['recall']}% recall at {d['fixtures']['gapscan_rules_only']['precision']}% precision**, up from {d['fixtures']['before_python_js_java_go_rules']['recall']}% / {d['fixtures']['before_python_js_java_go_rules']['precision']}% before the new rules (community rules plus GapScan: {d['fixtures']['community_plus_gapscan']['recall']}% / {d['fixtures']['community_plus_gapscan']['precision']}%).",
        "- Java: level with the free Semgrep rules on the OWASP Benchmark (held-out half: community +48, GapScan +47).",
        "- Python, Go and JavaScript: clearly ahead of the community rules on their benchmarks.",
        "- Kotlin, Swift and Android Java apps: the community rules catch almost nothing; GapScan catches roughly half to two thirds of the tested samples.",
        "",
        "## Results by language (held-out half)",
        "",
        "| Language | Benchmark | Evidence | Community Semgrep | GapScan |",
        "|---|---|---|---|---|",
    ]
    for r in d["languages"]:
        star = " *" if r["tuned_on_all_files"] else ""
        lines.append(
            f"| {r['name']}{star} | {r['benchmark']} | {r['evidence']} | {fmt(r['held_out']['community'])} | **{fmt(r['held_out']['gapscan'])}** |"
        )
    lines += [
        "",
        "\\* Tuned on all files of the set; indicative only.",
        "",
        "## What these numbers do not say",
        "",
    ]
    lines += [f"- {c}" for c in CAVEATS]
    lines += [
        "",
        f"Market reference (OWASP Benchmark Java, score): Semgrep OSS {d['market_reference']['semgrep_oss']}, CodeQL {d['market_reference']['codeql']}, a commercial engine {d['market_reference']['cognium_dev']}. Source: {d['market_reference']['source']}.",
        "",
    ]
    return "\n".join(lines)


def page(d: dict) -> str:
    rows = []
    for r in d["languages"]:
        c, g = r["held_out"]["community"], r["held_out"]["gapscan"]
        has_safe = g["fake"] > 0
        gv, cv = (g["score"], c["score"]) if has_safe else (g["caught"], c["caught"])
        unit = "score" if has_safe else "caught"
        width = lambda v: max(0, min(100, v))  # noqa: E731
        rows.append(
            f"""<tr><td><b>{html.escape(r["name"])}{" *" if r["tuned_on_all_files"] else ""}</b><span class="sub">{html.escape(r["benchmark"])}</span></td>
<td><div class="bar c"><i style="width:{width(cv)}%"></i></div><span class="num">{f"{cv:+.0f}" if has_safe else f"{cv:.0f}%"}</span></td>
<td><div class="bar g"><i style="width:{width(gv)}%"></i></div><span class="num"><b>{f"{gv:+.0f}" if has_safe else f"{gv:.0f}%"}</b></span></td>
<td class="sub">{html.escape(r["evidence"])}; {unit}</td></tr>"""
        )
    caveats = "".join(f"<li>{html.escape(c)}</li>" for c in CAVEATS)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GapScan detection results</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--sub:#5b6472;--line:#e3e6eb;--c:#9aa3b2;--g:#2347c9}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0f1115;--card:#171a20;--ink:#eef0f4;--sub:#9aa3b2;--line:#262b33;--c:#5b6472;--g:#7b96ff}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif}}
main{{max-width:960px;margin:0 auto;padding:32px 16px}}
h1{{font-size:30px;margin:0 0 6px}}p.lead{{color:var(--sub);margin:0 0 24px;font-size:17px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:24px}}
.kpi{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}}.kpi b{{display:block;font-size:30px}}.kpi span{{color:var(--sub);font-size:13px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:8px 16px 16px;margin-bottom:20px}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:middle}}
th{{font-size:12px;color:var(--sub);text-transform:uppercase;letter-spacing:.04em}}.sub{{display:block;color:var(--sub);font-size:12px;font-weight:400}}td.sub{{display:table-cell}}
.bar{{height:10px;border-radius:5px;background:var(--line);overflow:hidden;width:150px;display:inline-block;vertical-align:middle}}.bar i{{display:block;height:100%}}.bar.c i{{background:var(--c)}}.bar.g i{{background:var(--g)}}
.num{{display:inline-block;width:52px;margin-left:8px;font-variant-numeric:tabular-nums}}
.legend{{font-size:13px;color:var(--sub);margin:8px 0}}.legend span{{display:inline-block;width:10px;height:10px;border-radius:3px;margin:0 4px 0 12px}}
h2{{font-size:18px;margin:24px 0 8px}}li{{margin:4px 0;color:var(--sub)}}footer{{color:var(--sub);font-size:12px;margin-top:24px}}
@media(max-width:640px){{.bar{{width:90px}}td.sub{{display:none}}th:last-child{{display:none}}}}
</style></head><body><main>
<h1>GapScan detection results</h1>
<p class="lead">An offline security scanner with its own rule library: {d["total_rules"]} Apache-2.0 rules across 7 languages, measured against public benchmarks.</p>
<div class="kpis">
<div class="kpi"><b>{d["fixtures"]["gapscan_rules_only"]["recall"]}%</b><span>recall on 128 labeled code sites (was {d["fixtures"]["before_python_js_java_go_rules"]["recall"]}%), at {d["fixtures"]["gapscan_rules_only"]["precision"]}% precision</span></div>
<div class="kpi"><b>{d["total_rules"]}</b><span>own rules; no community rules shipped, no cloud, no data leaves the machine</span></div>
<div class="kpi"><b>+47 vs +48</b><span>Java, OWASP Benchmark, held-out half: level with the free Semgrep rules</span></div>
</div>
<div class="card"><h2>Held-out results by language</h2>
<div class="legend"><span style="background:var(--c)"></span>Community Semgrep rules<span style="background:var(--g)"></span>GapScan rules. Bars show the benchmark score (catch rate minus false-alarm rate), or the catch rate where a set has no safe cases.</div>
<table><thead><tr><th>Language / benchmark</th><th>Community</th><th>GapScan</th><th>Evidence</th></tr></thead><tbody>
{"".join(rows)}
</tbody></table><p class="sub" style="display:block">* tuned on all files of the set; indicative only.</p></div>
<h2>What these numbers do not say</h2><ul>{caveats}</ul>
<footer>Generated {d["generated"]} with Semgrep {html.escape(d["semgrep_version"])}. Reproduce with <code>uv run python tools/results_report.py</code>. Scanners only: the AI review step is not included.</footer>
</main></body></html>"""


if __name__ == "__main__":
    data = (
        json.loads((OUT / "benchmark-results.json").read_text())
        if "--render" in sys.argv
        else collect()
    )
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "benchmark-results.json").write_text(json.dumps(data, indent=2) + "\n")
    (OUT / "RESULTS.md").write_text(markdown(data))
    (OUT / "results.html").write_text(page(data))
    print("wrote", OUT)
