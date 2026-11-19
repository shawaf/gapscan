"""Score the taint engine and the own rules outside the OWASP Benchmark: SecuriBench Micro (an
independent test family) and real applications with published labels (cogniumhq/sast-benchmarks).

Nothing here was used to develop the engine; it is the generalization check for the numbers in
docs/results/RESULTS.md. Each case is a file (or a function in a file) that is labeled vulnerable
or safe for a category; it counts as flagged when an engine reports a matching CWE there.

    uv run python tools/realapp_bench.py            # needs the clones under data/eval-targets/

Sources (cloned into data/eval-targets/, never committed; commits printed with the results):
  securibench-micro  https://github.com/too4words/securibench-micro
  webgoat            https://github.com/WebGoat/WebGoat
  dvja               https://github.com/appsecco/dvja
  pygoat             https://github.com/adeyosemanputra/pygoat
  dvpwa              https://github.com/anxolerd/dvpwa
  juice-shop, nodegoat (pinned in eval/targets.toml); labels: cogniumhq/sast-benchmarks
"""

from __future__ import annotations

import csv
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(p) for p in sorted((ROOT / "packages").glob("*/src"))]  # the workspace packages
sys.path.insert(0, str(ROOT / "tools"))

from rule_bench import OWN, cwes, semgrep  # noqa: E402

from gapscan.context.treesitter import functions, parse  # noqa: E402
from gapscan.taint.engine import scan_dir  # noqa: E402

TARGETS = ROOT / "data/eval-targets"
LABELS = TARGETS / "sast-benchmarks/datasets"
CATEGORY_CWES: dict[str, set[int]] = {
    "sqli": {89, 564}, "cmdi": {78, 77, 88}, "xss": {79, 80}, "pathtraver": {22, 23, 36, 73},
    "ssrf": {918}, "redirect": {601}, "ldapi": {90}, "xpathi": {643}, "codeinj": {94, 95, 96},
    "deserialization": {502}, "nosqli": {943, 89}, "trustbound": {501},
}  # fmt: skip
DATAFLOW = set().union(*CATEGORY_CWES.values())


@dataclass
class Case:
    cid: str
    file: str  # relative to the app root
    func: str | None
    category: str
    vulnerable: bool


@dataclass
class App:
    name: str
    root: Path
    language: str
    own: str
    cases: list[Case] = field(default_factory=list)
    skipped: int = 0  # labels outside the data-flow categories (idor, csrf, ...)


def _commit(path: Path) -> str:
    out = subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=False)
    return out.stdout.strip() or "?"


def labeled_app(name: str, label_dir: str, language: str, own: str) -> App | None:
    root = TARGETS / name
    labels = LABELS / label_dir / "expectedresults.csv"
    if not root.is_dir() or not labels.is_file():
        return None
    app = App(name, root, language, own)
    rows = [r for r in csv.reader(labels.open()) if r and not r[0].startswith("#") and r[0] != "filePath"]
    for i, row in enumerate(rows):
        path, cat, vul = row[0], row[1], row[2].strip().lower() == "true"
        file, _, func = path.partition(":")
        if cat not in CATEGORY_CWES:
            app.skipped += 1
            continue
        if not (root / file).is_file():
            app.skipped += 1
            continue
        app.cases.append(Case(f"{name}#{i}", file, func or None, cat, vul))
    return app


def securibench() -> App | None:
    root = TARGETS / "securibench-micro"
    if not root.is_dir():
        return None
    app = App("securibench-micro", root, "java", "java")
    for f in sorted(root.rglob("*.java")):
        text = f.read_text("utf-8", "replace")
        m = re.search(r'vuln_count\s*=\s*"(\d+)"', text)
        if not m:
            continue
        rel = str(f.relative_to(root))
        group = f.parent.name
        app.cases.append(Case(f"securibench/{rel}", rel, None, group, int(m.group(1)) > 0))
    return app


def _func_range(app: App, file: str, func: str) -> tuple[int, int] | None:
    pf = parse(file, (app.root / file).read_bytes())
    if pf is None:
        return None
    for fn in functions(pf):
        if fn.name == func:
            return fn.start_line, fn.end_line
    return None


def flagged(app: App, results: list[tuple[str, int, set[int]]], case: Case, any_cwe: bool) -> bool:
    rng = _func_range(app, case.file, case.func) if case.func else None
    want = DATAFLOW if any_cwe else CATEGORY_CWES[case.category]
    for file, line, cw in results:
        if file != case.file or not cw & want:
            continue
        if rng is None or rng[0] <= line <= rng[1]:
            return True
    return False


def engines(app: App) -> dict[str, list[tuple[str, int, set[int]]]]:
    taint = [(h.file, h.line, {int(h.cwe.split("-")[1])}) for h in scan_dir(app.root)]
    raw = semgrep([OWN / app.own], [app.root])
    ours = []
    for r in raw:
        try:
            rel = str(Path(r["path"]).resolve().relative_to(app.root.resolve()))
        except ValueError:
            rel = r["path"]
        ours.append((rel, int(r["start"]["line"]), cwes(r)))
    rest = [x for x in ours if not x[2] & DATAFLOW]
    # "reported": everything GapScan shows (rules and data flow); "confirmed": what it ranks first
    # (injection classes only when the data-flow engine agrees, other classes from the rules)
    return {"own rules": ours, "taint": taint, "reported": ours + taint, "confirmed": rest + taint}


def report(app: App) -> dict[str, tuple[int, int, int, int]]:
    res = engines(app)
    any_cwe = app.name == "securibench-micro"  # its labels count any injection class
    print(f"\n=== {app.name} ({app.language}, commit {_commit(app.root)}): {len(app.cases)} cases"
          + (f", {app.skipped} labels outside the data-flow categories" if app.skipped else ""))
    print(f"{'group':18} {'real/safe':>9} " + " ".join(f"{k:>22}" for k in res))
    groups: dict[str, list[Case]] = defaultdict(list)
    for c in app.cases:
        groups[c.category].append(c)
    totals: dict[str, list[int]] = {k: [0, 0, 0, 0] for k in res}
    for g, cs in sorted(groups.items()):
        cells = []
        for k, rs in res.items():
            tp = sum(1 for c in cs if c.vulnerable and flagged(app, rs, c, any_cwe))
            fp = sum(1 for c in cs if not c.vulnerable and flagged(app, rs, c, any_cwe))
            real = sum(1 for c in cs if c.vulnerable)
            safe = len(cs) - real
            for i, v in enumerate((tp, real, fp, safe)):
                totals[k][i] += v
            cells.append(_cell(tp, real, fp, safe))
        real = sum(1 for c in cs if c.vulnerable)
        print(f"{g:18} {real:>4}/{len(cs) - real:<4} " + " ".join(f"{x:>22}" for x in cells))
    real = sum(1 for c in app.cases if c.vulnerable)
    print(f"{'ALL':18} {real:>4}/{len(app.cases) - real:<4} " + " ".join(f"{_cell(*totals[k]):>22}" for k in res))
    return {k: (t[0], t[1], t[2], t[3]) for k, t in totals.items()}


def _cell(tp: int, real: int, fp: int, safe: int) -> str:
    t = tp / real if real else 0.0
    f = fp / safe if safe else 0.0
    score = f"({(t - f) * 100:+4.0f})" if safe else "(catch)"
    return f"{tp}/{real} {t * 100:3.0f}% fa {fp}/{safe}  {score}"


if __name__ == "__main__":
    apps = [
        securibench(),
        labeled_app("webgoat", "webgoat", "java", "java"),
        labeled_app("dvja", "dvja", "java", "java"),
        labeled_app("pygoat", "pygoat", "python", "python"),
        labeled_app("dvpwa", "dvpwa", "python", "python"),
        labeled_app("juice-shop", "juice-shop", "typescript", "javascript"),
        labeled_app("nodegoat", "nodegoat", "javascript", "javascript"),
    ]
    grand: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    for a in apps:
        if a is None:
            continue
        for k, v in report(a).items():
            for i, x in enumerate(v):
                grand[k][i] += x
    print("\n=== all sets combined")
    for k, (tp, real, fp, safe) in grand.items():
        print(f"{k:12} {_cell(tp, real, fp, safe)}")
