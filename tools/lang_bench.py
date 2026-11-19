"""Score GapScan's own C# and PHP rules (and, for comparison, the community Semgrep rules) on labeled
benchmarks, the same way tools/rule_bench.py does for the other languages.

    uv run python tools/lang_bench.py csharp            # dev half only (what rules were tuned on)
    uv run python tools/lang_bench.py php --final       # also the held-out test half

Corpora (downloaded into data/eval-targets/, never committed):
  csharp  NIST Juliet C# 1.3 (SARD suite 110, sha256 2e6dbac4...c8e8f8): the `_01` file of every case in
          the injection CWE folders; each file's Bad() method is vulnerable, each Good*() method is safe
          (function-level labels). Plus cogniumhq/sast-benchmarks csharp-synthetic (15 files).
  php     NIST PHP Vulnerability Test Suite (SARD suite 103, sha256 3407473f...80f8c): 42,212 files, each
          labeled bad or good in its manifest; scored on a fixed sample per CWE. Plus DVWA (low.php is
          vulnerable, impossible.php is the secure version of the same module).

A case counts as flagged when a finding with a CWE of the expected class falls in its file (and line
range, for function-level labels). Score = catch rate minus false-alarm rate (Youden), in points.
Cases are split into dev and test halves by a hash of their id; rules are tuned on dev only.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from rule_bench import COMMUNITY, OWN, cwes, half, semgrep  # noqa: E402

TARGETS = ROOT / "data/eval-targets"
CATEGORY_CWES: dict[str, set[int]] = {
    "sqli": {89, 564}, "cmdi": {78, 77, 88}, "xss": {79, 80, 81, 83}, "pathtraver": {22, 23, 36, 73},
    "ssrf": {918}, "redirect": {601}, "ldapi": {90}, "xpathi": {643}, "codeinj": {94, 95, 96},
    "deserialization": {502}, "xxe": {611}, "fileinclusion": {98, 22, 94, 829}, "upload": {434},
}  # fmt: skip
ALIASES = {"deser": "deserialization", "ldap": "ldapi", "xpath": "xpathi", "fi": "fileinclusion"}


@dataclass
class Case:
    cid: str
    file: Path
    category: str
    vulnerable: bool
    lines: tuple[int, int] | None = None  # function-level label
    note: str = ""  # e.g. the input kind, for breakdowns


# --- C# --------------------------------------------------------------------------------------------

JULIET_DIRS = {
    "CWE23_Relative_Path_Traversal": "pathtraver", "CWE36_Absolute_Path_Traversal": "pathtraver",
    "CWE78_OS_Command_Injection": "cmdi", "CWE80_XSS": "xss", "CWE81_XSS_Error_Message": "xss",
    "CWE83_XSS_Attribute": "xss", "CWE89_SQL_Injection": "sqli", "CWE90_LDAP_Injection": "ldapi",
    "CWE94_Improper_Control_of_Generation_of_Code": "codeinj", "CWE643_Xpath_Injection": "xpathi",
    "CWE601_Open_Redirect": "redirect",
}  # fmt: skip
METHOD = re.compile(
    r"^\s*(?:public|private|protected)\s+(?:override\s+|static\s+)*[\w<>\[\]?]+\s+(Bad|Good\w*)\s*\("
)
JULIET_SOURCE = re.compile(r"CWE\d+_\w+?__(?:Web_)?(\w+?)_(?:\w+_)?\d\d\.cs$")


def juliet_methods(path: Path) -> list[tuple[str, int, int]]:
    """(name, first line, last line) of Bad() and every Good*() helper, from Juliet's fixed layout."""
    lines = path.read_text("utf-8", "replace").splitlines()
    starts = [(i + 1, m.group(1)) for i, line in enumerate(lines) if (m := METHOD.match(line))]
    out = []
    for k, (start, name) in enumerate(starts):
        end = starts[k + 1][0] - 1 if k + 1 < len(starts) else len(lines)
        if name == "Good":  # only dispatches to the helpers
            continue
        out.append((name, start, end))
    return out


def csharp_cases() -> list[Case]:
    cases: list[Case] = []
    base = TARGETS / "juliet-csharp/src/testcases"
    for folder, cat in JULIET_DIRS.items():
        for f in sorted((base / folder).rglob("*_01.cs")):
            source = f.name.split("__", 1)[1].split("_")[0] if "__" in f.name else ""
            for name, start, end in juliet_methods(f):
                cases.append(
                    Case(f"juliet/{f.stem}/{name}", f, cat, name == "Bad", (start, end), source)
                )
    syn = TARGETS / "sast-benchmarks/datasets/csharp-synthetic"
    labels = syn / "expectedresults.csv"
    if labels.is_file():
        for row in csv.reader(labels.open()):
            if not row or row[0].startswith("#") or row[0] == "name":
                continue
            cat = ALIASES.get(row[1], row[1])
            f = syn / "testcode" / f"{row[0]}.cs"
            if f.is_file() and cat in CATEGORY_CWES:
                cases.append(
                    Case(f"synthetic/{row[0]}", f, cat, row[2] == "true", None, "synthetic")
                )
    return cases


# --- PHP -------------------------------------------------------------------------------------------

SARD_CWES = {"89": "sqli", "79": "xss", "78": "cmdi", "90": "ldapi", "91": "xpathi", "95": "codeinj",
             "98": "fileinclusion", "601": "redirect"}  # fmt: skip
REQUEST_INPUTS = re.compile(r"\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|serialize string in POST")
DVWA = {"sqli": "sqli", "sqli_blind": "sqli", "exec": "cmdi", "xss_r": "xss", "xss_s": "xss",
        "fi": "fileinclusion", "open_redirect": "redirect", "upload": "upload"}  # fmt: skip


def php_cases(per_group: int) -> list[Case]:
    cases: list[Case] = []
    groups: dict[tuple[str, bool, bool], list[Case]] = defaultdict(list)
    for manifest in sorted((TARGETS / "php-sard").glob("*/manifest.sarif")):
        run = json.loads(manifest.read_text())["runs"][0]
        props = run["properties"]
        src = manifest.parent / run["artifacts"][0]["location"]["uri"]
        m = re.search(r"CWE_(\d+)", src.name)
        cat = SARD_CWES.get(m.group(1) if m else "")
        if not cat:
            continue
        request = bool(REQUEST_INPUTS.search(props.get("description", "")))
        bad = props.get("state") == "bad"
        groups[(cat, bad, request)].append(
            Case(
                f"sard/{manifest.parent.name}",
                src,
                cat,
                bad,
                None,
                "request" if request else "other",
            )
        )
    rng = random.Random(7)  # a fixed sample per (category, label, input kind): same cases every run
    for key in sorted(groups):
        items = groups[key]
        cases += items if len(items) <= per_group else rng.sample(items, per_group)
    dvwa = TARGETS / "dvwa/vulnerabilities"
    for module, cat in DVWA.items():
        for level, bad in (("low", True), ("impossible", False)):
            f = dvwa / module / "source" / f"{level}.php"
            if f.is_file():
                cases.append(Case(f"dvwa/{module}/{level}", f, cat, bad, None, "dvwa"))
    return cases


# --- scoring ---------------------------------------------------------------------------------------


def findings(configs: list[Path], files: list[Path]) -> dict[Path, list[tuple[int, set[int]]]]:
    out: dict[Path, list[tuple[int, set[int]]]] = defaultdict(list)
    for i in range(0, len(files), 2000):  # keep the command line short
        for r in semgrep(configs, files[i : i + 2000]):
            out[Path(r["path"]).resolve()].append((int(r["start"]["line"]), cwes(r)))
    return out


def flagged(case: Case, found: dict[Path, list[tuple[int, set[int]]]]) -> bool:
    want = CATEGORY_CWES[case.category]
    for line, cw in found.get(case.file.resolve(), []):
        if cw & want and (case.lines is None or case.lines[0] <= line <= case.lines[1]):
            return True
    return False


def cell(tp: int, real: int, fp: int, safe: int) -> str:
    t, f = (tp / real if real else 0.0), (fp / safe if safe else 0.0)
    score = f"{(t - f) * 100:+4.0f}" if real and safe else "  n/a"
    return f"{tp:>4}/{real:<4} {t * 100:3.0f}%  fa {fp:>4}/{safe:<4} {f * 100:3.0f}%  {score}"


def report(
    title: str, cases: list[Case], engines: dict[str, dict[Path, list[tuple[int, set[int]]]]]
) -> None:
    print(f"\n== {title}: {len(cases)} cases ({sum(c.vulnerable for c in cases)} vulnerable)")
    print(f"{'category':16} " + " | ".join(f"{k:^37}" for k in engines))
    by_cat: dict[str, list[Case]] = defaultdict(list)
    for c in cases:
        by_cat[c.category].append(c)
    for cat in [*sorted(by_cat), "ALL"]:
        cs = cases if cat == "ALL" else by_cat[cat]
        cells = []
        for found in engines.values():
            tp = sum(1 for c in cs if c.vulnerable and flagged(c, found))
            fp = sum(1 for c in cs if not c.vulnerable and flagged(c, found))
            real = sum(1 for c in cs if c.vulnerable)
            cells.append(cell(tp, real, fp, len(cs) - real))
        print(f"{cat:16} " + " | ".join(cells))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("language", choices=["csharp", "php"])
    ap.add_argument("--final", action="store_true", help="also print the held-out TEST half")
    ap.add_argument(
        "--per-group", type=int, default=150, help="PHP: SARD cases per (CWE, label, input)"
    )
    ap.add_argument("--by-input", action="store_true", help="DEV half broken down by input kind")
    ap.add_argument(
        "--why", help="DEV half only: list GapScan's misses and false alarms for a category"
    )
    args = ap.parse_args()
    cases = csharp_cases() if args.language == "csharp" else php_cases(args.per_group)
    if not cases:
        raise SystemExit("no cases: download the corpora first (see this file's docstring)")
    files = sorted({c.file for c in cases})
    engines = {"community": findings([COMMUNITY / args.language], files),
               "gapscan": findings([OWN / args.language], files)}  # fmt: skip
    halves = {
        "dev": [c for c in cases if half(c.cid) == "dev"],
        "test": [c for c in cases if half(c.cid) == "test"],
    }
    report(f"{args.language} DEV half", halves["dev"], engines)
    if args.by_input:
        for note in sorted({c.note for c in cases}):
            report(
                f"{args.language} DEV half, input: {note}",
                [c for c in halves["dev"] if c.note == note],
                engines,
            )
    if args.why:
        for c in halves["dev"]:
            if c.category == args.why and c.vulnerable != flagged(c, engines["gapscan"]):
                kind = "MISS" if c.vulnerable else "FALSE ALARM"
                print(f"  {kind:11} {c.cid}  {c.file.relative_to(ROOT)}:{c.lines or ''}")
    if args.final:
        report(f"{args.language} TEST half (held out)", halves["test"], engines)
        for note in sorted({c.note for c in cases}):
            report(
                f"{args.language} TEST half, input: {note}",
                [c for c in halves["test"] if c.note == note],
                engines,
            )


if __name__ == "__main__":
    main()
