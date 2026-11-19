"""Score GapScan's own Semgrep rules against labeled benchmarks, next to the community rules, with a dev/test split.

Method (so the numbers mean something):
  * Cases are split in two halves by a hash of their id. Rules are tuned looking at the DEV half only; the TEST
    half is printed only with --final, at checkpoints. A rule must never mention a benchmark's own helper classes or
    names: it has to be a rule that would make sense in any application.
  * A case is "flagged" when a finding in its file carries a CWE of the expected class (the OWASP scorecard rule).
    Score = true-positive rate - false-positive rate (Youden), per category and overall, the measure the published
    tool comparisons use. Corpora without safe cases (only positives) report the catch rate only.

    uv run python tools/rule_bench.py java            # dev half only
    uv run python tools/rule_bench.py python --final  # dev and test halves
Languages: java, python, javascript, kotlin, swift, plus the real-app sets swift-dvia, swift-igoat, android-apps, kotlin-apps and (Dart) dart.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OWN = ROOT / "packages/gapscan-security/src/gapscan/rules/semgrep"
COMMUNITY = ROOT / "data/semgrep-rules"
TARGETS = ROOT / "data/eval-targets"
CACHE = ROOT / "data/rule-bench-cache"

Cases = dict[str, tuple[str, bool]]  # id -> (category, is a real vulnerability)


@dataclass
class Corpus:
    scan: list[Path]  # what semgrep scans
    cases: Cases
    case_of: Callable[
        [str], str | list[str] | None
    ]  # finding path -> case id (or several: one file, several labels)
    cwes: dict[str, set[int]]  # category -> CWEs that count
    own: list[str]  # our rule folders
    community: list[str]  # community folders to compare with
    has_safe: bool = True
    case_cwes: dict[str, set[int]] | None = (
        None  # expected CWEs per case (overrides the category's set)
    )


def half(name: str) -> str:
    return "dev" if int(hashlib.sha1(name.encode()).hexdigest(), 16) % 2 == 0 else "test"


def semgrep(configs: list[Path], targets: list[Path]) -> list[dict]:
    args = [
        "semgrep",
        "scan",
        "--metrics=off",
        "--disable-version-check",
        "--quiet",
        "--json",
        "--timeout",
        "30",
    ]
    for c in configs:
        args += ["--config", str(c)]
    proc = subprocess.run([*args, *map(str, targets)], capture_output=True, text=True, timeout=3600)  # noqa: S603
    return json.loads(proc.stdout)["results"]


def cwes(result: dict) -> set[int]:
    raw = result["extra"].get("metadata", {}).get("cwe", [])
    raw = [raw] if isinstance(raw, str) else raw
    return {int(m) for r in raw for m in re.findall(r"CWE-(\d+)", str(r))}


# --- corpora ---------------------------------------------------------------------------------------

JAVA_CWES = {
    "cmdi": {78, 77, 88}, "crypto": {327, 326, 328}, "hash": {328, 327, 916, 759, 760}, "ldapi": {90},
    "pathtraver": {22, 23, 36, 73}, "securecookie": {614, 1004, 311}, "sqli": {89, 564}, "trustbound": {501},
    "weakrand": {330, 338, 331}, "xpathi": {643}, "xss": {79, 80},
}  # fmt: skip
PYTHON_CWES = {
    "cmdi": {78, 77, 88}, "codeinj": {94, 95, 96, 1336}, "deserialization": {502}, "hash": {328, 327, 916, 759, 760},
    "ldapi": {90}, "pathtraver": {22, 23, 36, 73}, "redirect": {601}, "securecookie": {614, 1004, 311},
    "sqli": {89, 564}, "trustbound": {501}, "weakrand": {330, 338, 331}, "xpathi": {643}, "xss": {79, 80}, "xxe": {611, 827},
}  # fmt: skip
JS_CWES = {
    "sqli": {89, 564}, "cmdi": {78, 77, 88}, "xss": {79, 80}, "codeinj": {94, 95, 96, 1336}, "ssrf": {918},
    "pathtraver": {22, 23, 36, 73}, "nosqli": {943, 89}, "redirect": {601},
}  # fmt: skip


def _owasp_csv(csv_file: Path) -> Cases:
    cases: Cases = {}
    for line in csv_file.read_text().splitlines():
        parts = line.split(",")
        if len(parts) >= 4 and not line.startswith("#"):
            cases[parts[0]] = (parts[1], parts[2].strip().lower() == "true")
    return cases


def java_corpus() -> Corpus:
    base = TARGETS / "benchmark-java"
    pat = re.compile(r"(BenchmarkTest\d{5})\.java$")
    return Corpus([base / "src/main/java/org/owasp/benchmark/testcode"], _owasp_csv(next(base.glob("expectedresults-*.csv"))),
                  lambda p: (m.group(1) if (m := pat.search(p)) else None), JAVA_CWES, ["java"], ["java"])  # fmt: skip


def python_corpus() -> Corpus:
    base = TARGETS / "benchmark-python"
    pat = re.compile(r"(BenchmarkTest\d{5})\.py$")
    return Corpus([base / "testcode"], _owasp_csv(base / "expectedresults-0.1.csv"),
                  lambda p: (m.group(1) if (m := pat.search(p)) else None), PYTHON_CWES, ["python"], ["python"])  # fmt: skip


def _unparseable(folder: Path, language: str) -> set[str]:
    """File names in `folder` that semgrep cannot parse (checked once, with a rule that matches any call)."""
    cache = CACHE / f"unparseable-{folder.name}.json"
    if cache.exists():
        return set(json.loads(cache.read_text()))
    CACHE.mkdir(parents=True, exist_ok=True)
    probe = CACHE / f"probe-{language}.yaml"
    probe.write_text(
        f"rules:\n  - id: probe\n    languages: [{language}]\n    message: probe\n    severity: INFO\n    pattern: $X.$Y($...A)\n"
    )
    proc = subprocess.run(["semgrep", "scan", "--config", str(probe), str(folder), "--metrics=off", "--disable-version-check", "--quiet", "--json"],  # noqa: S603
                          capture_output=True, text=True, timeout=600)  # fmt: skip
    bad = sorted(
        {
            Path(e["path"]).name
            for e in json.loads(proc.stdout)["errors"]
            if "yntax" in str(e.get("type")) or "arse" in str(e.get("type"))
        }
    )
    cache.write_text(json.dumps(bad))
    return set(bad)


def javascript_corpus() -> Corpus:
    sb = TARGETS / "sast-benchmarks/datasets"
    cases: Cases = {}
    by_path: dict[str, str] = {}
    # synthetic Node.js set: one file per case
    for line in (sb / "nodejs-synthetic/expectedresults.csv").read_text().splitlines():
        p = line.split(",")
        if len(p) >= 4 and not line.startswith("#"):
            cid = f"synthetic/{p[0]}"
            cases[cid] = (p[1], p[2].strip().lower() == "true")
            by_path[str((sb / "nodejs-synthetic/testcode" / f"{p[0]}.js").resolve())] = cid
    # Juice Shop and NodeGoat: labeled files in the applications (the apps are the local copies)
    for app, label in (("juice-shop", "juice-shop"), ("nodegoat", "nodegoat")):
        for row in csv.reader((sb / label / "expectedresults.csv").open()):
            if len(row) >= 4 and not row[0].startswith("#") and row[0] != "filePath":
                f = (TARGETS / app / row[0]).resolve()
                if f.is_file():
                    cid = f"{app}/{row[0]}#{row[1]}"
                    cases[cid] = (row[1], row[2].strip().lower() == "true")
                    by_path[str(f)] = cid
    scan = [sb / "nodejs-synthetic/testcode"]
    scan += sorted({Path(p).parent for p in by_path if "synthetic" not in p})
    # Juice Shop code-fix challenges: every wrong fix still contains the weakness, the `_correct` one is safe
    fixes = TARGETS / "juice-shop/data/static/codefixes"
    kinds = {"dbSchemaChallenge": "sqli", "unionSqlInjectionChallenge": "sqli", "loginAdminChallenge": "sqli", "loginBenderChallenge": "sqli",
             "loginJimChallenge": "sqli", "noSqlReviewsChallenge": "nosqli", "localXssChallenge": "xss", "restfulXssChallenge": "xss",
             "xssBonusChallenge": "xss", "redirectChallenge": "redirect", "redirectCryptoCurrencyChallenge": "redirect"}  # fmt: skip
    for f in sorted(fixes.glob("*.ts")):
        name = f.name.split("_")[0]
        if name in kinds:
            cid = f"codefix/{f.name}"
            cases[cid] = (kinds[name], not f.name.endswith("_correct.ts"))
            by_path[str(f.resolve())] = cid
    # fragments that do not parse cannot be judged by any tool, so they are left out
    broken = _unparseable(fixes, "typescript")
    for fid in [
        cid for cid in cases if cid.startswith("codefix/") and cid.split("/", 1)[1] in broken
    ]:
        del cases[fid]
    scan.append(fixes)
    return Corpus(scan, cases, lambda p: by_path.get(str(Path(p).resolve())), JS_CWES, ["javascript"], ["javascript", "typescript"])  # fmt: skip


# --- mobile: OWASP MASTG demo apps (positives from "the test fails", a few secure variants from "the test passes") ---
MOBILE_BUCKETS: list[tuple[str, str, set[int]]] = [  # bucket, regex on the demo title, CWEs that count
    ("hardcodedkey", r"hardcoded", {321, 798, 259}),
    ("weakhash", r"broken hashing|hash", {328, 327, 916}),
    ("weakcipher", r"broken (symmetric )?encryption|ecb|insufficient key|key generation", {327, 326, 780}),
    ("weakrand", r"random|non-random", {330, 338, 331}),
    ("tls", r"trustmanager|hostnameverifier|any server certificate|ignoring tls|minimum tls|cleartext|http urls|ats |wrong host|certificate", {295, 297, 319, 327}),
    ("storage", r"sharedpreferences|external storage|logging|log |backup|keyboard|caching|encryptedsharedpreferences", {312, 313, 922, 532, 200, 276, 311, 524, 921, 530}),
    ("webview", r"webview|uiwebview|evaluatejavascript|html injection", {749, 79, 200, 926, 22, 94, 1104}),
    ("component", r"exported|unprotected|pendingintent|deep link|url scheme|fileprovider|implicit intent|contentprovider|universal link", {926, 927, 939, 284, 200, 20}),
    ("injection", r"sql injection|path traversal|deserialization", {89, 22, 502}),
]  # fmt: skip
MOBILE_CWES = {b: c for b, _, c in MOBILE_BUCKETS}


def mobile_corpus(language: str) -> Corpus:
    import yaml

    demos = TARGETS / "mastg/demos"
    ext = {"kotlin": ".kt", "swift": ".swift"}[language]
    cases: Cases = {}
    dirs: list[Path] = []
    for md in sorted(demos.glob("*/MASVS-*/MASTG-DEMO-*/MASTG-DEMO-*.md")):
        d = md.parent
        if not any(f.suffix == ext for f in d.iterdir()):
            continue
        text = md.read_text()
        title = (yaml.safe_load(text.split("---")[1]).get("title") or "").lower() + " "
        evaluation = text.split("## Evaluation")[-1].lower() if "## Evaluation" in text else ""
        verdict = (
            "fail"
            if re.search(r"test fail|fails because|\bfails\b", evaluation)
            else ("pass" if re.search(r"test pass|passes because|\bpasses\b", evaluation) else "")
        )
        bucket = next((b for b, rx, _ in MOBILE_BUCKETS if re.search(rx, title)), None)
        if (
            bucket and verdict and not re.search(r"frida|idevicesyslog|runtime", title)
        ):  # runtime tracing demos are not about source
            cases[d.name] = (bucket, verdict == "fail")
            dirs.append(d)
    return Corpus(
        dirs,
        cases,
        lambda p: m.group(0) if (m := re.search(r"MASTG-DEMO-\d+", p)) else None,
        MOBILE_CWES,
        [language],
        [language],
    )


def _files_corpus(
    roots: list[Path], suffix: str, labels: dict[str, str], own: list[str], community: list[str]
) -> Corpus:
    """A real app: files that implement a known vulnerability, labeled by hand from the app's own challenge or exercise
    names (positives only). A finding anywhere in the file with a CWE of the label's class counts."""
    cases: Cases = {}
    by_path: dict[str, str] = {}
    for root in roots:
        for f in root.rglob(f"*{suffix}"):
            if f.stem in labels:
                cases[f.stem] = (labels[f.stem], True)
                by_path[str(f.resolve())] = f.stem
    return Corpus(
        roots, cases, lambda p: by_path.get(str(Path(p).resolve())), MOBILE_CWES, own, community
    )


def dvia_corpus() -> Corpus:
    """DVIA-v2 (a deliberately vulnerable iOS app), only the files whose code implements the vulnerable challenge."""
    return _files_corpus([TARGETS / "dvia/DVIA-v2/DVIA-v2"], ".swift", {
        "PListViewController": "storage", "DeviceLogsViewController": "storage", "CoreDataViewController": "storage",
        "RealmViewController": "storage", "CouchbaseLiteViewController": "storage", "KeychainViewController": "storage",
        "PasteboardViewController": "storage", "BrokenCryptographyDetailsViewController": "hardcodedkey",
        "ClientSideInjectionDetailViewController": "webview", "TransportLayerProtectionViewController": "tls",
    }, ["swift"], ["swift"])  # fmt: skip


def igoat_corpus() -> Corpus:
    """iGoat-Swift (OWASP): each exercise folder is one vulnerability."""
    return _files_corpus([TARGETS / "igoat/iGoat-Swift/iGoat-Swift/Source/Exercises"], ".swift", {
        "YapExerciseVC": "storage", "WebkitCacheExerciseVC": "storage", "CoreDataExerciseVC": "storage",
        "PlistStorageExerciseViewController": "storage", "NSUserDefaultsStorageExerciseVC": "storage",
        "BinaryCookiesExerciseVC": "storage", "RealmExerciseVC": "storage", "CouchBaseExerciseVC": "storage",
        "DeviceLogsExerciseVC": "storage", "BackgroundingExerciseVC": "storage",
        "CutAndPasteExerciseVC": "storage", "BrokenCryptographyExerciseVC": "hardcodedkey",
        "RandomKeyGenerationExerciseVC": "weakrand", "CrossSiteScriptingExerciseVC": "webview",
        "SQLInjectionExerciseVC": "injection", "ServerCommunicationExerciseVC": "tls", "URLSchemeAttackExerciseVC": "component",
    }, ["swift"], ["swift"])  # fmt: skip


def android_apps_corpus() -> Corpus:
    """DIVA and InsecureBankv2 (Java Android): files implementing a documented vulnerability, labeled from the apps' own
    challenge names. The manifest rules live with the Kotlin rules, so both folders count as ours."""
    return _files_corpus([TARGETS / "diva/app/src/main/java", TARGETS / "bank/InsecureBankv2/app/src/main/java"], ".java", {
        "LogActivity": "storage", "InsecureDataStorage1Activity": "storage", "InsecureDataStorage2Activity": "storage",
        "InsecureDataStorage3Activity": "storage", "InsecureDataStorage4Activity": "storage", "HardcodeActivity": "hardcodedkey",
        "Hardcode2Activity": "hardcodedkey", "APICredsActivity": "hardcodedkey", "APICreds2Activity": "hardcodedkey",
        "SQLInjectionActivity": "injection", "NotesProvider": "injection", "InputValidation2URISchemeActivity": "webview",
        "CryptoClass": "weakcipher", "TrackUserContentProvider": "injection", "MyWebViewClient": "webview",
        "DoLogin": "tls", "FilePrefActivity": "storage", "LoginActivity": "storage", "MyBroadCastReceiver": "component",
    }, ["java", "kotlin"], ["java", "kotlin"])  # fmt: skip


def kotlin_apps_corpus() -> Corpus:
    """InsecureShop (19 documented vulnerabilities, mapped to the file that implements each) and KotlinGoat (one file per
    vulnerability, listed in its README). Positives only."""
    cases: Cases = {}
    by_path: dict[str, str] = {}
    labels = {
        "insecureshop": {
            "WebViewActivity": "webview", "WebView2Activity": "webview", "PrivateActivity": "webview", "CustomWebViewClient": "tls",
            "LoginActivity": "storage", "Prefs": "storage", "ChooserActivity": "component", "AboutUsActivity": "component",
            "ProductListActivity": "component", "InsecureShopProvider": "component", "InsecureshopFileProvider": "component",
        },
        "kotlingoat": {
            "CodeInjection": "codeinj", "CommandInjection": "cmdi", "InsecureRandom": "weakrand", "PrivacyViolation": "storage",
            "UnvalidatedSSLCertificateHostname": "tls", "UnvalidatedRedirects": "redirect",
        },
    }  # fmt: skip
    for app, names in labels.items():
        for f in (TARGETS / app).rglob("*.kt"):
            if f.stem in names:
                cid = f"{app}/{f.stem}"
                cases[cid] = (names[f.stem], True)
                by_path[str(f.resolve())] = cid
    cwes_all = {**MOBILE_CWES, "codeinj": {94, 95, 96}, "cmdi": {78, 77, 88}, "redirect": {601}}
    return Corpus(
        [TARGETS / "insecureshop", TARGETS / "kotlingoat"],
        cases,
        lambda p: by_path.get(str(Path(p).resolve())),
        cwes_all,
        ["kotlin"],
        ["kotlin"],
    )


def dart_corpus() -> Corpus:
    """DVMA (a deliberately vulnerable Flutter app): every module that a static rule could plausibly see, scored against
    the CWEs the project's own registry lists for that module. Positives only."""
    import yaml

    root = TARGETS / "dvma"
    groups = {
        "crypto",
        "storage",
        "network",
        "input_validation",
        "code_quality",
        "platform",
        "native_bridge",
    }
    cases: Cases = {}
    per_case: dict[str, set[int]] = {}
    by_path: dict[str, str] = {}
    union: dict[str, set[int]] = defaultdict(set)
    for f in sorted((root / "config/registry/categories").rglob("*.yaml")):
        for cat, body in (yaml.safe_load(f.read_text()) or {}).items():
            if cat not in groups:
                continue
            for mod in body.get("vulnerabilities", []):
                folders = [d for d in (root / "lib/modules" / cat).rglob(mod["id"]) if d.is_dir()]
                numbers = {int(m) for c in mod.get("cwe", []) for m in re.findall(r"(\d+)", str(c))}
                if not folders or not numbers:
                    continue
                logic = [
                    d for d in folders[0].rglob("*.dart") if not d.name.endswith("_screen.dart")
                ]
                if (
                    not logic
                ):  # the module folder is only a UI screen: the simulated weakness lives elsewhere
                    continue
                cases[mod["id"]] = (cat, True)
                per_case[mod["id"]] = numbers
                union[cat] |= numbers
                for dart in folders[0].rglob("*.dart"):
                    by_path[str(dart.resolve())] = mod["id"]
    return Corpus(
        [root / "lib/modules"],
        cases,
        lambda p: by_path.get(str(Path(p).resolve())),
        dict(union),
        ["dart"],
        ["dart"],
        case_cwes=per_case,
    )


GO_CWES = {
    "sqli": {89, 564},
    "cmdi": {78, 77, 88},
    "pathtraver": {22, 23, 36, 73},
    "xss": {79, 80},
    "ssrf": {918},
}


def go_corpus() -> Corpus:
    """Go: the synthetic set (one file per case, with safe look-alikes) plus Vulnerability-goapp, a real app labeled per
    file and category (including files known to be safe for a category)."""
    sb = TARGETS / "sast-benchmarks/datasets"
    cases: Cases = {}
    by_path: dict[str, list[str]] = defaultdict(list)
    for row in csv.reader((sb / "go-synthetic/expectedresults.csv").open()):
        if len(row) >= 4 and not row[0].startswith("#") and row[0] != "name":
            cid = f"synthetic/{row[0]}"
            cases[cid] = (row[1], row[2].strip().lower() == "true")
            by_path[str((sb / "go-synthetic/testcode" / f"{row[0]}.go").resolve())].append(cid)
    for row in csv.reader((sb / "vulnerability-goapp/expectedresults.csv").open()):
        if len(row) >= 4 and not row[0].startswith("#") and row[0] != "filePath":
            f = (TARGETS / "goapp" / row[0]).resolve()
            if f.is_file() and row[1] in GO_CWES:
                cid = f"goapp/{row[0]}#{row[1]}"
                cases[cid] = (row[1], row[2].strip().lower() == "true")
                by_path[str(f)].append(cid)
    return Corpus(
        [sb / "go-synthetic/testcode", TARGETS / "goapp"],
        cases,
        lambda p: by_path.get(str(Path(p).resolve())),
        GO_CWES,
        ["go"],
        ["go"],
    )


CORPORA: dict[str, Callable[[], Corpus]] = {
    "java": java_corpus, "python": python_corpus, "javascript": javascript_corpus,
    "kotlin": lambda: mobile_corpus("kotlin"), "swift": lambda: mobile_corpus("swift"),
    "go": go_corpus, "kotlin-apps": kotlin_apps_corpus, "dart": dart_corpus, "swift-dvia": dvia_corpus, "swift-igoat": igoat_corpus, "android-apps": android_apps_corpus,
}  # fmt: skip


# --- scoring ---------------------------------------------------------------------------------------


def score(results: list[dict], c: Corpus) -> dict:
    flagged: set[str] = set()
    for r in results:
        ids = c.case_of(r["path"])
        for cid in [ids] if isinstance(ids, str) else (ids or []):
            if cid in c.cases and cwes(r) & (
                c.case_cwes[cid] if c.case_cwes else c.cwes.get(c.cases[cid][0], set())
            ):
                flagged.add(cid)
    out: dict[str, dict[str, dict[str, int]]] = {
        "dev": defaultdict(lambda: defaultdict(int)),
        "test": defaultdict(lambda: defaultdict(int)),
    }
    for cid, (cat, real) in c.cases.items():
        b = out[half(cid)][cat]
        b["real" if real else "fake"] += 1
        b["real_flagged" if real else "fake_flagged"] += int(cid in flagged)
    return out


def rates(b: dict[str, int]) -> tuple[float, float]:
    return (
        b["real_flagged"] / b["real"] if b["real"] else 0.0,
        b["fake_flagged"] / b["fake"] if b["fake"] else 0.0,
    )


DATAFLOW_CWE_IDS = {
    89,
    564,
    78,
    77,
    88,
    22,
    23,
    36,
    73,
    79,
    80,
    918,
    601,
    90,
    643,
    502,
    94,
    95,
    96,
    1336,
    501,
    943,
}
TAINT_ROOTS = {  # the taint engine needs the whole source tree (helpers live outside the test files)
    "java": TARGETS / "benchmark-java/src/main/java",
    "python": TARGETS / "benchmark-python",
}


def taint_results(lang: str) -> list[dict]:
    """GapScan's inter-procedural taint engine, as results in the same shape as semgrep's."""
    sys.path[:0] = [str(p) for p in sorted((ROOT / "packages").glob("*/src"))]
    from gapscan.taint.engine import scan_dir

    root = TAINT_ROOTS[lang]
    return [
        {"path": str(root / h.file), "extra": {"metadata": {"cwe": [h.cwe]}}}
        for h in scan_dir(root)
    ]


def run(lang: str, with_taint: bool = False) -> tuple[Corpus, dict]:
    c = CORPORA[lang]()
    CACHE.mkdir(parents=True, exist_ok=True)
    cache = CACHE / f"{lang}-community.json"
    if cache.exists():
        community = json.loads(cache.read_text())
    else:
        community = semgrep([COMMUNITY / f for f in c.community], c.scan)
        cache.write_text(json.dumps(community))
    ours = semgrep([OWN / f for f in c.own], c.scan)
    out = {"community": score(community, c), "ours": score(ours, c)}
    if with_taint:
        taint = taint_results(lang)
        out["taint"] = score(taint, c)
        out["ours+taint"] = score(ours + taint, c)
        # What GapScan ranks as confirmed: injection classes need the data-flow engine to agree,
        # every other class (crypto, hashing, randomness, cookies, XXE) comes from the rules.
        ours_rest = [r for r in ours if not (cwes(r) & DATAFLOW_CWE_IDS)]
        out["gapscan"] = score(ours_rest + taint, c)
    return c, out


def report(lang: str, parts: list[str], with_taint: bool = False) -> None:
    c, sc = run(lang, with_taint)
    names = list(sc)
    for part in parts:
        n = sum(1 for cid in c.cases if half(cid) == part)
        print(f"\n=== {lang}, {part} half ({n} cases) ===  cells: caught% / false-alarm%  (score)")
        print(f"{'category':14} {'real/fake':>9} " + " ".join(f"{k:>22}" for k in names))
        tot = {k: defaultdict(int) for k in sc}
        for cat in sorted(c.cwes):
            b0 = sc["ours"][part][cat]
            if not (b0["real"] or b0["fake"]):
                continue
            cells = []
            for k in sc:
                b = sc[k][part][cat]
                for key, v in b.items():
                    tot[k][key] += v
                t, f = rates(b)
                cells.append(f"{t * 100:4.0f}% /{f * 100:4.0f}% ({(t - f) * 100:+4.0f})")
            print(
                f"{cat:14} {b0['real']:>4}/{b0['fake']:<4} " + " ".join(f"{x:>22}" for x in cells)
            )
        cells = []
        for k in sc:
            t, f = rates(tot[k])
            cells.append(f"{t * 100:4.0f}% /{f * 100:4.0f}% ({(t - f) * 100:+4.0f})")
        print(
            f"{'ALL':14} {tot['ours']['real']:>4}/{tot['ours']['fake']:<4} "
            + " ".join(f"{x:>22}" for x in cells)
        )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("language", choices=sorted(CORPORA))
    ap.add_argument("--final", action="store_true", help="also print the held-out TEST half")
    ap.add_argument(
        "--taint", action="store_true", help="also score the taint engine (java, python)"
    )
    a = ap.parse_args()
    report(a.language, ["dev", "test"] if a.final else ["dev"], a.taint)
    sys.exit(0)
