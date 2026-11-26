<div align="center">

# GapScan

**The free, offline security scanner that tells you which OWASP requirements your code misses, with proof.**

GapScan scans a codebase on your own machine, maps every finding to OWASP Top 10:2025, ASVS 5.0,
API Security Top 10 and MASVS, and backs each one with evidence: a scanner result, a data-flow path
or the quoted code. An optional local AI model triages, explains and proposes fixes. Your code
never leaves the machine.

[![PyPI](https://img.shields.io/pypi/v/gapscan?color=2ea44f&label=pypi)](https://pypi.org/project/gapscan/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fshawaf%2Fgapscan-2496ed)](docs/offline.md#docker)
[![CI](https://github.com/shawaf/gapscan/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shawaf/gapscan/actions/workflows/ci.yml)
[![Offline](https://img.shields.io/badge/network%20during%20scan-none-2ea44f)](docs/offline.md)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%3A2025%20%C2%B7%20ASVS%205.0-000000)](docs/rules.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

[![GapScan dashboard overview](docs/images/report-overview.png)](docs/images/report-overview.png)

*The report dashboard: one self-contained HTML file, no CDN, no network.*

[Try it](#try-it-in-a-minute) · [Demo](#see-it-run) · [Compare](#how-it-compares) · [Screenshots](#screenshots) · [CI](#in-every-pull-request) · [AI assistants](#for-ai-coding-assistants) · [Trust](#built-to-be-trusted) · [Evaluation](#evaluation-read-this-before-trusting-any-number) · [Docs](#docs) · [Contribute](#contributing)

</div>

<!-- mcp-name: io.github.shawaf/gapscan -->

## Try it in a minute

Pick one. Each gets you a scan and an HTML report of the current folder.

**Docker** (nothing to install; every scanner and fresh vulnerability data are in the image):

```bash
mkdir -p gapscan-out
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/scan:ro" -v "$PWD/gapscan-out:/out" ghcr.io/shawaf/gapscan:1 scan /scan -o /out/scan.json
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/scan:ro" -v "$PWD/gapscan-out:/out" ghcr.io/shawaf/gapscan:1 report /out/scan.json -t /scan -o /out/report.html
```

**pipx** (Python 3.11+; `gapscan setup` downloads the scanners and the vulnerability data once):

```bash
pipx install gapscan
gapscan setup
gapscan scan . -o scan.json && gapscan report scan.json -t . -o report.html
gapscan serve --open             # or the local web UI: projects, history, your decisions
```

**Desktop app** (macOS, Apple silicon): download `GapScan.dmg` from the
[latest release](https://github.com/shawaf/gapscan/releases/latest). It is not signed yet, so the first
time, right-click the app and choose **Open**. The app's Setup page installs the scanners and data.

**In your pull requests**: see [In every pull request](#in-every-pull-request). It's one step in a
workflow, and nothing to install.

## See it run

[![GapScan from install to results](docs/images/demo.gif)](https://gapscan.dev/#demo)

*Real output on the sample app in `eval/fixtures/vuln-app`: scan, report, a zero-day watch alert and
dependency fixes verified by a rescan. The full 3-minute video, from `git clone` to the local web UI,
is on [gapscan.dev](https://gapscan.dev/#demo). Recorded with scanners only; the optional AI review is
not shown, and the watch step uses an older data snapshot so a new advisory can arrive.*

## At a glance

| You get | How |
|---|---|
| Every finding mapped to the standard | OWASP Top 10:2025, ASVS 5.0, API Security Top 10 2023, MASVS, GenAI LLM Top 10 2026 |
| Proof, not a list of warnings | each gap links to a scanner result, a data-flow path or the quoted code |
| Fewer false alarms | optional local AI review: *confirmed / likely / false positive / needs review*, labeled as AI-generated |
| Alerts when a new CVE hits code you already scanned | `gapscan watch`, exploited and reachable first |
| Fixes you can check | `gapscan fix` and `gapscan fix-deps` keep a patch only if an offline rescan shows the gap gone; `gapscan pr` opens the pull request when you ask |
| Proof from the running app | `--import` ZAP and nuclei results; code they confirm is marked and ranked up |
| Checks in every pull request | a GitHub Action that needs nothing installed, plus GitLab, Jenkins, Azure and pre-commit |
| Nothing leaves your machine | no network calls during `scan`; the model runs locally |

## What it does

### Scan
Runs Semgrep, OSV-Scanner, Trivy, Gitleaks, Checkov and Bandit over a folder and merges everything
into one finding schema with **stable IDs**. Secret values are redacted. Results from other tools
(SARIF, ZAP, nuclei) can be added with `--import` ([`docs/imports.md`](docs/imports.md)).

- **Own rule library**: 371 Apache-2.0 Semgrep rules in 9 languages, each with tests, CWE and a
  fix-oriented message ([`docs/rules.md`](docs/rules.md)).
- **Cross-file data flow**: GapScan's own taint engine follows attacker data through helpers and
  across files in Java, Python and JavaScript/TypeScript, and shows the whole path as evidence
  ([`docs/taint.md`](docs/taint.md)).
- **Supply chain**: dependency reachability (is the vulnerable function actually called?), CISA KEV
  and EPSS enrichment, known-malicious and typosquat packages, container images and IaC
  ([`docs/supply-chain.md`](docs/supply-chain.md)).

### Map to the standard
Every finding carries the OWASP controls it breaks. The dashboard shows coverage per standard in
three states, never two: **gap** (evidence shows the control is not met), **checked, no finding**,
and **needs a person** (code cannot prove it either way). Static analysis cannot prove code is
secure, so GapScan never says "passed".

### Review with a local model (optional)
A local model (Ollama by default) reads the surrounding code, traces where values come from, calls
read-only lookup tools and answers *true / likely / false positive / needs review*. Provable cases
(weak algorithms, provable noise) are decided by code, not by the model. Every model answer is
schema-validated; invalid output is retried, then marked `triage_failed`. Without a model, scanning,
mapping and the report all still work.

### Deep dive and fix
For the top confirmed issues the model writes an audit-style investigation, and every cited
`file:line` must have been shown to it. `gapscan fix` proposes a patch and offers it only if a
rescan shows the finding gone. Nothing is applied automatically.

### Prove it at runtime
Static analysis says "this could be exploited". A dynamic scan of the running application can say
"it was". Import ZAP or nuclei results and GapScan links each one to the code it confirms (same CWE,
the handler for that route), adds the runtime scanner as a source and ranks the finding higher:

```bash
gapscan scan ./my-app -o scan.json --import zap-report.json --import nuclei.jsonl
```

### Zero-day watch, fixes and pull requests
- `gapscan watch` re-checks every saved project's dependency list against freshly updated
  vulnerability data, without rescanning the code, and reports only what is new: exploited (CISA
  KEV) and reachable first. `--notify` shows a desktop notification.
- `gapscan schedule enable` makes it automatic: every day, fresh data, every saved project
  re-checked, and a notification only for advisories you haven't seen. In CI, a weekly `schedule:`
  trigger does the same for the default branch.
- `gapscan fix-deps` proposes the nearest safe version where the project declares the package and
  verifies it with an offline rescan. It never runs a package manager.
- `gapscan pr` turns a reviewed fix into a branch and a pull request on GitHub or GitLab, with your
  own credentials, when you ask for it ([`docs/zero-day-watch.md`](docs/zero-day-watch.md)).

```bash
gapscan schedule enable                            # the daily zero-day check, on autopilot
gapscan watch --all --notify                       # every saved project, desktop alert when something is new
gapscan watch --all -o alerts.json --fail-on-alert # for cron or CI: exit code 3 on new alerts
gapscan fix-deps scan.json -t ./my-project -p fix.diff
gapscan pr fix.diff -t ./my-project --title "Upgrade requests to 2.32.4"
```

GapScan cannot see a vulnerability nobody has disclosed yet in someone else's package. It closes
the time between disclosure and a fix, and it looks for unknown flaws in your own code.

### Report
One offline HTML dashboard plus SARIF, CSV, Markdown, CycloneDX SBOM, JSON and PDF exports. All
numbers are computed in Python; the dashboard only renders them.

### Manage and automate
- `gapscan serve`: a local web UI (loopback only) for projects, scan history and your decisions
  (false positive, accepted risk, fixed), and the desktop app around it.
- `gapscan ci run`: scans only what a change introduced, applies your `monitor / comment / block`
  policy and writes pull-request comments. Also a GitHub Action, a pre-commit hook, GitLab, Jenkins
  and Azure templates, and a VS Code extension ([`docs/ci.md`](docs/ci.md)).
- `gapscan mcp`: lets AI coding assistants scan the code they write ([`docs/mcp.md`](docs/mcp.md)).
- Verified offline bundles carry vulnerability data and rules to air-gapped machines
  ([`docs/offline.md`](docs/offline.md)).

![Flow](docs/flow.png)

## How it compares

GapScan runs well-known open-source scanners and adds what they leave to you. An honest summary:

| | GapScan | The same scanners run by hand | Cloud code-security services |
|---|---|---|---|
| Findings from Semgrep, Trivy, Gitleaks, Checkov, Bandit, OSV | one merged, de-duplicated report | one output format per tool | their own engines |
| Each finding mapped to OWASP Top 10, ASVS, API Top 10, MASVS | yes, with coverage per control | partly (some rules carry tags) | varies, often in paid tiers |
| Cross-file data-flow path as evidence | Java, Python, JS/TS | Semgrep Pro only | usually |
| AI triage and fixes | optional, local model, verified by a rescan | no | usually, in their cloud |
| Your code leaves the machine | never | never | yes |
| Price | free, Apache-2.0 | free | per seat or per repository |

What GapScan is not: a dynamic scanner or a penetration-testing tool. It reads code and imports
dynamic results ([`docs/imports.md`](docs/imports.md)); static analysis cannot prove code is secure,
so it never says "passed". See the [evaluation](#evaluation-read-this-before-trusting-any-number)
for measured accuracy.

## In every pull request

```yaml
# .github/workflows/gapscan.yml
name: gapscan
on: pull_request
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: shawaf/gapscan@v1
        with:
          base: ${{ github.base_ref }}
```

It scans only what the pull request changed, posts a comment with the top findings, uploads SARIF
to the Security tab, and blocks the merge only if your policy says so. It runs from the public
Docker image with the network switched off. Details: [`docs/github-action.md`](docs/github-action.md);
GitLab, Jenkins, Azure DevOps and pre-commit: [`docs/ci.md`](docs/ci.md).

## For AI coding assistants

Let your assistant check its own code against OWASP before you review it:

```bash
claude mcp add gapscan -- uvx gapscan mcp --root .        # Claude Code
```

Cursor, VS Code and other clients: [`docs/mcp.md`](docs/mcp.md). The server is read-only, offline and
confined to the project folder. It is listed in the MCP Registry as `io.github.shawaf/gapscan`.

## Screenshots

All screenshots are from the sample app in `eval/fixtures/vuln-app` and are regenerated with
`uv run python tools/readme_screenshots.py`.

<table>
  <tr>
    <td width="50%">
      <a href="docs/images/report-coverage.png"><img src="docs/images/report-coverage.png" alt="Coverage by standard"></a>
      <br><b>Coverage by standard.</b> Every control in three honest states: evidence of failure, checked with no finding, or manual review. Never "passed".
    </td>
    <td width="50%">
      <a href="docs/images/report-gap-detail.png"><img src="docs/images/report-gap-detail.png" alt="One gap with its evidence"></a>
      <br><b>One gap, with proof.</b> The scanner result, the code around it, the controls it fails and the AI review, labeled as AI-generated.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/images/report-findings.png"><img src="docs/images/report-findings.png" alt="Findings table with filters"></a>
      <br><b>Findings.</b> Filter by severity, verdict, CWE, scanner and evidence. Keyboard driven (<kbd>/</kbd>, <kbd>j</kbd>, <kbd>k</kbd>, <kbd>Enter</kbd>).
    </td>
    <td width="50%">
      <a href="docs/images/report-dependencies.png"><img src="docs/images/report-dependencies.png" alt="Dependencies page"></a>
      <br><b>Dependencies.</b> Known-vulnerable packages from offline vulnerability data, with KEV, EPSS and reachability.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/images/report-owasp.png"><img src="docs/images/report-owasp.png" alt="OWASP Top 10 page"></a>
      <br><b>OWASP Top 10:2025.</b> Gaps grouped by category.
    </td>
    <td width="50%">
      <a href="docs/images/report-hotspots.png"><img src="docs/images/report-hotspots.png" alt="Hotspots page"></a>
      <br><b>Hotspots.</b> Files where gaps concentrate, so you know where to start.
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/images/manager-overview.png"><img src="docs/images/manager-overview.png" alt="Local web UI overview"></a>
      <br><b>Local web UI</b> (<code>gapscan serve</code>). Projects, scan history, risk score and the gaps to close first.
    </td>
    <td width="50%">
      <a href="docs/images/manager-gaps.png"><img src="docs/images/manager-gaps.png" alt="Gaps in the local web UI"></a>
      <br><b>Gaps across runs.</b> What is new since the last scan, saved views, and your decisions carried across scans.
    </td>
  </tr>
</table>

<details>
<summary>Light theme</summary>

[![Light theme overview](docs/images/report-overview-light.png)](docs/images/report-overview-light.png)

</details>

## Built to be trusted

| | |
|---|---|
| **Offline** | No network calls during `scan`. The model endpoint must be localhost or an explicitly configured internal host, unless you opt into a hosted model for triage ([how](docs/ai-upgrades.md#a-hosted-model-opt-in)). |
| **Read-only** | The scanned code is read, never executed, built, installed or imported. |
| **Untrusted input** | All scanned content is treated as data (prompt-injection risk). Agent tools are read-only and confined to the target directory. |
| **Redacted** | Secret values are redacted in findings, cache, logs and reports. |
| **Evidence** | Every finding links to a scanner result or quoted code. AI-only findings are labeled as such. |
| **Validated** | Model output is schema-checked; it is never silently accepted. |
| **Not steerable** | The scanned project cannot configure or silence the scanners: its own ignore files are ignored, and findings silenced inline (`# nosec`, `nosemgrep`) are still reported, marked as suppressed. |

The one exception to "no network" is the setup wizard you start yourself, which downloads only from
hosts pinned in `runtime/manifest.json` and checks every file against a pinned sha256.

## From source

Requirements: [uv](https://docs.astral.sh/uv/). [Ollama](https://ollama.com) only if you want AI
review.

```bash
git clone https://github.com/shawaf/gapscan && cd gapscan
make setup                       # Python deps via uv
cp config/gapscan.example.toml gapscan.toml
uv run gapscan setup             # needs network once: missing scanners, OSV and Trivy data, KEV, EPSS
uv run gapscan doctor            # what is installed, what is missing

uv run gapscan scan ./my-project -o scan.json
uv run gapscan report scan.json -t ./my-project
uv run gapscan serve --open      # or the local web UI
```

With a local model:

```bash
ollama pull qwen3-coder:30b      # or a smaller profile: gapscan model list
uv run gapscan kb build          # local knowledge base for the reviewer
uv run gapscan triage scan.json -t ./my-project --limit 40 --deep-dive -o triage.json
uv run gapscan report scan.json --triage triage.json -t ./my-project
```

Large local data (vulnerability databases, models, the knowledge base index: several GB) lives in
`data/` in a source checkout, and in a per-user folder for an installed package or the desktop app
(`~/Library/Application Support/GapScan`, `%LOCALAPPDATA%\GapScan` or `~/.local/share/gapscan`; set
`GAPSCAN_HOME` to move it). Desktop app and packaging: [`docs/packaging.md`](docs/packaging.md).

**Languages:** Python, JavaScript/TypeScript, Java, Kotlin, Go, Swift, Dart, C# and PHP. Coverage is
uneven: cross-file data flow covers Java, Python and JavaScript/TypeScript only, and Dart/Flutter
detection is still weak.

## Evaluation (read this before trusting any number)

`make eval` runs hand-labeled sites, the OWASP Benchmarks for Java and Python and, optionally, your
own labeled projects. Method, every result, what failed and the 95% confidence intervals are in
[`docs/evaluation.md`](docs/evaluation.md) and [`docs/results/RESULTS.md`](docs/results/RESULTS.md).
Treat AI verdicts as advisory: the gain over a confirm-everything baseline is real but modest, and
most of it comes from deterministic reasoning in the data-flow tracer, not from the model.

## Docs

| | |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | the layers, packages and rules for new code |
| [`docs/rules.md`](docs/rules.md), [`docs/taint.md`](docs/taint.md), [`docs/supply-chain.md`](docs/supply-chain.md) | the rule library, the data-flow engine, reachability and malicious packages |
| [`docs/zero-day-watch.md`](docs/zero-day-watch.md) | re-checking saved projects, dependency fixes and fix pull requests |
| [`docs/ci.md`](docs/ci.md), [`docs/github-action.md`](docs/github-action.md) | CI, pull requests and IDE |
| [`docs/mcp.md`](docs/mcp.md) | the MCP server for Claude Code, Cursor and other AI assistants |
| [`docs/imports.md`](docs/imports.md) | adding SARIF, ZAP and nuclei results, and code confirmed at runtime |
| [`docs/manager.md`](docs/manager.md) | the local web UI and its security design |
| [`docs/ai-upgrades.md`](docs/ai-upgrades.md), [`docs/memories.md`](docs/memories.md) | model tiers, autofix, and how your notes guide the reviewer |
| [`docs/offline.md`](docs/offline.md), [`docs/packaging.md`](docs/packaging.md) | bundles, verified updates, the Docker image, the desktop app |
| [`docs/evaluation.md`](docs/evaluation.md) | method, results and failures |
| [`docs/licenses.md`](docs/licenses.md) | licenses of everything GapScan runs, bundles or measures against |
| [`docs/writing-rules.md`](docs/writing-rules.md) | write and test a new rule in 10 minutes |
| [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CHANGELOG.md`](CHANGELOG.md) | reporting vulnerabilities, contributing, what changed in each release |

## Development

```bash
make lint          # ruff, mypy and the import-boundary contracts
make test          # pytest (browser tests need: uv run playwright install chromium)
make rules-test    # every own rule against its vulnerable and safe cases (needs semgrep)
make dashboard     # rebuild the report dashboard (needs node)
make manager       # rebuild the local web UI (needs node)
```

## Contributing

GapScan gets better with every rule, false-positive report and fix. Good places to start:

- **Write a rule.** Rules are plain Semgrep YAML with a test file; [`docs/writing-rules.md`](docs/writing-rules.md)
  takes you from idea to pull request in about 10 minutes. Issues labeled `rules` list requests.
- **Report a false positive or a miss** with the issue form; each one becomes a test case.
- **Ask, share and suggest** in [Discussions](https://github.com/shawaf/gapscan/discussions).

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md) first. Security
problems in GapScan itself go to a private report ([`SECURITY.md`](SECURITY.md)).

## For teams

GapScan is free and stays free for a single machine. Teams that need shared projects, owners and
due dates, integrations and an audit trail can use GapScan Platform, built on this same engine:
see [gapscan.dev](https://gapscan.dev).

## License and credits

GapScan is licensed under the [Apache License 2.0](LICENSE). Third-party tools, rule sets, data and
models keep their own licenses; see [`docs/licenses.md`](docs/licenses.md) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). The Semgrep community rules (Semgrep Rules
License) are not bundled. OWASP content is CC BY-SA 4.0.

The test fixtures under `eval/fixtures/` (and the rule tests and sample project listed in
`.gitleaks.toml`) contain deliberately fake credentials that the scanners are meant to detect.
