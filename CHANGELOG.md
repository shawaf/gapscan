# Changelog

All notable changes to GapScan are listed here. Versions follow [semantic versioning](https://semver.org).

## [Unreleased]

### Fixed

- `gapscan report` on large projects is about 20 times faster (OWASP Juice Shop: 7 minutes to 20
  seconds, same output): parsed files and their function and call lists are cached.
- Minified files (`*.min.js`, `*.min.css`) and `bower_components/` count as vendored code, and Go's
  `testdata/` as test code, so a copied jQuery no longer tops the list.
- The known-malicious check no longer flags a legitimate package whose declared range (`^10.0.0`)
  cannot resolve to any of the compromised releases an advisory lists.
- `gapscan data fetch-vulns` (and `gapscan setup`) keep downloading the other sources when one host
  is blocked, and say which one failed instead of printing a traceback.

### Added

- `gapscan --version` / `-V`.

## [1.1.1] - 2026-11-26

The zero-day check runs on its own.

### Added

- **`gapscan schedule enable`**: a daily zero-day check you turn on once. Every day it downloads
  fresh vulnerability data, re-checks every saved project's dependencies and shows a desktop
  notification only for advisories no earlier check reported. It uses the system scheduler (a
  LaunchAgent on macOS, a systemd user timer on Linux, a printed crontab line otherwise), so nothing
  keeps running. `--at` sets the time, `--no-fetch` only re-checks (air-gapped machines), and
  `gapscan schedule status` / `disable` show and stop it.
- `gapscan data fetch-vulns --watch [--notify]` downloads the data and then runs that check.
- `gapscan watch --new-only` reports each alert once, however often it runs.
- The GitHub Action docs and CI example add a weekly `schedule:` trigger, so the default branch is
  re-scanned with the newest image (fresh vulnerability data every week) even when nobody pushes.

## [1.1.0] - 2026-11-26

GapScan in one step: `pipx install gapscan`, a ready-to-run Docker image, a GitHub Action that needs
nothing installed, desktop and Linux builds on every release, an MCP Registry listing, and proof from
the running application through ZAP and nuclei imports.

### Added

- **On PyPI.** `pipx install gapscan` (or `uvx gapscan`) installs the whole program as one package.
  An installed package keeps its data in the per-user folder, never in the current directory.
- **`gapscan setup`**: gets a machine ready in one command. It downloads the missing scanners from
  the pinned setup manifest (every file checked against its sha256), then the vulnerability data.
  `--no-scanners`, `--no-data` and `--java-db` choose what it fetches.
- **Docker image** `ghcr.io/shawaf/gapscan` (linux/amd64 and linux/arm64): every scanner, GapScan and
  vulnerability data, ready for `docker run --network none`. Rebuilt every week with fresh data, with
  a build-provenance attestation. Tags `1.1.0`, `1.1`, `1` and `latest`.
- **The GitHub Action needs nothing installed.** `uses: shawaf/gapscan@v1` runs GapScan from the
  image, with the network off for the scan. `engine: path` keeps the old behaviour for self-hosted
  runners.
- **`gapscan scan --import`** adds results from other tools as evidence: SARIF from any static tool,
  OWASP ZAP JSON reports and nuclei JSON Lines. A ZAP or nuclei result marks the code finding it
  confirms (same CWE, the handler of that route), which then lists the runtime scanner as a source,
  shows what was seen, and ranks higher. See `docs/imports.md`.
- **Releases carry builds**: the wheel and sdist, the macOS app (`GapScan.dmg`, Apple silicon,
  unsigned) and a Linux x86_64 build, with `SHA256SUMS` and provenance attestations. Each build is
  started and made to scan a sample before it is published.
- **MCP Registry listing** (`io.github.shawaf/gapscan`) and setup guides for Claude Code, Cursor and
  VS Code in `docs/mcp.md`.
- **For contributors**: a 10-minute rule-writing guide (`docs/writing-rules.md`), issue forms for
  bugs, false positives and rule requests, a pull-request template and a code of conduct.

- Opt-in hosted model for triage (`llm.allow_remote`): any provider over HTTPS (OpenAI-compatible APIs
  such as OpenAI, Anthropic, Gemini, Mistral, Groq, OpenRouter and Azure, or a hosted Ollama), key from an
  environment variable, every message secret-masked again before it is sent. Off by default; `scan`
  still makes no network call.

### Changed

- The README opens with three ways to try GapScan (Docker, pipx, desktop app), the pull-request setup,
  the MCP setup and a comparison with running the scanners by hand and with cloud services.
- `gapscan doctor` now names `gapscan setup` as the fix for a missing scanner or database.
- The status is now beta: the "early alpha" badge and warning are gone. The evaluation still comes
  with every number.

### Fixed

- **No network call during a scan.** Trivy contacted `check.trivy.dev` (version check and
  telemetry) on every run, even offline. GapScan now switches both off for every Trivy call.
- **`gapscan pr` with dependency fixes.** When two fixes changed the same manifest, `fix-deps`
  wrote a patch whose second hunk did not apply, so `gapscan pr` rejected it. The patch is now one
  diff per file with every fix applied.
- **One watch alert per vulnerability.** A CVE that OSV lists as both a GHSA and a PYSEC advisory
  was reported twice; it is now reported once.
- **No model named when none ran.** Without AI review, the report named the configured model and
  the web UI labeled the top gaps "AI-generated". Both now name a model only when one reviewed
  the findings.

### Added

- `gapscan data fetch-vulns`: downloads the OSV and Trivy databases, CISA KEV and EPSS in one step
  (the README's Quick start used to leave dependency scanning without data).
- **Midnight look**, now the default for the report and the web UI: a dark-only control-room style
  with glass-edged cards, a floating sidebar, green status dots and monospace logs. The GapScan,
  Soft and Glassy looks stay one click away on the Look switch (or press `u`).
- **Projects first.** The web UI opens on your projects, adding one is a dialog, and each project has
  a Features page when there is more than one feature. The theme and look can be saved per project.
- **A simpler web UI.** New sidebar, icons and Overview from the Midnight design; Gaps, ASVS coverage
  and Runs show the essentials first, with the rest one click away. Look and theme are in Settings.

### Removed

- The **Classic** look. Anyone who had it saved now gets the default look.

## [1.0.0] - 2026-11-20

The first public release of GapScan: a free, offline security scanner that maps every finding to
OWASP and backs each one with evidence. **Early alpha**: read the
[evaluation](https://github.com/shawaf/gapscan/blob/main/docs/evaluation.md) before relying on any number.

### Highlights

- **Scan.** Runs Semgrep, OSV-Scanner, Trivy, Gitleaks, Checkov and Bandit (plus any SARIF file)
  and merges the results into one finding schema with stable IDs. Secret values are redacted.
- **Own rule library.** 371 Apache-2.0 Semgrep rules in 9 languages, each with tests, a CWE and a
  fix-oriented message.
- **Cross-file data flow.** GapScan's own taint engine follows attacker data through helpers and
  across files in Java, Python and JavaScript/TypeScript, and shows the whole path as evidence.
- **Mapped to the standard.** Every finding carries the controls it breaks in OWASP Top 10:2025,
  ASVS 5.0, API Security Top 10 2023, MASVS and GenAI LLM Top 10 2026. Coverage is shown in three
  honest states: evidence of failure, checked with no finding, or manual review. Never "passed".
- **Supply chain.** Dependency reachability, CISA KEV and EPSS enrichment, known-malicious and
  typosquat packages, container images and infrastructure as code.
- **Optional local AI review.** A local model (Ollama by default) triages each finding as
  confirmed, likely, false positive or needs review, explains it and proposes a fix. Output is
  schema-validated and labeled as AI-generated. Everything works without a model.
- **Zero-day watch.** `gapscan watch` re-checks saved projects against freshly updated
  vulnerability data without rescanning, exploited and reachable first, with an optional desktop
  notification.
- **Fixes you can check.** `gapscan fix` and `gapscan fix-deps` keep a patch only if an offline
  rescan shows the gap gone. `gapscan pr` opens the pull request on GitHub or GitLab when you ask.
- **Report.** One self-contained offline HTML dashboard, plus SARIF, CSV, Markdown, CycloneDX SBOM,
  JSON and PDF exports.
- **Local web UI.** `gapscan serve` (loopback only) for projects, scan history and your decisions,
  in a new GapScan look with dark and light themes.
- **In your workflow.** `gapscan ci run`, a GitHub Action, a pre-commit hook, GitLab, Jenkins and
  Azure templates, a VS Code extension and an MCP server for AI coding assistants.
- **Air-gapped.** Verified offline bundles carry vulnerability data and rules to machines with no
  network.

### Trust

- No network calls during `scan`. The model endpoint must be localhost or an explicitly configured
  internal host.
- The scanned code is read, never executed, built, installed or imported.
- The scanned project cannot silence the scanners: its ignore files are ignored and inline
  suppressions are still reported, marked as suppressed.

### Install

GapScan is installed from source for now; there is no PyPI package or signed desktop installer yet.

```bash
git clone https://github.com/shawaf/gapscan && cd gapscan
make setup
uv run gapscan doctor
uv run gapscan scan ./my-project -o scan.json
uv run gapscan report scan.json -t ./my-project
```

Requirements: Python 3.11+, [uv](https://docs.astral.sh/uv/) and the scanners on your `PATH`.
[Ollama](https://ollama.com) only for AI review. See the [README](https://github.com/shawaf/gapscan#quick-start).

### Known limitations

- Cross-file data flow covers Java, Python and JavaScript/TypeScript only; Dart/Flutter detection
  is still weak.
- AI verdicts are advisory: the measured gain over a confirm-everything baseline is real but
  modest. Method and results are in [`docs/evaluation.md`](https://github.com/shawaf/gapscan/blob/main/docs/evaluation.md).
- GapScan cannot see a vulnerability nobody has disclosed yet in someone else's package. It closes
  the time between disclosure and a fix, and looks for unknown flaws in your own code.

[1.0.0]: https://github.com/shawaf/gapscan/releases/tag/v1.0.0
