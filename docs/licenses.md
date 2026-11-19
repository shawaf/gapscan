# Third-party licenses and what may ship in a bundle

GapScan itself is licensed under the Apache License 2.0 (see `LICENSE`). Everything below is third-party.

**Verified** means checked against the project's own
license file, package metadata or model card on 2026-10-01; **unverified** means not yet
confirmed. This is an engineering register, not legal advice: a legal review is still
required before Stage 2 (see ROADMAP).

## Tools GapScan runs (separate processes, not linked)

| Component | License | Bundled? | Status / notes |
|---|---|---|---|
| Semgrep CE (engine) | LGPL-2.1-only | optional | verified (Homebrew metadata) |
| **GapScan Rules** (`packages/gapscan-security/src/gapscan/rules/semgrep/`, Kotlin, Swift, Dart) | Apache-2.0 (ours) | yes | written for this project, tested in `tests/rules/`; see `docs/rules.md` |
| **Semgrep community rules** | **Semgrep Rules License v1.0** | **no, not by default** | verified (LICENSE in the rules repo). Restricts use in a competing product or service. Fine for internal use on a developer machine; **do not ship in a commercial bundle**. Plan: GapScan's own rule library. Any bundle that includes them must be an explicit opt-in that prints this license |
| OSV-Scanner | Apache-2.0 | yes | verified |
| Trivy | Apache-2.0 | yes | verified |
| Gitleaks | MIT | yes | verified |
| Checkov | Apache-2.0 | yes | verified |
| Bandit | Apache-2.0 | yes | verified |
| CodeQL | restricted outside open-source/research use | **never** | not used. Only supported as customer-supplied SARIF via the generic SARIF ingest |

## Data

| Dataset | License | Notes |
|---|---|---|
| OWASP Top 10:2025 (repo `LICENSE`) | CC BY-SA 4.0 | verified. Attribution required; share-alike applies to adapted material (our mapping tables) |
| OWASP ASVS 5.0.0 (repo license) | CC BY-SA 4.0 | verified. Same obligations |
| OpenCRE (repo license) | CC0-1.0 | verified for the repo. The API responses embed ASVS and CWE text that keep their own terms |
| MITRE CWE catalog v4.20 | MITRE CWE Terms of Use | verified (terms page read 2026-10-09). Free for research, development and commercial use; every copy must reproduce MITRE's copyright designation and the license. Bundles reproduce both in `NOTICES.md`, the repository in `THIRD_PARTY_NOTICES.md`. CWE is a MITRE trademark |
| OWASP Cheat Sheet Series | CC BY-SA 4.0 | verified (GitHub license metadata). Snapshot pinned to a commit |
| OWASP API Security Top 10 2023 | CC BY-SA 4.0 | verified (LICENSE file) |
| OWASP GenAI LLM Top 10 2026 | CC BY-SA 4.0 | verified (project README states it; the repo has no LICENSE file) |
| OWASP MASVS v2.1.0 | CC BY-SA 4.0 | verified (repository license) |
| OSV vulnerability database (language ecosystems only) | per-source; the ecosystems GapScan fetches (PyPI, npm, Maven, Go, Pub, Swift, RubyGems, NuGet, Packagist, crates.io) come predominantly from the GitHub Advisory Database, **CC-BY 4.0** | verified 2026-10-25 (osv.dev data page). Commercial redistribution OK with attribution to OSV / the sources (in bundle `NOTICES.md`). GapScan does **not** fetch OSV's OS-distro sources, some of which are non-commercial (Chainguard/Wolfi, CC-BY-NC-ND) or share-alike — re-check `fetch.py` `OSV_ECOSYSTEMS` before adding any |
| Trivy DB / Java DB | tooling Apache-2.0 (Aqua Security); the DB aggregates NVD (US-gov public domain), GitHub Advisory DB (CC-BY 4.0) and distro advisories (Red Hat, Debian, …) | verified 2026-10-25 (trivy-db repo). Aqua distributes it for offline/air-gapped use; the aggregated sources are commercially redistributable. Attribution to Aqua + the sources in `NOTICES.md`. A full per-source review is advisable if a customer requires one |
| CISA KEV | CC0 / US-government public domain | verified 2026-10-25 (cisa.gov KEV `license.txt`): "use this data in any legal manner"; commercial use and redistribution permitted, no attribution required. Do **not** use the CISA logo / DHS seal or imply endorsement; third-party links keep their own terms. Downloaded to `enrichment/kev.json`, shipped in bundles |
| FIRST EPSS | free to use; attribution requested | verified 2026-10-25 (first.org/epss): published freely via CSV/API, no registration; free to use in products and commercially; FIRST requests citation. Downloaded to `enrichment/epss.csv`, shipped in bundles; attribution in `NOTICES.md` |

## Evaluation targets (downloaded to `data/eval-targets/`, never committed or bundled)

| Target | License | Notes |
|---|---|---|
| OWASP BenchmarkJava (pinned commit in `eval/targets.toml`) | **GPL-2.0** | verified (GitHub license metadata). Used only as local evaluation data: it is scanned, never executed, and must not be copied into this repository or any offline bundle (that would be redistribution under the GPL). Results files contain only counts and per-category rates |
| OWASP Juice Shop v20.2.0 | MIT | verified (GitHub license metadata) |
| OWASP NodeGoat | Apache-2.0 | verified (GitHub license metadata) |
| `eval/fixtures/labeled/` | GapScan's own, Apache-2.0 | hand-written for this project; contains fake credentials on purpose |

## Models

| Model | License | Notes |
|---|---|---|
| qwen3-coder:30b (default profile `best`) | Apache-2.0 | verified (Qwen's model card on Hugging Face). Ollama's page does not show it |
| granite4.2 (profiles `small`, `tiny`) | Apache-2.0 | verified (Ollama library page) |
| nomic-embed-text (embeddings for the KB) | Apache-2.0 | verified for nomic-embed-text v1 and v1.5 (Hugging Face model cards); Ollama's page does not state it |
| qwen2.5-coder, llama3, deepseek-r1 | various | not used by default; check before recommending |

## What ships inside the dashboard HTML (`report/templates/dashboard.html`, built from `dashboard/`)

Everything below is inlined into one file, so its license notices travel with every report. Verified from each package's own `package.json` (2026-10-02).

| Package | Version | License |
|---|---|---|
| preact | 11.0.0 | MIT |
| echarts | 6.1.0 | Apache-2.0 |
| zrender (ECharts' renderer) | 6.1.0 | BSD-3-Clause |
| highlight.js (13 language grammars) | 11.12.0 | BSD-3-Clause |
| tslib | (from package.json) | 0BSD |

Build tools (Vite, TypeScript, vite-plugin-singlefile, vitest) are development-only and not shipped (MIT / Apache-2.0). Browser tests and the optional PDF export use Playwright (Apache-2.0) and a Chromium build downloaded by `playwright install chromium`. The system font stack is used, so no font files are bundled. Every page built from the templates embeds the full license and notice texts of these packages (`<script type="text/plain" id="third-party-notices">`, generated at build time from each package's own files by `dashboard/third-party-notices.ts`; done 2026-10-09).

## The offline Docker image (`docker/Dockerfile`)

| Component | License | Notes |
|---|---|---|
| python:3.12-slim-bookworm (Debian + CPython) | Debian package licenses, PSF | unmodified base image; unverified in detail |
| gitleaks 8.30.1, OSV-Scanner 2.6.0, Trivy 0.74.0 | MIT, Apache-2.0, Apache-2.0 | verified earlier from Homebrew metadata (same versions); downloaded from the projects' releases and pinned by their published sha256 |
| Semgrep 1.176.0, Bandit 1.9.4, Checkov 3.3.20 | LGPL-2.1, Apache-2.0, Apache-2.0 | installed with pip in a separate environment |
| Data bundle contents | see the sections above | `NOTICES.md` inside every bundle carries the attributions; an image built from a bundle that includes the Semgrep community rules is internal-only and says so in `/opt/gapscan/IMAGE-NOTICE.txt` |

## Python/native dependencies (runtime)

typer, pydantic, pydantic-settings, rich, numpy (BSD-3-Clause), tree-sitter and all tree-sitter grammar packages are
MIT; httpx is BSD-3-Clause; jinja2 is BSD; cryptography (signed local-run reports) is Apache-2.0 OR BSD-3-Clause, with
cffi (MIT-0) and pycparser (BSD-3-Clause). Verified from installed package metadata (numpy's license assumed BSD-3-Clause, not read).

## OWASP attribution (CC BY-SA 4.0)

The knowledge-base index (`data/kb/`, not committed) is adapted from CC BY-SA material. Any bundle that includes it must ship the attribution notices and these licenses, and answers that quote it show the citation. See also the next section.

## OWASP-derived tables in this repository

`packages/gapscan-security/src/gapscan/owasp/mappings/` contains data derived from OWASP material; see the `NOTICE.md`
there. Reports must credit OWASP as the source of category and requirement text.

## Still to do (ROADMAP section 3)
- [ ] Legal review of the whole register before Stage 2.
- [ ] Generate and publish an SBOM of GapScan itself in CI. `make sbom` writes a CycloneDX file locally (40 components from `uv.lock`), but its license fields are empty because Trivy reads the lockfile only, so licenses still come from this register.
- [ ] Replace Semgrep-community-rule dependencies with GapScan's own rules; until then the
      recorded Semgrep output in `tests/data/semgrep.sarif` carries only rule ids, short
      descriptions and CWE tags, and should be re-recorded with our own rules.
