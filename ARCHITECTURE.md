# GapScan architecture

How the code is organized, so new scanners, rules and standards fit in without a rewrite.

## 1. The gap model

GapScan measures the **gap** between a standard and what the evidence in the code shows:

```
target (a versioned standard)  −  observed (evidence from scanners)  =  gap
```

- **Target**: a standard with a version. Today: OWASP Top 10:2025, ASVS 5.0, API Security Top 10
  2023, MASVS and GenAI LLM Top 10 2026.
- **Control**: one requirement inside a target (an ASVS requirement, a Top 10 category).
- **Evidence**: a scanner result, a taint path or quoted code. Every gap has evidence.
- **Gap**: a control the evidence shows is not met, with a priority computed in Python and,
  optionally, a schema-checked AI verdict.

In the code a gap is a `Finding` (`gapscan.core.models`). Findings map to controls through a
generic `controls: list[ControlRef]`, so the core never assumes every gap is an OWASP gap. Evidence
is anchored to `file` and line today.

## 2. Layers

Imports only point down. A module may import from its own layer and the layers below it, never
from a layer above. `make lint` checks this with import-linter (contracts in `pyproject.toml`).

```
┌──────────────────────────────────────────────────────────────────────┐
│ Apps            cli · mcp · local web UI and desktop app · ci (thin) │
├──────────────────────────────────────────────────────────────────────┤
│ Adapters        LLM: local endpoint · Store: SQLite · Data: bundle   │
├──────────────────────────────────────────────────────────────────────┤
│ Security pack   scanners, own rules, taint, reachability, OWASP      │
│                 target packs and mappings, review agent, dashboard   │
├──────────────────────────────────────────────────────────────────────┤
│ Engine          stages: scan → normalize → map to controls →         │
│                 prioritize → review; code context, redaction, LLM    │
│                 plumbing, storage                                    │
├──────────────────────────────────────────────────────────────────────┤
│ Core            finding model, ControlRef, Evidence and the          │
│                 interfaces Scanner, TargetPack, LLMProvider, Store   │
└──────────────────────────────────────────────────────────────────────┘
```

| Layer | Owns | Must not |
|---|---|---|
| Core | Data models and interfaces (`Protocol`s). Pure Python, pydantic. | Do I/O or import the security pack. |
| Engine | The pipeline as typed stages; normalize, code context, redaction, the review flow, LLM plumbing (structured output, cache, prompt loading), storage. | Import the security pack, a concrete LLM client or an app. |
| Security pack | Scanners, rules, target packs, mappings, the review agent, the knowledge base, report views. | Import an app. |
| Apps | Parsing input, wiring adapters, calling engine services. | Contain business logic. |

## 3. Interfaces and the registry

| Interface | Purpose | Implementations |
|---|---|---|
| `Scanner` | Run one tool over a target, return findings. Never executes the target. | Semgrep, OSV, Trivy, Gitleaks, Checkov, Bandit, taint, malware |
| `TargetPack` | A versioned standard: its controls and the mapping from evidence (CWE, rule id) to controls. | OWASP Top 10:2025, ASVS 5.0, API Top 10 2023, MASVS, GenAI LLM Top 10 2026 |
| `LLMProvider` | Chat and structured output, schema-validated. | Local (asserts a localhost or configured internal host) |
| `Store` | Scans, decisions, memories. | SQLite |

The security pack registers its scanners, target packs and engine hooks through the `gapscan.packs`
entry point (`security_pack.py`), so adding a scanner is a new module plus one registration, not an
edit to a central list:

| Hook | What the engine does with it | Security pack |
|---|---|---|
| `add_collector` | The `scan` stage runs every collector. | The enabled scanners, container images and the SBOM |
| `add_annotator` | `normalize` runs evidence annotators before merging and context annotators before scoring. | Secret facts; dependency reachability; KEV and EPSS from the offline mirrors |
| `add_flow_filter` | Code context traces data flow only for findings every filter accepts. | Not for weak-algorithm and insecure-setting weaknesses |
| `add_capability` | Groups scanners into capabilities a project turns on. | SAST, Dependencies, Secrets, IaC |

The model review is the engine's flow (`services.review_scan`) over the pack's steps
(`agent.review.AgentSteps`); apps pass in the model provider they wired. Only packs listed in
`scanners.packs` load, so an installed package can never add a scanner on its own.

## 4. Packages

One repository, a uv workspace (`packages/`). `gapscan` is a namespace package spread over the
members, so every module keeps its import path (`gapscan.normalize`, `gapscan.owasp.packs`).

| Package | Contents | Depends on |
|---|---|---|
| `gapscan-core` | Finding model and interfaces (`gapscan.core`), the version | pydantic |
| `gapscan-engine` | Pipeline stages, normalize, code context (with prompt-injection detection), redaction, controls mapping, the registry, the review flow and run services, LLM plumbing and prompt templates, storage, memories, CI policy and diff scope | core |
| `gapscan-security` | Scanners, own rules, taint, malware, reachability, secret facts, KEV/EPSS, OWASP target packs and mappings, knowledge base, review agent, report and dashboard, autofix, evaluation | engine |
| `gapscan-local` | The apps: CLI, MCP server, local web UI and desktop app, setup wizard and runtime, offline bundle, CI mode, pull-request comments | engine, security |

A file one package needs from another is found through that package's module (for example
`gapscan.owasp.build.MAPPINGS_DIR`), never by a path relative to the importing file.

## 5. Rules for new code

- Import models and interfaces from `gapscan.core.models` and `gapscan.core.interfaces`.
- Put new code in the lowest layer that can own it. A concrete tool, model or database belongs in
  the pack or an adapter, behind an interface.
- Security-specific names (OWASP, CWE, CVE) belong in the security pack, not in core.
- New scanners and standards register through the pack's registry.
- A new module that opens network connections must be added to the `network` contract's allowlist
  on purpose, with a reason. The scan itself makes no network calls.
