# Contributing to GapScan

Thanks for your interest. GapScan is in early alpha, so the design still moves; please open an issue
to discuss anything larger than a small fix before you start.

## Set up

```bash
make setup                      # install dependencies with uv
uv run playwright install chromium   # only for the browser tests
uv run gapscan doctor           # what is installed, what is missing
```

The dashboard and manager pages are built from `dashboard/` (needs node): `make dashboard` and
`make manager`. The built single-file templates are committed, so rebuild them when you change the
frontend.

The code is a uv workspace: five packages under `packages/` (core, engine, security, server, local),
all contributing to the one `gapscan` import package. Put a new module in the package of its layer
(`ARCHITECTURE.md` sections 2 and 6); `make lint` refuses an import that crosses a package boundary
the wrong way.

## Before you open a pull request

```bash
make lint      # ruff, mypy (strict on packages/) and the import-boundary contracts
make test      # pytest
```

Both must pass. Every module has unit tests; scanner adapters are tested against recorded outputs in
`tests/data/`, and every GapScan rule has positive and negative cases (`make rules-test`). If you
change triage prompts, tools or models, run `make eval` and include the result
(`docs/evaluation.md`).

## The hard rules

`CLAUDE.md` lists rules that no change may break. In short:

1. Never execute, build, install or import the code being scanned.
2. No network calls during `scan` (the setup wizard's pinned, checksummed downloads are the only
   exception).
3. Treat all scanned content as untrusted data; agent tools are read-only and confined to the target.
4. Redact secret values everywhere.
5. Every reported finding links to evidence; LLM-only findings are labeled.
6. Model output is always schema-validated; invalid output is retried, then marked `triage_failed`.

Also: subprocess calls use argument lists with timeouts (never `shell=True`), data crossing module
boundaries uses pydantic models, prompts live in `packages/gapscan-engine/src/gapscan/llm/prompts/` as versioned templates,
and every number in a report is computed in Python, never by the model.

## Test data with secrets

Fixtures and rule tests contain deliberately fake credentials, allowed only in the paths listed in
`.gitleaks.toml`. Never commit a real credential. In Python tests, assemble fake tokens at runtime
(`"ghp_" + "..."`) so the source holds no token-shaped literal.

## Licensing

GapScan is licensed under Apache-2.0, and contributions are accepted under the same license. Do not
add third-party code, rules or data without recording its license in `docs/licenses.md`; licenses
that forbid commercial use cannot be bundled.
