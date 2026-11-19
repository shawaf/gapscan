# GapScan GitHub Action

The composite action in `action.yml` runs GapScan on a pull request and:

1. scans only what the change introduced (`gapscan ci run --base`),
2. uploads **SARIF** to the repository's **Security tab** (code scanning),
3. posts a **pull-request comment** with the top findings and their data flow,
4. optionally **sends the report** to your GapScan project (hybrid/cloud),
5. saves the findings JSON as a build artifact.

The engine makes no network call during the scan (hard rule 2). The only outbound calls are the
SARIF upload, the comment and the optional project push.

## Quick start

```yaml
name: gapscan
on: pull_request
permissions:
  contents: read
  pull-requests: write
  security-events: write          # SARIF upload to the Security tab
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # the diff against the base branch needs history
      - uses: <owner>/gapscan@v1
        with:
          base: ${{ github.base_ref }}
```

The runner must have `gapscan` on `PATH`. On a **self-hosted** runner, install the offline bundle
(see [`offline.md`](offline.md)) and use the template in `integrations/ci/github-actions.yml`. On a
**hosted** runner, pass `install:` with the command that installs the engine, for example:

```yaml
      - uses: <owner>/gapscan@v1
        with:
          base: ${{ github.base_ref }}
          install: pipx install gapscan
```

The project decides which **capabilities** run (SAST, Dependencies, Secrets, IaC) from its Security
service settings; see the platform model in `ARCHITECTURE.md`.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `target` | `.` | Directory to scan |
| `base` | `""` | Base git ref to diff against (empty scans everything) |
| `comment` | `true` | Post the findings as a PR comment |
| `upload-sarif` | `true` | Upload SARIF to the Security tab (needs `security-events: write`) |
| `sarif-category` | `gapscan` | Code-scanning category for the SARIF |
| `github-token` | `${{ github.token }}` | Token for the PR comment |
| `server-url` | `""` | GapScan server URL (enables the push step) |
| `project-id` | `""` | GapScan project id (required to push) |
| `team-token` | `""` | GapScan server token, a secret (push only) |
| `install` | `""` | Shell command to install `gapscan` before scanning |

## What blocks a pull request

`gapscan ci run` exits non-zero when a policy rule says `block` (`gapscan.policy.toml`), which fails
the job. Tune the policy as described in [`ci.md`](ci.md). Findings a reviewer or the model already
judged false positives never block.

## Security notes

- Every third-party action is pinned to a commit SHA.
- Event values (branch names, PR numbers) reach the shell through `env:` only, never interpolated
  into a script, so a crafted branch name cannot become code.
- The comment and SARIF steps run with `if: always()`, so results are reported even when the policy
  fails the job.
