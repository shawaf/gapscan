# GapScan GitHub Action

The composite action in `action.yml` runs GapScan on a pull request and:

1. scans only what the change introduced (`gapscan ci run --base`),
2. uploads **SARIF** to the repository's **Security tab** (code scanning),
3. posts a **pull-request comment** with the top findings and their data flow,
4. saves the findings JSON as a build artifact.

Nothing needs to be installed: by default the action runs GapScan from the public image
`ghcr.io/shawaf/gapscan`, which carries every scanner and vulnerability data refreshed every week.
The scan step runs that container with `--network none` (hard rule 2). The only outbound calls are
pulling the image, the SARIF upload and the comment.

## Quick start

```yaml
name: gapscan
on:
  pull_request:
  schedule:
    - cron: "17 6 * * 1"          # weekly: catch vulnerabilities disclosed since the last change
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
      - uses: shawaf/gapscan@v1
        with:
          base: ${{ github.base_ref }}
```

That is the whole setup. `@v1` follows the newest 1.x release and runs the image tag `:1`; pin
`@v1.1.0` for an exact version (image `:1.1.0`).

### Which GapScan runs

| `engine` | What runs | When to use it |
|---|---|---|
| `docker` (default) | `ghcr.io/shawaf/gapscan` at the action's version, or the image you name in `image:` | GitHub-hosted runners, and self-hosted runners with Docker |
| `path` | the `gapscan` on the runner's `PATH`, optionally installed first by `install:` | self-hosted runners without Docker, for example with the offline bundle ([`offline.md`](offline.md)) |

```yaml
      - uses: shawaf/gapscan@v1
        with:
          base: ${{ github.base_ref }}
          engine: path
          install: pipx install gapscan && gapscan setup
```

### Between pull requests: the weekly re-check

A dependency can become vulnerable without anyone touching the code: an advisory is published for
a version you already use. The `schedule:` trigger above covers that. On a scheduled run there is no
base branch, so GapScan scans the whole default branch with the newest image, which is rebuilt every
week with fresh vulnerability data (OSV, Trivy, CISA KEV, EPSS). New findings show up in the
Security tab, where GitHub notifies the repository's security contacts. No PR comment is posted.

To stop a pull request on serious findings, add a `gapscan.policy.toml` to the repository (see
[What blocks a pull request](#what-blocks-a-pull-request)).

## Inputs

| Input | Default | What it does |
|---|---|---|
| `target` | `.` | Directory to scan |
| `base` | `""` | Base git ref to diff against (empty scans everything) |
| `comment` | `true` | Post the findings as a PR comment |
| `upload-sarif` | `true` | Upload SARIF to the Security tab (needs `security-events: write`) |
| `sarif-category` | `gapscan` | Code-scanning category for the SARIF |
| `github-token` | `${{ github.token }}` | Token for the PR comment |
| `engine` | `docker` | `docker` runs the public image; `path` uses `gapscan` on `PATH` |
| `image` | `""` | With `engine: docker`, the image to run (empty: `ghcr.io/shawaf/gapscan` at the action's version) |
| `install` | `""` | With `engine: path`, a shell command that installs `gapscan` before scanning |

## What blocks a pull request

`gapscan ci run` exits non-zero when a policy rule says `block` (`gapscan.policy.toml`), which fails
the job. Tune the policy as described in [`ci.md`](ci.md). Findings a reviewer or the model already
judged false positives never block.

## Security notes

- Every third-party action is pinned to a commit SHA.
- The scan runs in a container with no network, as the runner's own user, with only the workspace
  mounted. The image is built and attested by this repository's `docker.yml` workflow; check it with
  `gh attestation verify oci://ghcr.io/shawaf/gapscan:1 --repo shawaf/gapscan`.
- Event values (branch names, PR numbers) reach the shell through `env:` only, never interpolated
  into a script, so a crafted branch name cannot become code.
- The comment and SARIF steps run with `if: always()`, so results are reported even when the policy
  fails the job.

## GitHub Marketplace

The action is listed on GitHub Marketplace as **GapScan OWASP Security Scan** (the name comes from
`action.yml`). Listing is a manual step on a release, because GitHub offers no API for it:

1. Once, the repository owner accepts the GitHub Marketplace Developer Agreement and has two-factor
   authentication turned on.
2. Open the release (Releases, then the pencil icon on the newest `v1.x.y`), tick **Publish this
   Action to the GitHub Marketplace**, wait for "Everything looks good!", pick the categories
   (primary **Security**, secondary **Code quality**) and click **Update release**.

Tick the box on each new release that `release.yml` publishes, so the listing shows the newest
version.
