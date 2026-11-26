# Developer workflow: CI, pull requests, pre-commit, IDE, AI assistants

## `gapscan ci run`: only what the change introduced

    gapscan ci run . --base origin/main --comment comment.md      # a pull request
    gapscan ci run . --baseline last-main-scan.json               # against an earlier scan
    gapscan ci run . --staged --fast                              # pre-commit: seconds

* `--base REF`: `git diff -U0` against the merge-base gives the lines the change added. A finding is
  introduced if its own lines **or any step of its taint path** touch them (a new call can create a
  source-to-sink path whose sink sits in untouched code), or, for a dependency, if its name is on an
  added line of its manifest or lockfile.
* `--baseline FILE`: introduced = its stable id is not in the earlier scan (ids survive code moves).
* `--fast`: only semgrep, taint, gitleaks and malware (seconds instead of minutes).
* `--sarif FILE`: also write SARIF 2.1.0 (for GitHub code scanning or any SARIF viewer); `--out FILE`
  writes the full findings JSON, `--comment FILE` the pull-request comment.
* Exit code 1 when a policy rule says `block`; 2 for usage/git errors.

## Policies

`gapscan.policy.toml` in the project (or `--policy FILE`). First matching rule wins; the default is
`monitor`.

    default = "monitor"                # monitor | comment | block

    [[rule]]
    name = "injection in code"
    cwe = ["CWE-89", "CWE-78"]         # also: rule_id (glob), category, asset, severity (this or worse),
    asset = "code"                     #       path (glob), scanner, reachability = ["reachable"]
    action = "block"

Findings a model or person already judged false positives (`--triage`, `--decisions`) never block.

## Pull-request comments

`gapscan ci comment comment.md --provider github|gitlab|bitbucket|azure --url ... --repo ... --pr N`
posts one summary comment (with the data flow of the top findings). It is the **only outbound call**
GapScan makes, a separate command from `scan`/`ci run`, to the URL you pass over https (http only for
localhost/private addresses); the token is read from the environment variable `--token-env`
(default `GAPSCAN_SCM_TOKEN`), never from an argument. Text from the scanned project is flattened and
stripped of markup characters before it is shown. Limits: one summary comment, no inline review
comments, and a re-run posts a new comment (the first line carries a `gapscan-comment` marker for a
future update-in-place).

Ready-to-copy pipelines for GitHub Actions (GHES), GitLab, Jenkins (also the usual route for
Bitbucket Data Center) and Azure DevOps Server are in `integrations/ci/`. The GitHub, GitLab and
Azure templates and the pre-commit files validate against the official schemas
(`uv run --with jsonschema python tools/validate_ci.py`), and the GitHub workflow passes `actionlint`;
the Jenkinsfile is not linted (that needs a Jenkins controller).

## GitHub Action (one-line setup)

For github.com, the composite action in `action.yml` wraps the steps above: it scans the pull
request, uploads SARIF to the **Security tab** and posts the comment, running GapScan from the public
Docker image so nothing has to be installed. See [`github-action.md`](github-action.md).

    - uses: actions/checkout@v4
      with: { fetch-depth: 0 }
    - uses: shawaf/gapscan@v1
      with:
        base: ${{ github.base_ref }}

## Pre-commit

`.pre-commit-hooks.yaml` in this repository defines the hook `gapscan` (staged files, fast
scanners, blocks per policy).

## VS Code (`integrations/vscode/`)

Runs the local `gapscan scan` and shows the findings as problems (command "GapScan: Scan
workspace", optional scan on save). Install the packaged extension with
`code --install-extension gapscan-0.1.0.vsix`; build it with `npm install && npm run package` in
`integrations/vscode/`.

Tests: the mapping logic with Node (`npm test`), and end to end in a real VS Code
(`GAPSCAN_EXE=$(which gapscan) xvfb-run -a npm run e2e`): the extension activates at startup, scans
the vulnerable fixture with the real CLI, and must show the SQL injection and command injection as
errors on the right lines, then clear them. Verified with VS Code 1.141. **Not published** to the
Visual Studio Marketplace or Open VSX. JetBrains is not started.

## MCP server for AI coding assistants

    gapscan mcp --root .

Add it to an assistant's MCP configuration (stdio). Tools: `gapscan_scan_snippet(language, code)`
and `gapscan_scan_file(path)`. Read-only, confined to `--root`, fast scanners only, offline. Setup for
Claude Code, Cursor and other clients is in [`mcp.md`](mcp.md).

## Other CI systems with the Docker image

Any CI whose runners have Docker can use `ghcr.io/shawaf/gapscan` instead of installing GapScan
(add `--user "$(id -u):$(id -g)" -e HOME=/tmp` when the checkout belongs to the runner's user):

    docker run --rm --network none -v "$PWD:/src" -w /src ghcr.io/shawaf/gapscan:1 \
      ci run . --base origin/main --comment gapscan-comment.md --out gapscan-findings.json
