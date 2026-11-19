# Zero-day watch, dependency fixes and fix pull requests

Three commands close the time between "a vulnerability in one of your dependencies was disclosed"
and "a reviewed pull request fixes it". All three run on your machine.

What this can and cannot do: GapScan cannot see a vulnerability that nobody has disclosed yet in
someone else's package. It tells you within minutes of a data update which of your projects is
affected by a newly published advisory, whether your code actually calls the vulnerable function,
and proposes the upgrade. Unknown flaws in your *own* code are what the regular scan (rules, taint
engine, AI review) looks for.

## 1. `gapscan watch`: re-check without rescanning

Every scan saves the project's dependency list as a CycloneDX SBOM. After you refresh the
vulnerability data (`gapscan update` with a new bundle, or `gapscan data fetch`), the watch hands
each saved SBOM to osv-scanner, offline, and reports only the advisories the saved scan did not know.

```bash
gapscan watch scan.json -t ./my-project          # one saved scan; -t lets it check reachability
gapscan watch --all --notify                     # every project in the local manager, with a
                                                 # desktop notification when something is new
gapscan watch --all -o alerts.json --fail-on-alert   # for cron or CI: exit code 3 on alerts
```

Alerts are ranked by a fixed rule computed in Python, never by the model:

1. listed in CISA's Known Exploited Vulnerabilities catalog (KEV),
2. reachable: the project calls the vulnerable function (`-t` or a manager project folder; the code
   is read, never run),
3. the FIRST EPSS exploit-probability score,
4. severity.

Each alert names the package and version, the advisory and CVE, where the project declares the
package, the reachability evidence (`vulnerable function called at api/client.py:12`) and the fixed
version. A saved scan without an SBOM (Trivy was not installed) cannot be re-checked; the watch says
so. Ecosystems without an installed offline database are listed as skipped, never silently ignored.

The watch makes no network call. The desktop notification uses macOS Notification Center or
`notify-send` on Linux; package names are passed to it as data, so a crafted name cannot run a
script.

## 2. `gapscan fix-deps`: the nearest safe version

```bash
gapscan fix-deps scan.json -t ./my-project -p fix.diff
```

For each vulnerable package with a known fix, GapScan picks the highest fixed version among its
advisories (so one bump closes all of them) and edits the line where the project declares it:
requirements files, `pyproject.toml`, `package.json`, `go.mod`, `pom.xml`, Gradle catalogs and build
files, `Gemfile`, `Cargo.toml`. The operator stays as you wrote it (`==`, `^`, `~`, `>=`, Go's `v`).

- **Verified**: a copy with the edit applied is rescanned offline; the fix counts only if the
  advisories are gone.
- **Lockfile**: if a lockfile pins the version (`package-lock.json`, `poetry.lock`, ...), GapScan
  says to regenerate it. It never runs `npm`, `pip`, `go` or any package manager, because they can
  execute code from the project and its dependencies.
- **Transitive**: a package the project does not declare gets an explanation (upgrade the parent or
  add an override), not a guess.

Nothing in the project changes; you get a diff to review.

## 3. `gapscan pr`: open the pull request

```bash
export GITHUB_TOKEN=...                          # a token that may push and open pull requests
gapscan pr fix.diff -t ./my-project --title "Upgrade requests to 2.32.4 (CVE-2026-1111)"
```

GapScan checks that the working tree is clean and the patch applies, shows where it will push, and
asks before doing anything. Then it creates a branch (`gapscan/fix-<hash>`), applies the patch,
commits, pushes with your own git credentials, switches back to your branch and opens the pull
request through the GitHub or GitLab API (`--provider gitlab`, `--url` for a self-hosted server).
Git hooks and fsmonitor are disabled for these git calls, so no code from the project runs. If a
step fails, the new branch is removed again.

GapScan never opens a pull request on its own. The same patch can come from `gapscan fix` (a code
fix kept only if a rescan shows the gap gone) as well as from `gapscan fix-deps`.
