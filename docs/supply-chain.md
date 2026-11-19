# Supply chain: reachability, malicious packages, images and IaC

## Dependency reachability (`reachability.py`)

Every dependency finding gets `reachability` and `reachability_evidence`:

| Status | Meaning | Priority |
|---|---|---|
| `reachable` | a known-vulnerable function is called in a file that imports the package | +5 |
| `imported` | the package is imported; no function-level data says which call is vulnerable | unchanged |
| `not_reachable` | imported, but none of the vulnerable functions is called | x0.5 |
| `not_imported` | a *direct* dependency that no source file imports (plugins and runtime loading are possible, so it is lowered, not dropped) | x0.6 |
| `transitive` | not declared by the project; this check cannot see inside the dependency | unchanged |

Function-level data comes from the advisory when it lists affected symbols (the OSV adapter keeps
them in `raw.symbols`) and from `packages/gapscan-security/src/gapscan/reach_hints.toml` (a short, curated list: verify
against the advisory before adding to it). Without symbol data the best answer is `imported`, never
`reachable`: the tool does not guess. KEV-listed CVEs stay at 100 whatever the status. Import names
that differ from package names (`pyyaml` is imported as `yaml`) are handled for the common cases in
`context/callgraph.py::IMPORT_ALIASES`. Limits: name-based, no type resolution, no calls through
aliases of the imported module, at most 60 packages per scan are searched (highest severity first).

## Malicious packages (`malware` scanner)

* **Known malicious**: the OSV database already in the bundle contains the OpenSSF
  malicious-packages advisories (`MAL-...`). A declared dependency with one is a critical finding.
  Nothing extra is downloaded. If the pinned version is not in the advisory's version list it is
  skipped.
* **Typosquat suspects**: a declared name one edit away from a popular package name
  (`packages/gapscan-security/src/gapscan/typosquat_names.toml`, PyPI and npm) is a medium finding that says "verify". This is
  a name-similarity heuristic and is labeled as one. Scoped npm names are skipped.

Declared dependencies are read from `requirements*.txt`, `pyproject.toml`, `package.json`,
`go.mod`, `pom.xml`, `Gemfile` and `Cargo.toml` (`manifests.py`; lockfiles are left to OSV-Scanner).

## Container images and IaC as first-class assets

Every finding has an `asset`: `code`, `dependency`, `secret`, `iac` (Checkov and Trivy config) or
`image`. Scan a saved image archive fully offline:

    docker save -o app.tar myapp:1.0
    gapscan scan ./repo --image app.tar

Findings from the image (OS and library vulnerabilities, misconfigurations, secrets) carry
`file = image:app.tar > <layer target>` and `asset = image`. **Not done yet:** a dedicated tab for
these views in the dashboard (the data and exports carry `asset`, so the existing filters and CSV/JSON
exports can already slice by it).
