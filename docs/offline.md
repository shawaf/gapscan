# Running GapScan offline

GapScan never needs the network to scan. Everything it knows (vulnerability databases, OWASP and CWE
reference data, the knowledge base, exploit data) arrives as one **bundle** built on a connected machine
and imported with `gapscan update`.

```
connected machine                                   air-gapped machine
-----------------                                   ------------------
gapscan bundle -o gapscan-bundle.tar.gz   ──────►   gapscan update --from gapscan-bundle.tar.gz
(refresh, check OWASP editions, package)            (verify every checksum, then install)
```

## Building a bundle (connected machine)

```bash
gapscan bundle -o gapscan-bundle.tar.gz              # refresh everything, then package
gapscan bundle --no-refresh -o b.tar.gz              # package what is already on this machine
gapscan bundle --model qwen3-coder:30b               # also ship the model weights (large)
gapscan bundle --java-db                             # + Trivy's Java DB (about 2.6 GB; needed only for jar/war scanning)
gapscan bundle --wheels                              # + the Python dependencies as wheels
```

What `gapscan bundle` does, in this order:
1. **Checks the latest released OWASP editions** (Top 10, ASVS, API Security Top 10, GenAI LLM Top 10, MASVS, Cheat Sheets) from the official repositories. A different edition than the mapping tables were built for (for example a new Top 10 year or ASVS 5.1) **fails the bundle before anything is downloaded**; regenerate and review the tables (`gapscan data build-mappings`) and update `owasp/expected_editions.json` in the same commit. Patch-level changes are warnings. It prints what changed since the last bundle.
2. Downloads the OWASP/CWE sources, CISA KEV, EPSS, the OSV database and the Trivy database, and rebuilds the knowledge base.
3. Verifies that the committed CWE to Top 10 / ASVS tables are exactly what the fresh OWASP data produces; otherwise it stops.
4. Writes `bundle.json` (the sha256 and size of every file, dataset versions and snapshot dates), `NOTICES.md` (license notices that must travel with the data) and a `.sha256` file next to the archive.

**Not in a default bundle**
- *Semgrep community rules*: their license (Semgrep Rules License v1.0) forbids use in a competing product or service and restricts redistribution. `--include-semgrep-community-rules --accept-semgrep-rules-license` ships them for **internal use only** (the bundle then carries a notice saying so). Without them Semgrep has no rules until you add your own at `scanners.semgrep.rules_path`.
- *The OWASP Benchmark and other evaluation targets* (GPL-2.0), the LLM response cache and Trivy's scan caches.
- *Scanner binaries*: they come with the Docker image (below) or your platform's package manager.

## Importing a bundle (air-gapped machine)

```bash
sha256sum -c gapscan-bundle.tar.gz.sha256     # compare with the checksum you carried over separately
gapscan update --from gapscan-bundle.tar.gz --verify-only     # check integrity, install nothing
gapscan update --from gapscan-bundle.tar.gz
```

`update` treats the bundle as untrusted input: it reads the manifest first, accepts only regular files the manifest lists (no links, absolute paths, `..`, extras or duplicates), extracts to a staging directory and verifies the sha256 and size of **every** file **before** touching installed data, refuses to replace newer snapshots with older ones unless `--force`, swaps each dataset in with a rename and rolls back if anything fails. Reports then show "data bundle built" and "vulnerability data as of" dates, with a warning when the data is older than 30 days.

**What the checksums do and do not prove.** They detect corruption and any change after the bundle was built. They do not prove *who* built it: anyone who can alter both the archive and its checksum file can substitute a bundle. Carry the checksum over a separate channel, or sign the archive with your own tooling (minisign, GPG). Built-in signing is a Stage 3 item.

## Docker

**The public image.** `ghcr.io/shawaf/gapscan` (linux/amd64 and linux/arm64) carries every scanner,
GapScan and vulnerability data fetched when it was built; it is rebuilt every week, so a fresh pull
brings fresh data. Nothing else is needed, and the container needs no network:

```bash
mkdir -p gapscan-out
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/scan:ro" -v "$PWD/gapscan-out:/out" ghcr.io/shawaf/gapscan:1 scan /scan -o /out/findings.json
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/scan:ro" -v "$PWD/gapscan-out:/out" ghcr.io/shawaf/gapscan:1 \
  report /out/findings.json -t /scan -o /out/report.html
```

Tags: `1.1.0` (exact), `1.1`, `1` and `latest`. The data's sources and terms are in
`/opt/gapscan/DATA-NOTICE.md` inside the image; the Semgrep community rules are not included. Verify
where an image came from with `gh attestation verify oci://ghcr.io/shawaf/gapscan:1 --repo shawaf/gapscan`.

**Your own image from a bundle.** For an air-gapped site that wants to control the data, build the
image from a verified bundle instead (`DATA_SOURCE=bundle`, the default of `docker/Dockerfile`):

```bash
make docker-build BUNDLE=gapscan-bundle.tar.gz     # connected machine, once: pinned scanners + GapScan + the bundle
docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/myproject:/scan:ro" -v "$PWD/out:/out" gapscan-offline scan /scan -o /out/findings.json
docker run --rm --network none ... gapscan-offline report /out/findings.json -t /scan -o /out/report.html --exports /out/exports
make docker-test                                   # the acceptance test: scan + report with --network none
```

The Go scanners (gitleaks, OSV-Scanner, Trivy) are downloaded at build time and **pinned by the sha256 the projects publish**; a mismatch fails the build. The image runs as a non-root user. The bundle is bind-mounted during the build and is not stored in any layer.

**Limits.** The image has no language model: `scan`, `report` and `doctor` work fully offline, but `triage` needs an LLM endpoint on localhost or an internal host (a hard rule), so run Ollama next to the container (for example with `--network host`, or a private network that contains only the two). `make docker-build` builds for the architecture it runs on (arm64 or amd64). If the bundle contained the Semgrep community rules, the image carries `/opt/gapscan/IMAGE-NOTICE.txt` and **must not be published**.
