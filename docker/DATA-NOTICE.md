# Data in this image

The public GapScan image (`ghcr.io/shawaf/gapscan`) contains vulnerability data fetched when the image
was built. `gapscan doctor` shows how old it is; pull the image again for newer data (it is rebuilt
every week), or mount your own data folder at `/opt/gapscan/data`.

| Data | Source | License or terms |
|---|---|---|
| OSV database | osv.dev | CC BY 4.0 (attribution: Open Source Vulnerabilities, osv.dev) |
| Trivy vulnerability database | Aqua Security trivy-db | Apache-2.0 (the underlying advisories keep their own terms) |
| CISA Known Exploited Vulnerabilities | cisa.gov | Public domain (U.S. Government work) |
| EPSS scores | FIRST.org | Free to use with attribution to FIRST.org, Inc. |

GapScan's own Semgrep rules are Apache-2.0. The Semgrep community rules are **not** in the public image.
See `docs/licenses.md` in the GapScan repository for every scanner's license.
