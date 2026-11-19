# Third-party notices

GapScan is licensed under the Apache License 2.0 (`LICENSE`). It includes or redistributes the
third-party material below. The full register of everything GapScan runs, bundles or measures
against, with how each license was verified, is `docs/licenses.md`.

## MITRE CWE

CWE names and identifiers in `packages/gapscan-security/src/gapscan/owasp/mappings/` (and the CWE catalog text in the
knowledge base that `gapscan kb build` creates) come from the MITRE CWE catalog. The CWE Terms of
Use require reproducing MITRE's copyright designation and the license in every copy:

Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation.

> CWE™ is free to use by any organization or individual for any research, development, and/or commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE’s copyright designation and this license in any such copy. CWE is a trademark of The MITRE Corporation. Please contact cwe@mitre.org if you require further clarification on this issue.

Source: https://cwe.mitre.org/about/termsofuse.html (read 2026-10-09). Provided by MITRE on an
"as is" basis without warranty of any kind.

## OWASP material (CC BY-SA 4.0)

The mapping tables in `packages/gapscan-security/src/gapscan/owasp/mappings/` are adapted from OWASP Top 10:2025 and OWASP
ASVS 5.0.0, and the per-weakness checklists in `packages/gapscan-security/src/gapscan/agent/checklists.json` are written from
the OWASP Cheat Sheet Series. They are licensed under Creative Commons Attribution-ShareAlike 4.0
International (https://creativecommons.org/licenses/by-sa/4.0/), copyright the OWASP Foundation and
contributors; see `packages/gapscan-security/src/gapscan/owasp/mappings/NOTICE.md` for what was changed.

## Libraries inlined into the report and manager pages

The single-file HTML pages (`packages/gapscan-security/src/gapscan/report/templates/dashboard.html`,
`packages/gapscan-local/src/gapscan/server/templates/manager.html`, and every report generated from them) inline Preact
(MIT), Apache ECharts (Apache-2.0, with its NOTICE), ZRender (BSD-3-Clause), highlight.js
(BSD-3-Clause) and tslib (0BSD). Their full license and notice texts are embedded in each page in
the `<script type="text/plain" id="third-party-notices">` block, generated at build time from each
package's own files (`dashboard/third-party-notices.ts`).

## Bundles

Offline bundles carry their own `NOTICES.md` (OWASP, MITRE, vulnerability data, and the model or
Semgrep community rules when included); see `packages/gapscan-local/src/gapscan/offline/bundle.py`.
