# Bring in results from other tools (`gapscan scan --import`)

GapScan reads code. Some problems are only proven by testing the running application, and you may
already run other scanners. `--import` adds their results to a scan as evidence, so everything lands
in one report, mapped to the same OWASP controls.

```bash
gapscan scan ./my-app -o scan.json \
  --import zap-report.json \
  --import nuclei.jsonl \
  --import codeql.sarif
gapscan report scan.json -t ./my-app
```

| Format | Produce it with | Becomes |
|---|---|---|
| SARIF 2.1.0 | CodeQL, most SAST tools (`--format sarif`) | code findings, like GapScan's own |
| OWASP ZAP JSON report | `zap-baseline.py -t URL -J zap-report.json`, `zap-full-scan.py ... -J`, or the "Traditional JSON Report" | runtime findings |
| nuclei JSON Lines | `nuclei -u URL -jsonl -o nuclei.jsonl` (an array from `-json-export` works too) | runtime findings |

The format is recognized from the file's content, and a file GapScan cannot read stops the scan with
a reason, never silently.

## Code confirmed at runtime

A **runtime finding** keeps the request that showed the problem (method, URL, parameter) and the
scanner's own evidence, for example the database error ZAP saw, as its quoted evidence.

GapScan then looks for the code each runtime finding confirms: a code finding with the **same CWE**
in a file that names the request's **route** as a string at most 40 lines above it (the decorator or
registration of the handler that contains it, such as `@app.route("/user")` or
`app.get("/user", ...)`). A confirmed code finding:

- lists the runtime scanner in its sources (`semgrep, zap`),
- shows a reachability line such as *Confirmed at runtime by zap: SQL Injection at GET /user?name=...*,
- ranks higher, because a problem proven against the running application is no longer a guess.

The match is deliberately strict, so it can miss a link (a route built from parts, or a handler far
from where its route is declared). It never links on the site root alone.

## What GapScan does and does not do here

- It only **reads** the files you give it. It never runs ZAP or nuclei and never contacts the
  application: the scan stays offline (hard rule 2).
- Secret values in imported evidence are masked like in any other finding (hard rule 4).
- Run dynamic scanners only against applications you own or are authorized to test.
