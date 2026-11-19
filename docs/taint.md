# Inter-procedural taint analysis (`taint` scanner)

GapScan's own engine for the bugs a single-function rule cannot see: attacker data that is read in
one file, passed through helpers in other files and written to a sink in a third. It runs in the
same scan as the other scanners (enabled by default, no binary to install) and reports each
source-to-sink path as a finding with the whole path as evidence.

Languages: Java, Python, JavaScript/TypeScript. Sinks: SQL, OS command, path, SSRF, XSS, open
redirect, deserialization, code injection, LDAP, XPath, NoSQL, trust boundary.

## How it works

1. **Parse** every source file with tree-sitter (text only, nothing is run: hard rule #1).
2. **Summarize each function**: which parameters reach its return value, which reach a sink (and
   which), and whether it returns data that comes straight from an untrusted source.
3. **Iterate to a fixed point** over the whole project (at most 6 passes), so a summary can use the
   summaries of the functions it calls, in any file order.
4. **Report** a finding whenever a source label reaches a sink argument that is not cleaned for that
   kind of sink. The finding's `raw.taint_path` lists every hop (`file:line`), and
   `raw.cross_file` says whether the path crosses files.

Inside a function the analysis is flow-ordered: an assignment at the top level replaces the old
taint; an assignment inside a branch or loop only adds to it. Collections and builders
(`list.add`, `sb.append(a).append(b)`) absorb what goes in; `this`/`self` fields flow between the
methods of a class; script-level code (Python, JS) is analyzed too.

## Models are data

Sources, sinks, sanitizers and "never carries text" calls live in `packages/gapscan-security/src/gapscan/taint/models/*.toml`,
one file per language or framework. A file with `requires` only applies to source files that match
it. Shipped: Java core, Servlet, Spring; Python core, Flask, Django, FastAPI; JavaScript core,
Express/Koa/Fastify-style. Adding a framework is adding a file; the engine does not change.

## Heuristics (visible, and the reason triage still matters)

- Numeric/boolean/UUID parameter types and `int()`, `parseInt`, `Integer.parseInt` ... clean the value.
- A function whose name says sanitize/escape/validate/allowlist is treated as a sanitizer.
- Checks follow their polarity: `if not valid(x): return` (or `abort()`, `throw`) validates `x` from
  then on; `if valid(x): use(x)` validates `x` inside that block only; `if '../' in x: return`
  protects `x` against path traversal afterwards. A weak check still hides a real bug, which is
  why triage reviews them.
- `CONSTANT_TABLE.get(user_value, default)` returns the table's values, not the input.
- Environment variables and CLI arguments are sources only for command/code/SQL/deserialization
  sinks: they are set by the operator, not by an attacker.

## Limits

Name-based call resolution (no types: same-named methods on different classes can be confused, at
most 4 candidates are followed), no aliasing, no flow through fields of other objects, no
reflection, no framework wiring beyond the TOML models. It does not see data that is not read from a
request (e.g. archive contents for zip-slip).

## Measured results

Full tables and caveats: [docs/results/DATAFLOW.md](results/DATAFLOW.md). In short:

| Set | Data-flow engine | GapScan rules alone |
|---|---|---|
| OWASP Benchmark Java, held-out half | 62% caught, 0% false alarms (+62); 100% / 0% in every injection category | +47 |
| OWASP Benchmark Python, held-out half | 57% / 4% (+54) | +51 |
| Independent: SecuriBench Micro + 6 real apps, first look | 68% / 16% (+51) | 61% / 16% (+45) |
| Own corpora and labeled fixtures (`tests/test_taint.py`) | all caught, no false alarms | |

The Benchmark numbers are within one family of synthetic test cases whose decoys the engine was
built to see through; the independent check is the realistic estimate.

## Precision features

Constant folding (conditions, `switch` and `match` selectors, string methods on constants),
index-aware lists and key-aware maps and `configparser` objects, strong updates for variables and
collections declared in the same block, typed receivers for Java (a `StringBuilder` never resolves
to a project method named `append`), path-aware guards (`if not valid(x): return` validates `x`
afterwards; `if valid(x): ...` only inside), blocklist checks (`if '../' in name: return`),
derived-value validation (`url = urlparse(bar)` then checking `url`), template-aware XSS, and a
per-function work budget so no input can stall a scan.
