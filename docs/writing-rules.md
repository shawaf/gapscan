# Write a GapScan rule in 10 minutes

GapScan's own rules are plain [Semgrep](https://semgrep.dev/docs/writing-rules/overview) YAML, licensed
Apache-2.0, with a test file next to each language. A new rule is the easiest useful contribution:
it helps every GapScan user the day it is merged, and you need no other part of the codebase.

## 1. Set up (once)

```bash
git clone https://github.com/shawaf/gapscan && cd gapscan
make setup
uv tool install semgrep==1.176.0      # the version CI tests the rules with
```

## 2. Write the rule

Rules live in `packages/gapscan-security/src/gapscan/rules/semgrep/<language>/`. Add yours to the
language's YAML file, next to rules like it:

```yaml
  - id: gapscan.python.sqli-string-built         # gapscan.<language>.<short-name>
    languages: [python]
    severity: ERROR                              # ERROR, WARNING or INFO
    message: >-
      An SQL statement is built from a string with concatenation, `%`, `.format()` or an f-string.
      Pass the values as bound parameters instead (`cursor.execute("... WHERE id = %s", (value,))`).
    metadata:
      cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]
      category: security
      confidence: HIGH                           # HIGH, MEDIUM or LOW
    patterns:
      - pattern-either:
          - pattern: $C.execute($Q % ..., ...)
          - pattern: $C.execute(f"...{...}...", ...)
```

What every rule needs (`tests/test_own_rules.py` checks it):

- an `id` that starts with `gapscan.<language>.`,
- at least one **CWE**: it is how the finding is mapped to OWASP Top 10, ASVS and the other
  standards, so pick the most specific one,
- a `confidence`, and a **message that says how to fix it**, not only what is wrong,
- for Kotlin, Swift and Dart (mobile) rules, a `masvs` tag such as `MASVS-CRYPTO-1`.

Prefer a taint rule (`mode: taint`) when the problem is "untrusted input reaches a dangerous call":
it raises far fewer false alarms than a pattern on the call alone. The existing taint rules in each
language file show the sources each framework uses.

## 3. Test it

Add a vulnerable and a safe case to `tests/rules/<language>/`, using Semgrep's test annotations:

```python
def sql_cases(cur, name):
    # ruleid: gapscan.python.sqli-string-built
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ok: gapscan.python.sqli-string-built
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
```

Then run:

```bash
semgrep --test --config packages/gapscan-security/src/gapscan/rules/semgrep/python tests/rules/python
make rules-test                                  # every language
uv run python tools/build_rule_controls.py       # refresh the rule -> control table
uv run pytest tests/test_own_rules.py
```

A good rule has at least one `ok:` case that looks almost like the bad one: that is what keeps the
false-alarm rate down.

## 4. Open the pull request

Say what the rule catches, which CWE you chose and why, and where you saw the pattern in real code
if you can (a public repository or an advisory). If the rule is for a benchmark category, you can
score it with `uv run python tools/rule_bench.py <language>` ([`rules.md`](rules.md) explains the
method: rules are tuned on the dev half only and must make sense outside the benchmark).

Not sure a rule is worth writing? Open a **Rule request** issue first, or look for issues labeled
`good first issue`.
