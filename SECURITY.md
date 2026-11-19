# Security policy

GapScan reads untrusted code and feeds it to a language model, so its own security matters as much
as what it finds. Thank you for helping keep it safe.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Report it privately through GitHub:
open the repository's **Security** tab and choose **Report a vulnerability**. Include what you did,
what happened, and the GapScan version or commit.

You will get an acknowledgement, and we will keep you informed while we investigate and fix it.
Please give us a reasonable time to release a fix before you disclose the problem publicly; we
will credit you in the release notes unless you prefer otherwise.

## Supported versions

GapScan is in **early alpha**. Only the latest commit on `main` receives security fixes.

## What counts as a vulnerability in GapScan

GapScan promises a set of hard rules (see `CLAUDE.md` and the "Built to be trusted" section of
`README.md`). A way to break any of them is in scope, for example:

- **Executing scanned code**: anything that makes GapScan run, build, install or import code from
  the folder it scans.
- **Network access during a scan**: a scan that contacts any host, or a model endpoint that is not
  localhost or an explicitly configured internal host.
- **Prompt injection that escapes the guardrails**: scanned content that makes the reviewer call a
  tool outside its allowlist, read files outside the target folder, or have its output accepted
  without schema validation.
- **Hiding findings**: scanned content (a config file, a comment, a crafted file) that suppresses
  findings without the owner's knowledge.
- **Secret exposure**: a secret value from the scanned code appearing unredacted in a finding, the
  cache, a log, a report or an export.
- **Dashboard and manager**: script injection in a generated report, or a way for another site or
  local user to drive the manager (`gapscan serve`) without its session token.
- **Supply chain**: a downloaded engine, model, rule or data file that is accepted without matching
  its pinned checksum.

## Out of scope

- Vulnerabilities **in the code GapScan scans**: those are findings, not GapScan bugs.
- Missed detections and false alarms (please open a normal issue; `docs/evaluation.md` explains how
  detection quality is measured).
- Problems in third-party scanners or models that GapScan runs; report those to their projects, and
  tell us if GapScan should work around them.

## Test data

The folders `eval/fixtures/`, `tests/rules/`, `tests/data/` and `packages/gapscan-local/src/gapscan/sample_project/`
contain deliberately fake, invalid credentials that the scanners are meant to find. They are not a
leak. If you find a credential anywhere that looks real, please report it privately as above.
