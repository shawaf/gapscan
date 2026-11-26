## What this changes

<!-- The problem, and what behaves differently after this change. -->

## How it was tested

<!-- Commands you ran (`make lint`, `make test`, `make rules-test`, `make eval` for triage changes). -->

## Checklist

- [ ] `make lint` and `make test` pass
- [ ] New code has unit tests; a new rule has an `ok:` and a `ruleid:` case
- [ ] No hard rule in `CLAUDE.md` is weakened (no network during `scan`, scanned code never run, secrets redacted)
- [ ] Docs and `CHANGELOG.md` updated if users will notice the change
