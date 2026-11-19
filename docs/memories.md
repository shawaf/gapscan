# Team memories

Notes your reviewers write about *your* project, shown to the model reviewer when a similar finding comes up. They make the reviewer stop repeating the same mistake ("this folder is not deployed", "this helper really validates the id").

```bash
gapscan memory add "the logs folder is never deployed" --path src/logs
gapscan memory add "sanitizeId() allows only [a-z0-9_-]" --rule detect-non-literal-fs-filename --path src/api
gapscan memory list
gapscan memory rm <id>
gapscan memory from-decisions scan.json gapscan-decisions.json   # decisions that carry a real note
gapscan triage scan.json -t . --memories data/memories.json       # default: <data dir>/memories.json
```

In `gapscan serve` the same thing lives on each project's page (add, disable, delete), and a decision saved with a note creates a memory automatically.

## Rules of the road
- **Scoped:** a memory applies by rule, folder or glob, and weakness (CWE). An unscoped note applies weakly everywhere. The best three matches are shown.
- **Advisory:** the model is told to treat them as leads to verify against the code. They never change the hard guardrails (installed vulnerable dependencies, KEV, secrets, prompt-injection handling, rule-decided findings).
- **High and critical findings stay protected:** a dismissal made while a "harmless" or "accepted" memory was shown becomes "needs review", so one wrong note cannot hide a serious issue.
- **Auditable:** each verdict lists the memories it saw; the dashboard shows them under the review. Deleting or disabling a memory applies from the next scan.
- **Yours:** a plain JSON file (`{"version": 1, "memories": [...]}`) or a table in the manager database. Nothing is learned silently and nothing leaves the machine.

Evaluation and the adversarial test are in `docs/evaluation.md`.
