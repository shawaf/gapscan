# AI upgrades

## Hardware tiers

Same prompts at every tier; only the model, and optionally where it runs, changes.

    [llm]
    tier = "laptop"          # ci (8B) | laptop (14B) | server (30B), or your own

    [llm.tiers.gpu]          # a team GPU server on the internal network
    profile = "best"
    endpoint = "http://gpu01.internal:11434"   # localhost, a private address or name, or a
                                               # host listed in llm.internal_hosts

    [llm]
    tier = "gpu"

Explicit `llm.profile`, `llm.model` and `llm.endpoint` always win over a tier. The endpoint rule is
unchanged: public hosts are refused. For a GPU server, `config/gapscan.example.toml` shows a
`server` profile with `gpt-oss:120b` (checked on the Ollama registry on 2026-10-07; Apache-2.0). It is
not benchmarked by GapScan: run `gapscan model bench` on your server first.

## Verified with a real model

On 2026-10-07, on a 4-core CPU-only Linux machine with 16 GB RAM, without Ollama:

* The setup wizard (`gapscan/runtime/`) downloaded the pinned llama.cpp b11403 engine, the
  `qwen2.5-coder:14b` Q4_K_M model (9.0 GB), the embedding model, and the six scanners. It checked
  every file against its pinned sha256 and started the engine on a loopback port (ready in 48 s).
* `gapscan triage --limit 3` on `eval/fixtures/vuln-app`: three schema-valid verdicts with evidence
  references. Command injection and pickle deserialization came back `true_positive`; the AWS key
  came back `needs_review`. The repo summary grouped the findings correctly.
* `gapscan fix` on the SQL injection: the model proposed a parameterized query. The re-scan removed
  all 4 SQL-injection findings at that line and added none, so the patch was offered. Without
  `--apply`, the project was left untouched.
* Speed on this CPU: about 8 prompt tokens/s and 1.4 generated tokens/s, so roughly 2 to 3 minutes
  per finding. Use a GPU or the `small` profile for interactive use.

## Team memory (org memory)

Already in Stage 1: `gapscan memory add/list/rm/from-decisions` and the project page in
`gapscan serve`. Memories are visible, editable, deletable and shown to the model as leads, never
as orders (`docs/memories.md`).

## Verified autofix (`gapscan fix`)

    gapscan fix scan.json --finding <id> --target ./repo [--apply]

1. The local model proposes `old -> new` text for the flagged file (schema-validated, one
   replacement, `old` must occur exactly once, at most 40 changed lines).
2. The patch is applied to a **temporary copy** of the project, never to the real one.
3. The scanners that reported the finding are run on the copy before and after.
4. It is offered only if the finding is gone and no new finding appeared. A rejected patch is
   retried once with the reason as feedback; otherwise the answer is "no verified fix".
5. `--apply` writes a verified patch to the file; without it nothing is written.

Covers code and configuration findings. Dependencies (upgrade) and secrets (rotate) are refused.
**Not done on purpose:** running the project's build or tests against the patch. That executes
scanned code, which hard rule #1 forbids; the roadmap's optional sandboxed-test step needs that rule
amended by the owner first.

## Data flywheel (opt-in, on-premises)

    [flywheel]
    enabled = true
    gapscan memory export-dataset scan.json gapscan-decisions.json -t ./repo -o gapscan-dataset

Each reviewer decision becomes one training example (the prompt the triage model sees, and the
answer the decision implies as `TriageAnswer` JSON), split by a hash of the finding id into
`train.jsonl` and `heldout.jsonl` (default 20% held out) with a `manifest.json`. Secret-looking text
is masked. It is a local file: nothing is sent anywhere, and the export refuses to run until the
owner enables it. The files contain code excerpts, so treat them like the source. Training itself is
Phase 10 (a tuned model is accepted only if it beats the base model on the held-out file).
