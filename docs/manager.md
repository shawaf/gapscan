# GapScan Control Center (`gapscan serve`)

One dashboard on localhost to start scans, watch them, and read and act on the results, so nobody
has to switch to a terminal. It follows the gap model: you first choose a **domain** (what to close gaps
against), then a project, and a project's menu is grouped into **Gaps** (overview, runs, the gaps),
**Targets** (the standards it is measured against) and **Evidence** (dependencies, secrets, hotspots,
compare). A scan never blocks the interface: its progress stays in the top bar while you keep working.

```bash
make dashboard manager        # build the UIs once (needs node); the built files are committed
uv run gapscan serve --open   # prints http://127.0.0.1:8765/?token=...
uv run python tools/demo_manager.py --seed 3   # the same UI on recorded data, no scanners needed
```

## Screens
| Screen | What it does |
|---|---|
| Domains (start page) | full-width grid (three columns on wide screens) of domain cards, each with an inline picture of what the domain covers; the gap model in one line (target − evidence = gap → proof of fix) and one card per domain: Application security (built: ASVS 5.0 and Top 10:2025 with coverage views, API Security Top 10 2023 and MASVS mapped on gaps, GenAI LLM Top 10 2026 planned, your own policy file as a gate), then the planned compliance and legal domains: security standards, industry regulations, EU regulation, privacy laws, and the Middle East and North Africa. The planned domains come from the engine's catalog (`gapscan/compliance/catalog.json`, `GET /api/compliance`); each opens a page listing its frameworks with region, what scans can show and build wave, and says nothing is measured yet. |
| Application security projects | cards or table of registered folders, add, archive and restore (history and decisions are kept, runs are blocked while archived), delete with a typed confirmation |
| Overview | risk score and grade with trend and an explanation drawer, open gaps by severity, review verdicts, top gaps to close, coverage of the ASVS target, change since the previous run, limits of the result |
| Runs | start a run (preset: full scan, scanners only or dry run; scanners with availability, model profile, findings to review, tool calls, baseline, ASVS level), watch the live run step by step, queue, history, run drawer with scanner table, log and a failed-run banner, cancel with confirmation; a **dry run** lists the files by language, which scanners would run or be skipped, whether the model is ready, the ignore file and an estimate, and starts nothing or writes anything; waiting benchmarks appear in the queue |
| All targets | every security target of the project, its state (coverage view, mapped on gaps, gate, planned) and the numbers this run has for it |
| Gaps (findings) | saved views with counts, ten filters with removable chips, group and sort, columns, virtualized table, bulk decisions with a note, keyboard control, export of the current view |
| Finding drawer | decision panel (a note is required), code with flagged lines, scanner evidence, the AI review in a labeled box with confidence, tools used and team memories, callers, untrusted sources, cheat sheets, history across runs, a held-for-review notice for prompt-injection attempts |
| OWASP Top 10 | heat view of the ten categories (color is the worst open severity) and a table with cheat sheets |
| ASVS coverage | the three states with a warning about what "no finding" means, a chapter matrix that expands to requirements |
| Dependencies | tabs for vulnerable packages (KEV, EPSS, fixed in), the upgrade plan, and the SBOM |
| Secrets and Config | locations only, never values, with a notice when a scanner was unavailable |
| Hotspots | treemap of files (size is lines, color is worst severity) and the riskiest files |
| Compare | any two finished runs: new, fixed and still-open findings, score change, trend chart |
| Settings | default scanners, review model profile and defaults, how ignore rules work, team memories of the project |
| System Health | checklist with component, version and how-to-fix, data freshness bars, offline bundle import, model manager with **Benchmark this model** (runs the labeled cases through the same queue as scans, so it never competes with a scan for the model, and shows the last result per model) |

States from the design are built: live-update pause and retry, model server offline, stale data with an
import action, scanner unavailable, loading skeletons, empty (first use and no matches), failed and
interrupted runs, and confirmations for cancelling a run and deleting a project.

Keyboard: `1` to `9` jump between the project pages (Compare has no number), `/` search, `j` and `k` move, `Enter` opens, `x` selects,
`Esc` closes, `Ctrl/Cmd K` the command palette, `t` the theme.

## How it is built
- Python standard-library HTTP server (no web framework), SQLite (`data/gapscan.db`) for projects,
  scan history, decisions, team memories and settings. Scan artifacts live in `data/runs/<scan id>/`
  (`scan.json`, `triage.json`, `report.json`, `report.html`, `exports/`).
- One worker runs one scan at a time; the rest wait in a queue and can be removed. Cancel is
  cooperative (stops between findings). Each run records its own options (scanners, profile, tool
  calls, ASVS level, baseline) and live statistics.
- The UI is a Preact app in `dashboard/` that builds to one offline HTML file
  (`packages/gapscan-local/src/gapscan/server/templates/manager.html`) with system fonts and inline SVG only. The result
  pages read the same report JSON as the standalone report (`GET /api/scans/<id>/report.json`).
- Decisions are saved by the server; "Rebuild report" re-renders a finished run with the latest
  decisions without rescanning. A decision that carries a real note also creates a team memory.

## Security design
- Binds to loopback only; `--host` accepts only loopback addresses. `Host` is checked on every
  request (blocks DNS rebinding).
- A random per-launch token: the printed URL sets an HttpOnly, SameSite=Strict cookie and then
  redirects, so the token leaves the address bar. Every API call needs the cookie (or a Bearer
  header). `/health` is the only open path and reveals nothing.
- State-changing requests must be same-origin JSON (Origin and Content-Type checked), so another
  web page cannot drive the API. 1 MB body limit. CSP, `nosniff`, no-referrer and no-store headers.
- Only folders you registered can be scanned. Filesystem roots, the home folder and the data
  folder are refused. Scans never execute the scanned code (same engine as the CLI).
- Bundle import accepts only a `.tar.gz` path and runs the same verify-before-install as
  `gapscan update`.

## Sending runs to a team workspace

A local run can be sent to a GapScan Platform workspace as a signed "local run" report
from the app instead of the command line:

1. **Settings → Team workspace**: enter the team server's address and the token your workspace
   admin gave you, then **Connect**. The address is checked by asking the server who the token
   is; HTTPS is required except for this machine and private network addresses. The token is
   kept in `<data dir>/workspace-token`, readable only by you, and never sent back to the page.
2. **Create key** once, and give the public key (Copy) to the admin, who registers it under your
   name in the team dashboard.
3. On a finished run, **Send to team workspace**: pick the workspace project and press Send. The
   run is signed with this install's key and holds findings and their evidence only.

This is the manager's only connection to another machine besides the setup wizard's pinned
downloads (`server/workspace.py`, allowed by name in the `network` import contract). It happens
only when you press Connect, open the project picker or press Send, never during a scan, never
follows a redirect, and goes only to the address you saved. The sidebar says when a workspace is
connected. **Disconnect** deletes the token.

## Limits (Stage 2 work)
Single user, single machine, no accounts or roles, one scan at a time, SQLite. "Build a bundle" from the design is not built: a bundle is made on a connected machine with `gapscan bundle`. Run provenance ("started by") is not recorded because there are no users. The
engine, data model and dashboard stay separate so a multi-user server can replace this layer.

## Setup wizard and the managed AI engine

The **Setup** page (left menu, under Settings) gets a machine ready in five steps: it reads the hardware, installs the AI engine, downloads a model that fits, downloads the security data, and starts the engine to check it loads.

- **AI engine:** `llama-server` from llama.cpp, started by the manager on a free loopback port with the web UI off, one request at a time, and stopped when the manager stops. Scans start it by themselves when a run needs the model (and switch it when a run asks for another installed model). While it runs, the manager's configuration points at it (OpenAI-style backend); when it stops, the configuration returns to what you set up yourself, for example your own Ollama.
- **Which model fits:** usable memory (75% of RAM on Apple silicon, VRAM plus 40% of RAM with an NVIDIA card, 60% of RAM otherwise) against the model's file size plus 15% for the context. A model that does not fit cannot be selected; if none fits, scanners still run and AI review stays off.
- **The only online step.** Setup downloads only from the hosts listed in `packages/gapscan-local/src/gapscan/runtime/manifest.json` (every redirect hop is checked again, HTTPS only), only the files pinned there by size and sha256, resumes interrupted downloads, refuses when the disk is too small, and discards a file whose checksum does not match. Scans stay offline.
- **Updating the list:** `uv run python tools/make_pack_manifest.py` (needs network; reads metadata only) rewrites the manifest from the pinned llama.cpp release and the model repositories.
- **Models:** `qwen3-coder:30b` is the only model with measured results (see `docs/evaluation.md`). The 14B model is offered for 16 GB machines but has not been benchmarked yet. The tiny 3B model is not offered.
- **Files:** `data/runtime/` holds `bin/`, `models/`, `logs/` and `state.json`.


## First run

On a computer where nobody has been through it yet (no projects and no welcome decision saved), the app opens on a **Welcome** page instead of an empty project list.

- **One plan.** It reads the machine and lists what it would set up, in order, with sizes: the AI engine, the AI model (nothing to download when Ollama already has it), the small knowledge-base model, the scanners that are missing, and optionally the security data (vulnerability databases, advisories). The person can untick the AI part or the security data, press **Set up**, and watch one progress bar; **Stop** keeps what was downloaded. A step that fails stops the run with the reason, and offers *Try again* or *Carry on anyway*.
- **Reopening is safe.** If the app is closed halfway, the next launch shows the same page with finished steps ticked, and picks up a step that was still running.
- **Skip for now** remembers the choice; the Setup page stays in the menu for later.
- **Then a first scan.** When everything is ready the page offers **Try the sample project**: a small app with planted mistakes (SQL injection, command injection, template injection, an open redirect, a hardcoded key, a weak hash, vulnerable dependencies, an unsafe Dockerfile, risky browser code) is copied to the user's GapScan folder and scanned with the scanners only. With the real scanners it takes about 45 seconds and gives about 58 findings across code, configuration, dependencies and secrets. It is only read, never run. **Add my own project** goes to the project form.
- **API:** `GET /api/setup` now includes `plan` and `welcome` (`null`, `"done"` or `"skipped"`), `POST /api/setup/welcome` saves the decision and `POST /api/sample` creates the sample project.
