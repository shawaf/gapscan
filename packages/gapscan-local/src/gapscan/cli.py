"""GapScan command-line interface (typer).

Phase 0 wires the command skeleton and a working `doctor`. The scan/kb/bundle
commands are stubs that will be filled in by later phases.
"""

from __future__ import annotations

import errno
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .agent.review import AgentSteps
from .config import Config, load_config
from .core.version import __version__
from .doctor import Status, run_all_checks
from .evaluation.runner import headline, run_eval, write_result
from .evaluation.targets import fetch_target, is_fetched, load_targets
from .kb import build_kb, load_kb
from .llm.bench import load_cases, run_benchmark
from .llm.client import LLMClient, LLMError
from .memory import (
    Memory,
    add_memory,
    from_decision,
    load_memories,
    remove_memory,
    save_memories,
)
from .models import Finding, Investigation, ScannerRun, ScanResult, Verdict
from .offline.bundle import BundleError, BundleOptions, build_bundle
from .offline.fetch import (
    FetchError,
    fetch_enrichment,
    fetch_kb_sources,
    fetch_osv_db,
    fetch_owasp,
    fetch_trivy_db,
)
from .offline.refresh import download_wheels, refresh_all
from .offline.update import UpdateError, import_bundle, verify_bundle
from .paths import use_app_dir
from .pipeline import collect_evidence, normalize_scan, run_scan
from .report.build import load_previous
from .report.dashboard import TemplateMissing
from .report.decisions import load_decisions
from .report.exports import write_exports
from .report.exports.pdf import PdfUnavailable, render_pdf
from .report.service import build_dashboard
from .runtime.download import DownloadCancelled, DownloadError
from .runtime.manager import RuntimeManager
from .runtime.tools import activate as activate_tools
from .scanners.imports import Imported, ImportError_, load_import
from .services import ReviewHooks, review_scan
from .stages import StageMismatch, TriageOutput
from .store.raw import RawStore

app = typer.Typer(
    name="gapscan",
    help="Offline security analysis: deterministic scanners + a local LLM triage agent.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to gapscan.toml (defaults to search + env)."),
]


def _load(config_path: Path | None) -> Config:
    try:
        cfg = load_config(config_path)
        activate_tools(cfg.data.dir / "runtime")  # scanners installed by the setup wizard
        return cfg
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Config error:[/red] {exc}")
        raise typer.Exit(code=2) from exc


@app.callback()
def _main() -> None:
    """GapScan — offline AI security analysis agent."""
    use_app_dir()  # an installed package keeps its data in the per-user folder, not the cwd


@app.command()
def setup(
    scanners: Annotated[
        bool, typer.Option("--scanners/--no-scanners", help="Download missing scanners.")
    ] = True,
    data: Annotated[
        bool, typer.Option("--data/--no-data", help="Download the vulnerability data.")
    ] = True,
    java_db: Annotated[
        bool, typer.Option("--java-db", help="Also Trivy's Java DB (about 2.6 GB).")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Get this machine ready to scan (needs network once; the scan itself stays offline).

    Downloads the scanners that are missing (Trivy, Gitleaks, OSV-Scanner, and Semgrep, Checkov and
    Bandit in a private Python), only from the hosts pinned in the setup manifest, each file checked
    against its pinned sha256, and then the vulnerability data (`gapscan data fetch-vulns`)."""
    cfg = _load(config)
    if scanners:
        tools = RuntimeManager(cfg.data.dir).tools
        last = [-1]

        def progress(done: int, total: int) -> None:
            pct = int(done * 100 / total) if total else 100
            if pct // 25 != last[0] // 25:
                last[0] = pct
                console.print(f"  {pct}% of {total / 1e6:.0f} MB")

        try:
            tools.install(progress, say=lambda m: console.print(m, markup=False))
        except (DownloadError, DownloadCancelled, OSError) as exc:
            console.print(f"[red]Scanner download failed:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        tools.activate()
        left = tools.missing()
        if left:
            console.print(
                "[yellow]Still missing:[/yellow] " + ", ".join(left) + " (no pinned download for "
                "this platform; install them yourself or use the Docker image)"
            )
        else:
            console.print("[green]Every scanner is ready.[/green]")
    if data:
        try:
            data_fetch_vulns(java_db=java_db, config=config)
        except (FetchError, OSError) as exc:
            console.print(f"[red]Vulnerability data download failed:[/red] {exc}", markup=True)
            console.print("Scanning still works; dependency checks need this data. Retry later.")
            raise typer.Exit(code=1) from exc
    console.print("Next: `gapscan scan <folder> -o scan.json`, then `gapscan report scan.json`.")


@app.command()
def version() -> None:
    """Print the GapScan version."""
    console.print(f"gapscan {__version__}")


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(help="Path to the target repository to analyze.")],
    out: Annotated[
        Path, typer.Option("--out", "-o", help="Output path for the findings JSON.")
    ] = Path("gapscan-findings.json"),
    image: Annotated[
        list[Path] | None,
        typer.Option(
            "--image",
            help="A container image saved with `docker save -o app.tar` (repeatable). "
            "Scanned offline with Trivy and shown as its own view.",
        ),
    ] = None,
    imports: Annotated[
        list[Path] | None,
        typer.Option(
            "--import",
            help="Results of another tool to add as evidence (repeatable): SARIF, an OWASP ZAP JSON "
            "report or nuclei JSON Lines. A ZAP or nuclei result marks the code it confirms.",
        ),
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Run the scanners and normalize their findings (LLM triage and the dashboard come later)."""
    cfg = _load(config)
    if not target.is_dir():
        console.print(f"[red]Target directory not found:[/red] {target}")
        raise typer.Exit(code=2)
    missing = [p for p in image or [] if not p.is_file()]
    if missing:
        console.print(f"[red]Image archive not found:[/red] {', '.join(map(str, missing))}")
        raise typer.Exit(code=2)
    imported: list[Imported] = []
    for path in imports or []:
        try:
            imported.append(load_import(path, target))
        except ImportError_ as exc:
            console.print(f"[red]Cannot import:[/red] {exc}", markup=False)
            raise typer.Exit(code=2) from exc
    if imported:
        raw = collect_evidence(cfg, target, images=image or [])
        for item in imported:
            raw.findings += item.findings
            raw.runs.append(ScannerRun(scanner=f"{item.scanner} (imported)", status="ok",
                                       finding_count=len(item.findings)))  # fmt: skip
        result = normalize_scan(cfg, raw, target)
    else:
        result = run_scan(cfg, target, images=image or [])
    out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    table = Table(title=f"Scanners ({result.target})")
    for col in ("scanner", "status", "findings", "seconds"):
        table.add_column(col)
    for r in result.runs:
        table.add_row(r.scanner, r.status, str(r.finding_count), f"{r.duration_s:.1f}")
    console.print(table)
    console.print(
        f"{len(result.findings)} findings after merging, {result.ignored_count} ignored -> {out}"
    )
    confirmed = sum(1 for f in result.findings if f.raw.get("runtime_proof"))
    if confirmed:
        console.print(f"{confirmed} code finding(s) confirmed at runtime by imported results")
    if any(r.status != "ok" for r in result.runs):
        console.print("[yellow]Some scanners did not run; see the table above.[/yellow]")


@app.command()
def fix(
    scan_json: Annotated[Path, typer.Argument(help="Findings JSON from `gapscan scan`.")],
    finding_id: Annotated[str, typer.Option("--finding", "-f", help="Finding id to fix.")],
    target: Annotated[
        Path, typer.Option("--target", "-t", help="The project that was scanned.")
    ] = Path("."),
    apply: Annotated[
        bool,
        typer.Option("--apply", help="Write a verified patch to the file (default: only show it)."),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Propose a patch with the local model and offer it only if a re-scan confirms it works:
    the finding must disappear and no new finding may appear. Nothing is written unless --apply."""
    from .autofix import NoFix, apply_offer, suggest_verified_fix
    from .models import ScanResult

    cfg = _load(config)
    result = ScanResult.model_validate_json(scan_json.read_text(encoding="utf-8"))
    finding = next((f for f in result.findings if f.id == finding_id), None)
    if finding is None:
        console.print(f"[red]No finding with id[/red] {finding_id}")
        raise typer.Exit(code=2)
    try:
        offer = suggest_verified_fix(cfg, target, finding, client=LLMClient(cfg.llm))
    except NoFix as exc:
        console.print(f"[yellow]No verified fix:[/yellow] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(offer.explanation)
    console.print(offer.diff or "(empty diff)", markup=False)
    for c in offer.checks:
        console.print(f"{'[green]ok[/green]' if c.ok else '[red]FAILED[/red]'} {c.name} {c.detail}")
    if apply:
        apply_offer(target, offer)
        console.print(f"[green]Applied to[/green] {offer.file}")


@app.command()
def watch(
    scans: Annotated[
        list[Path] | None,
        typer.Argument(help="Findings JSON files from `gapscan scan` to re-check."),
    ] = None,
    all_projects: Annotated[
        bool, typer.Option("--all", help="Re-check every project saved in the local manager.")
    ] = False,
    target: Annotated[
        Path | None,
        typer.Option(
            "--target",
            "-t",
            help="The scanned project's folder (one scan only): read to tell whether the "
            "vulnerable function is called.",
        ),
    ] = None,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the alerts as JSON.")
    ] = None,
    notify: Annotated[
        bool, typer.Option("--notify", help="Show a desktop notification when there are alerts.")
    ] = False,
    fail_on_alert: Annotated[
        bool, typer.Option("--fail-on-alert", help="Exit with code 3 when there are alerts.")
    ] = False,
    new_only: Annotated[
        bool,
        typer.Option(
            "--new-only",
            help="Report only advisories no earlier `--new-only` check reported (for a daily job).",
        ),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Zero-day watch: re-check saved scans' dependencies against the vulnerability data installed
    now (after `gapscan update` or `gapscan data fetch-vulns`), without scanning the code again.
    Reports every advisory the saved scan did not know about, exploited (KEV) and reachable ones
    first. Makes no network call. `gapscan schedule enable` runs it every day."""
    _run_watch(_load(config), scans, all_projects, target, out, notify, fail_on_alert, new_only)


def _run_watch(
    cfg: Config,
    scans: list[Path] | None,
    all_projects: bool,
    target: Path | None,
    out: Path | None,
    notify: bool,
    fail_on_alert: bool,
    new_only: bool,
) -> None:
    from .enrich import load_enrichment
    from .notify import desktop_notify
    from .scanners.osv import OSVScanner
    from .server.watch import watch_saved_projects
    from .watch import WatchReport, alert_line, only_unseen, watch_scan

    if not scans and not all_projects:
        console.print("[red]Give one or more scan JSON files, or --all.[/red]")
        raise typer.Exit(code=2)
    if target is not None and (all_projects or len(scans or []) != 1):
        console.print("[red]--target goes with exactly one scan file.[/red]")
        raise typer.Exit(code=2)
    scanner = OSVScanner(cfg.scanners.osv.db_dir, cfg.scanners.timeout_s)
    if not scanner.is_available():
        console.print(
            "[red]osv-scanner or its offline database is missing.[/red] Run `gapscan doctor`."
        )
        raise typer.Exit(code=2)
    enrichment = load_enrichment(cfg.data.enrichment_dir)
    work = cfg.data.dir / "watch"
    reports: list[WatchReport] = []
    for i, path in enumerate(scans or []):
        scan = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        name = Path(scan.target).name or path.stem
        reports.append(
            watch_scan(
                scan, name, scanner, work / f"file-{i}", enrichment=enrichment, target=target
            )
        )
    if all_projects:
        reports += watch_saved_projects(cfg, scanner, work / "projects", enrichment=enrichment)
    alerts = sorted(
        (a for r in reports for a in r.alerts), key=lambda a: (-a.priority, a.project, a.package)
    )
    if new_only:
        known = len(alerts)
        alerts = only_unseen(alerts, work / "reported.json")
        console.print(f"{len(alerts)} not reported before ({known - len(alerts)} already were)")
    for r in reports:
        line = f"{r.project}: {r.components} dependencies checked, {len(r.alerts)} new advisories"
        console.print(line + (f" ({r.note})" if r.note else ""), markup=False)
        if r.skipped_ecosystems:
            console.print(
                f"  no offline database for {', '.join(r.skipped_ecosystems)}", markup=False
            )
    for a in alerts:
        console.print(f"  [{a.severity.value}] {alert_line(a)}", markup=False)
    if out is not None:
        out.write_text(
            json.dumps([r.model_dump(mode="json") for r in reports], indent=2), encoding="utf-8"
        )
    if notify and alerts:
        top = alerts[0]
        title = f"GapScan: {len(alerts)} new advisor{'y' if len(alerts) == 1 else 'ies'}"
        desktop_notify(title, alert_line(top))
    if fail_on_alert and alerts:
        raise typer.Exit(code=3)


@app.command("fix-deps")
def fix_deps(
    scan_json: Annotated[Path, typer.Argument(help="Findings JSON from `gapscan scan`.")],
    target: Annotated[
        Path, typer.Option("--target", "-t", help="The project that was scanned.")
    ] = Path("."),
    patch: Annotated[
        Path | None, typer.Option("--patch", "-p", help="Write all edits as one unified diff.")
    ] = None,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the fixes as JSON.")
    ] = None,
    verify: Annotated[
        bool, typer.Option(help="Rescan a copy with each edit applied (offline, osv-scanner).")
    ] = True,
    config: ConfigOption = None,
) -> None:
    """Propose upgrades for vulnerable dependencies: the nearest version that fixes every advisory
    of a package, edited where the project declares it. Nothing in the project is changed; review
    the diff, then apply it or open a pull request with `gapscan pr`. Package managers are never
    run, so lockfiles are flagged for you to regenerate."""
    from .depfix import combined_diff, propose_dependency_fixes
    from .scanners.osv import OSVScanner

    cfg = _load(config)
    result = ScanResult.model_validate_json(scan_json.read_text(encoding="utf-8"))
    rescan = None
    if verify:
        scanner = OSVScanner(cfg.scanners.osv.db_dir, cfg.scanners.timeout_s)
        if scanner.is_available():
            work = cfg.data.dir / "depfix"

            def rescan(copy: Path) -> list[Finding]:
                work.mkdir(parents=True, exist_ok=True)
                return scanner.run(copy, work)
        else:
            console.print("[yellow]osv-scanner is not available: fixes are not verified.[/yellow]")
    fixes = propose_dependency_fixes(target, result.findings, rescan=rescan)
    if not fixes:
        console.print("No vulnerable dependency with a known fixed version.")
        return
    for fx in fixes:
        state = {True: "verified by rescan", False: "NOT fixed by the edit", None: "not verified"}[
            fx.verified
        ]
        head = (
            f"{fx.package} {fx.from_version or '?'} -> {fx.to_version} ({', '.join(fx.advisories)})"
        )
        console.print(f"{head}: {len(fx.edits)} edit(s), {state}", markup=False)
        for note in fx.notes:
            console.print(f"  {note}", markup=False)
    diff = combined_diff(target, fixes)
    if patch is not None:
        patch.write_text(diff, encoding="utf-8")
        console.print(f"patch written to {patch}", markup=False)
    elif diff:
        console.print(diff, markup=False)
    if out is not None:
        out.write_text(
            json.dumps([fx.model_dump(mode="json") for fx in fixes], indent=2), encoding="utf-8"
        )


@app.command("pr")
def pull_request(
    patch: Annotated[
        Path, typer.Argument(help="Unified diff to propose (from `gapscan fix-deps`).")
    ],
    title: Annotated[str, typer.Option(help="Pull request title and commit subject.")],
    target: Annotated[Path, typer.Option("--target", "-t", help="The git repository.")] = Path("."),
    body: Annotated[str, typer.Option(help="Pull request description.")] = "",
    base: Annotated[
        str, typer.Option(help="Branch to merge into (default: the current one).")
    ] = "",
    branch: Annotated[
        str, typer.Option(help="New branch name (default: gapscan/fix-<hash>).")
    ] = "",
    provider: Annotated[str, typer.Option(help="github | gitlab")] = "github",
    url: Annotated[
        str,
        typer.Option(
            help="API root, e.g. https://ghe.example.com/api/v3 (default: the public one)."
        ),
    ] = "",
    repo: Annotated[str, typer.Option(help="owner/name (default: from the remote URL).")] = "",
    remote: Annotated[str, typer.Option(help="Git remote to push the branch to.")] = "origin",
    token_env: Annotated[
        str, typer.Option(help="Environment variable that holds the API token.")
    ] = "GITHUB_TOKEN",
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Open a pull request with a reviewed patch: new branch, commit, push with your git
    credentials, then the SCM API with your token. You run it; GapScan never opens one on its own.
    Git hooks are disabled for these git calls, so no project code runs."""
    from .pullrequest import PRError, PullRequestPlan, open_pull_request, prepare, push_branch
    from .scm import SCMError

    plan = PullRequestPlan(
        target=target, patch=patch.read_text(encoding="utf-8"), title=title,
        body=body or "Proposed by GapScan at the maintainer's request. Review before merging.",
        provider=provider, api_url=url, repo=repo, base=base, branch=branch, remote=remote,
    )  # fmt: skip
    try:
        prepare(plan)
    except (PRError, SCMError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print(
        f"Will push branch {plan.branch} to {plan.remote} and open a pull request into "
        f"{plan.base} on {plan.repo} ({plan.api_url}), changing {', '.join(plan.files)}.",
        markup=False,
    )
    if not yes and not typer.confirm("Go ahead?", default=False):
        raise typer.Exit(code=1)
    try:
        push_branch(plan)
        where = open_pull_request(plan, token_env)
    except (PRError, SCMError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"pull request opened: {where}", markup=False)


ci_app = typer.Typer(
    name="ci",
    help="Pipelines, pre-commit and pull requests: diff-aware scan, policy, comment.",
    no_args_is_help=True,
)
app.add_typer(ci_app)


@ci_app.command("run")
def ci_run(
    target: Annotated[Path, typer.Argument(help="The repository to scan.")] = Path("."),
    base: Annotated[
        str | None,
        typer.Option(
            "--base", help="Only findings introduced since this git ref (e.g. origin/main)."
        ),
    ] = None,
    baseline: Annotated[
        Path | None, typer.Option(help="Only findings not in this earlier scan JSON.")
    ] = None,
    staged: Annotated[
        bool, typer.Option("--staged", help="Only findings in staged files (pre-commit).")
    ] = False,
    fast: Annotated[
        bool,
        typer.Option(
            "--fast", help="Fast scanners only (seconds): semgrep, taint, gitleaks, malware."
        ),
    ] = False,
    policy: Annotated[
        Path | None, typer.Option(help="Policy file (default: gapscan.policy.toml in the target).")
    ] = None,
    triage: Annotated[
        Path | None, typer.Option(help="`gapscan triage` output: false positives never block.")
    ] = None,
    decisions: Annotated[
        Path | None,
        typer.Option(help="gapscan-decisions.json: decided false positives never block."),
    ] = None,
    comment: Annotated[
        Path | None, typer.Option(help="Write the pull-request comment (Markdown) here.")
    ] = None,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the full findings JSON here.")
    ] = None,
    sarif: Annotated[
        Path | None,
        typer.Option(help="Write SARIF here (for GitHub code scanning or any SARIF viewer)."),
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Scan, keep what the change introduced, apply the policy. Exit 1 when a rule says `block`."""
    from .ci import dismissed_ids, render_comment, run_ci
    from .diffscan import GitError
    from .policy import load_policy

    cfg = _load(config)
    if not target.is_dir():
        console.print(f"[red]Target directory not found:[/red] {target}")
        raise typer.Exit(code=2)
    if sum(bool(x) for x in (base, baseline, staged)) > 1:
        console.print("[red]Use only one of --base, --baseline, --staged.[/red]")
        raise typer.Exit(code=2)
    try:
        res, scan_result = run_ci(
            cfg, target, load_policy(policy, target), base_ref=base, baseline=baseline,
            staged=staged, fast=fast, dismissed=dismissed_ids(triage, decisions),
        )  # fmt: skip
    except GitError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    if out:
        out.write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")
    if comment:
        comment.write_text(render_comment(res), encoding="utf-8")
    if sarif:
        from .report.build import build_report
        from .report.exports import to_sarif

        data = build_report(scan_result, config=cfg, target=target)
        sarif.write_text(json.dumps(to_sarif(data), indent=2), encoding="utf-8")
    console.print(
        f"{res.considered} of {res.scanned} findings in scope ({res.mode}): "
        f"{res.count('block')} block, {res.count('comment')} comment, {res.count('monitor')} monitor"
    )
    for f, action, name in res.rows:
        if action == "block":
            from rich.markup import escape

            console.print(
                "  [red]BLOCK[/red] "
                + escape(f"[{f.severity.value}] {f.file}:{f.start_line} {f.title} ({name})")
            )
    if res.blocked:
        raise typer.Exit(code=1)


@ci_app.command("comment")
def ci_comment(
    comment_file: Annotated[Path, typer.Argument(help="Markdown from `gapscan ci run --comment`.")],
    provider: Annotated[str, typer.Option(help="github | gitlab | bitbucket | azure")],
    url: Annotated[str, typer.Option(help="Your self-hosted SCM URL (https).")],
    repo: Annotated[
        str,
        typer.Option(
            help="owner/repo (github), project id (gitlab), PROJECT/slug (bitbucket), project/repository (azure)."
        ),
    ],
    number: Annotated[str, typer.Option("--pr", help="Pull / merge request number.")],
    token_env: Annotated[
        str, typer.Option(help="Environment variable that holds the access token.")
    ] = "GAPSCAN_SCM_TOKEN",
) -> None:
    """Post the comment to your self-hosted SCM. The only outbound call GapScan makes."""
    from .scm import SCMError, post_comment

    try:
        where = post_comment(
            provider, url, repo, number, comment_file.read_text("utf-8"), token_env
        )
    except SCMError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"posted to {where}")


@app.command()
def mcp(
    root: Annotated[
        Path, typer.Option("--root", help="Project root the tools are confined to.")
    ] = Path("."),
    config: ConfigOption = None,
) -> None:
    """MCP server over stdio: lets an AI coding assistant scan the code it writes, offline."""
    from .mcp_server import serve

    serve(_load(config), root)


@app.command()
def doctor(config: ConfigOption = None) -> None:
    """Check scanners, the LLM endpoint/model and vuln DBs; print versions."""
    cfg = _load(config)
    checks = run_all_checks(cfg)

    table = Table(title="gapscan doctor")
    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")

    style = {Status.OK: "green", Status.WARN: "yellow", Status.MISSING: "red"}
    glyph = {Status.OK: "OK", Status.WARN: "WARN", Status.MISSING: "MISSING"}
    for check in checks:
        table.add_row(
            check.name,
            f"[{style[check.status]}]{glyph[check.status]}[/{style[check.status]}]",
            check.detail,
        )
    console.print(table)

    missing = [c for c in checks if c.status is Status.MISSING]
    if missing:
        console.print(
            f"\n[red]{len(missing)} component(s) missing.[/red] "
            "With network: `gapscan setup` installs missing scanners and vulnerability data. "
            "Air-gapped: `gapscan bundle` on a connected machine, then `gapscan update`."
        )
        raise typer.Exit(code=1)
    console.print("\n[green]All checks passed.[/green]")


kb_app = typer.Typer(name="kb", help="Local knowledge base (CWE/OWASP/ASVS).", no_args_is_help=True)
app.add_typer(kb_app)


@kb_app.command("build")
def kb_build(
    embed: Annotated[
        bool, typer.Option(help="Compute embeddings (needs the local model server).")
    ] = True,
    config: ConfigOption = None,
) -> None:
    """Build the local knowledge base from the stored CWE/OWASP sources and your policies."""
    cfg = _load(config)
    try:
        index = build_kb(cfg, embed=embed)
    except (RuntimeError, LLMError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    st = index.stats()
    model = st.get("embedding_model") or "none, keyword search only"
    console.print(f"Indexed {st['chunks']} chunks -> {cfg.data.kb_dir} (embeddings: {model})")


@kb_app.command("stats")
def kb_stats(config: ConfigOption = None) -> None:
    """What is in the knowledge base."""
    kb = load_kb(_load(config), use_embeddings=False)
    if kb is None:
        console.print("[yellow]Knowledge base not built. Run `gapscan kb build`.[/yellow]")
        raise typer.Exit(code=1)
    st = kb.index.stats()
    table = Table(title=f"{st['chunks']} chunks (embedding model: {st.get('embedding_model')})")
    table.add_column("source")
    table.add_column("chunks")
    for source, n in sorted(st["by_source"].items()):  # type: ignore[attr-defined]
        table.add_row(source, str(n))
    console.print(table)


@kb_app.command("search")
def kb_search(
    query: Annotated[str, typer.Argument(help="What to look up.")],
    limit: Annotated[int, typer.Option("--limit", "-n")] = 3,
    source: Annotated[
        str, typer.Option(help="Restrict to one source, e.g. cheatsheet or cwe.")
    ] = "",
    config: ConfigOption = None,
) -> None:
    """Search the knowledge base (shows the citation for each hit)."""
    kb = load_kb(_load(config))
    if kb is None:
        console.print("[yellow]Knowledge base not built. Run `gapscan kb build`.[/yellow]")
        raise typer.Exit(code=1)
    hits = kb.search_chunks(query, limit, {source} if source else None)
    for c in hits:
        console.print(f"[bold]{c.citation}[/bold]\n{c.url}\n{c.text[:500]}\n")
    if not hits:
        console.print("no results")


class _ConsoleReview(ReviewHooks):
    """`gapscan triage` progress on the console."""

    def __init__(self, scan: ScanResult) -> None:
        self.by_id = {f.id: f for f in scan.findings}

    def message(self, text: str) -> None:
        console.print(f"[dim]{text}[/dim]")

    def deep_dive_started(self, groups: int) -> None:
        if groups:
            console.print("\n[bold]Deep dive[/bold]")

    def verdict(self, v: Verdict) -> None:
        f = self.by_id[v.finding_id]
        label = "FAILED" if v.triage_failed else f"{v.verdict.value} ({v.confidence:.0%})"
        console.print(f"{f.priority:>5}  {f.rule_id[:48]:<48} {f.file or f.package}: {label}")

    def investigation(self, inv: Investigation) -> None:
        f = self.by_id[inv.finding_id]
        if inv.failed or inv.answer is None:
            state = f"FAILED: {inv.error[:80]}"
        else:
            a = inv.answer
            state = (f"{a.protection.value}, {len(a.evidence)} evidence, {len(a.related)} "
                     f"related, {len(inv.dropped)} ungrounded dropped")  # fmt: skip
        shared = f" (covers {len(inv.covers)} findings)" if len(inv.covers) > 1 else ""
        console.print(f"{f.priority:>5}  {f.rule_id[:48]:<48} {state}{shared}")


@app.command()
def triage(
    findings: Annotated[Path, typer.Argument(help="Findings JSON written by `gapscan scan`.")],
    target: Annotated[Path, typer.Option("--target", "-t", help="The scanned directory.")],
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("gapscan-verdicts.json"),
    limit: Annotated[int, typer.Option(help="Triage at most N top-priority findings.")] = 5,
    summary: Annotated[bool, typer.Option(help="Also write the repo-level summary.")] = True,
    deep_dive: Annotated[
        bool,
        typer.Option(
            help="Also investigate confirmed findings in depth (scope, related "
            "locations, missing controls, ordered fix, verification)."
        ),
    ] = False,
    deep_dive_limit: Annotated[
        int, typer.Option(help="Investigate at most N findings in depth.")
    ] = 5,
    memories_file: Annotated[
        Path | None,
        typer.Option("--memories", help="Team memories file (default: <data dir>/memories.json)."),
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Triage the top findings with the local model (read-only tools), then summarize the repo."""
    cfg = _load(config)
    memories = load_memories(memories_file or _memories_path(cfg))
    data = ScanResult.model_validate_json(findings.read_text(encoding="utf-8"))
    output = review_scan(cfg, data, target, steps=AgentSteps(LLMClient(cfg.llm)), limit=limit,
                         deep_dive_limit=deep_dive_limit if deep_dive else 0, summary=summary,
                         memories=memories, hooks=_ConsoleReview(data))  # fmt: skip
    verdicts, repo = output.verdicts, output.summary
    out.write_text(output.model_dump_json(indent=2), encoding="utf-8")
    if repo and repo.narrative:
        console.print(f"\n[bold]{repo.narrative.headline}[/bold]")
        for r in repo.narrative.top_risks:
            console.print(f"  - {r.title} ({', '.join(r.finding_ids)}): {r.why}")
    elif repo and repo.failed:
        console.print(f"[yellow]Summary failed: {repo.error}[/yellow]")
    console.print(f"{len(verdicts)} verdicts -> {out}")


@app.command()
def report(
    scan_file: Annotated[Path, typer.Argument(help="Findings JSON written by `gapscan scan`.")],
    triage_file: Annotated[
        Path | None, typer.Option("--triage", help="Output of `gapscan triage`.")
    ] = None,
    target: Annotated[
        Path | None,
        typer.Option("--target", "-t", help="The scanned directory (for code and hotspots)."),
    ] = None,
    baseline: Annotated[
        Path | None, typer.Option(help="Previous scan or report JSON to compare against.")
    ] = None,
    decisions: Annotated[
        Path | None, typer.Option(help="gapscan-decisions.json exported from the dashboard.")
    ] = None,
    out: Annotated[Path | None, typer.Option("--out", "-o", help="Dashboard HTML path.")] = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Also write the report data as JSON.")
    ] = None,
    project: Annotated[str | None, typer.Option(help="Project name shown in the report.")] = None,
    exports: Annotated[
        Path | None, typer.Option(help="Also write SARIF, CSV, Markdown, JSON and SBOM here.")
    ] = None,
    pdf: Annotated[
        bool,
        typer.Option("--pdf", help="Also write the PDF executive report (needs gapscan[pdf])."),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Build the interactive dashboard (one self-contained HTML file) from a scan."""
    cfg = _load(config)
    scan = ScanResult.model_validate_json(scan_file.read_text(encoding="utf-8"))
    review = None
    if triage_file is not None:
        review = TriageOutput.model_validate_json(triage_file.read_text(encoding="utf-8"))
        try:
            review.check(scan)
        except StageMismatch:
            console.print(f"[red]{triage_file} was made from a different scan than {scan_file}.[/red]"
                          " Run `gapscan triage` on this scan first.")  # fmt: skip
            raise typer.Exit(code=2) from None
    try:
        data, html = build_dashboard(
            scan,
            review,
            config=cfg,
            target=target.resolve() if target else None,
            baseline=load_previous(baseline) if baseline else None,
            decisions=load_decisions(decisions),
            project=project,
            kb=load_kb(cfg, use_embeddings=False),
        )
    except (TemplateMissing, ValueError, OSError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    out = out or Path(f"gapscan-report-{data.meta.project}-{data.meta.generated_at[:10]}.html")
    out.write_text(html, encoding="utf-8")
    if json_out:
        json_out.write_text(data.model_dump_json(indent=2), encoding="utf-8")
    if exports is not None:
        for path in write_exports(data, scan, exports, out.stem):
            console.print(f"  wrote {path}")
    if pdf:
        try:
            console.print(f"  wrote {render_pdf(out, out.with_suffix('.pdf'))}")
        except PdfUnavailable as exc:
            console.print(f"[yellow]PDF skipped: {exc}[/yellow]")
    c = data.counts
    size_kb = out.stat().st_size // 1024
    grade = f"{data.score.value:.0f}/100 (grade {data.score.grade})"
    console.print(f"Risk {grade}, {c.open} open findings of {c.total} -> {out} ({size_kb} KB)")


model_app = typer.Typer(name="model", help="Choose and compare local models.", no_args_is_help=True)
app.add_typer(model_app)


@model_app.command("list")
def model_list(config: ConfigOption = None) -> None:
    """Show the configured model, the profiles, and which models the server has installed."""
    cfg = _load(config)
    llm = cfg.llm
    console.print(
        f"Configured: [bold]{llm.model}[/bold] (profile {llm.profile!r}, backend {llm.backend})"
    )
    try:
        installed = {m["name"]: m for m in LLMClient(llm).list_models()}
    except LLMError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        installed = {}
    table = Table(title="Profiles (set llm.profile, or llm.model for any model id)")
    for col in ("profile", "model", "code budget", "installed", "note"):
        table.add_column(col)
    for name, p in llm.all_profiles.items():
        ok = p.model in installed or (":" not in p.model and f"{p.model}:latest" in installed)
        table.add_row(
            name, p.model, str(p.code_context_tokens), "yes" if ok else "no (ollama pull)", p.note
        )
    console.print(table)
    if installed:
        other = Table(title="Installed on the server")
        for col in ("model", "size GB", "params", "quant"):
            other.add_column(col)
        for m in installed.values():
            other.add_row(m["name"], str(m["size_gb"]), m["params"], m["quant"])
        console.print(other)


@model_app.command("bench")
def model_bench(
    models: Annotated[str, typer.Option("--models", "-m", help="Comma-separated model ids.")] = "",
    cases: Annotated[Path, typer.Option(help="Labeled triage cases (JSON).")] = Path(
        "eval/triage_cases.json"
    ),
    out_dir: Annotated[Path, typer.Option(help="Where result files are written.")] = Path(
        "eval/results"
    ),
    config: ConfigOption = None,
) -> None:
    """Compare models on labeled triage cases: accuracy, false alarms removed, speed, validity."""
    cfg = _load(config)
    names = [m.strip() for m in models.split(",") if m.strip()] or [cfg.llm.model]
    client = LLMClient(cfg.llm)
    labeled = load_cases(cases)
    out_dir.mkdir(parents=True, exist_ok=True)
    table = Table(title=f"Triage benchmark ({len(labeled)} cases)")
    cols = ("model", "accuracy", "TPs kept", "FPs removed", "valid 1st try", "failed", "median s")
    for col in cols:
        table.add_column(col)
    for name in names:
        console.print(f"running {name} ...")
        result = run_benchmark(client, name, labeled)
        s = result["summary"]
        stamp = datetime.now(UTC).strftime("%Y-%m-%d")
        (out_dir / f"{stamp}-{name.replace(':', '_').replace('/', '_')}.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
        table.add_row(name, f"{s['accuracy']:.0%}", f"{s['true_positives_kept']:.0%}",
                      f"{s['false_positives_removed']:.0%}", f"{s['first_try_valid_json']:.0%}",
                      str(s["failed"]), str(s["median_seconds"]))  # fmt: skip
    console.print(table)


eval_app = typer.Typer(
    name="eval",
    help="Measure GapScan against labeled fixtures and benchmark apps.",
    no_args_is_help=True,
)
app.add_typer(eval_app)
EVAL_LOCAL = Path("eval/local/targets.toml")  # private projects: gitignored
EVAL_TARGETS = Path("eval/targets.toml")
EVAL_FIXTURES = Path("eval/fixtures/labeled")


@eval_app.command("list")
def eval_list(config: ConfigOption = None) -> None:
    """Show the benchmark targets, their pinned commits and whether they are downloaded."""
    cfg = _load(config)
    table = Table(title="Evaluation targets")
    for col in ("name", "language", "license", "ground truth", "pinned commit", "downloaded"):
        table.add_column(col)
    table.add_row("fixtures", "mixed", "own", "hand-labeled (62 sites)", "in repo", "yes")
    for t in load_targets(EVAL_TARGETS).values():
        table.add_row(
            t.name,
            t.language,
            t.license,
            t.truth,
            t.sha[:12],
            "yes" if is_fetched(cfg.data.eval_dir, t) else "no",
        )
    console.print(table)


@eval_app.command("fetch")
def eval_fetch(
    names: Annotated[str, typer.Option("--targets", help="Comma-separated; default all.")] = "",
    config: ConfigOption = None,
) -> None:
    """Download the benchmark apps at their pinned commits (needs network; nothing is executed)."""
    cfg = _load(config)
    targets = load_targets(EVAL_TARGETS)
    chosen = [n.strip() for n in names.split(",") if n.strip()] or list(targets)
    for name in chosen:
        if name not in targets:
            console.print(f"[red]unknown target {name!r}[/red]")
            raise typer.Exit(code=2)
        console.print(f"fetching {name} ({targets[name].license}) ...")
        try:
            fetch_target(cfg.data.eval_dir, targets[name])
        except (RuntimeError, OSError) as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from exc
    console.print("done; downloaded data stays under data/ and is never committed or bundled.")


@eval_app.command("run")
def eval_run(
    names: Annotated[
        str,
        typer.Option(
            "--targets",
            help="Comma-separated: fixtures, benchmark-java, juice-shop, nodegoat, local "
            "(your own projects from eval/local/targets.toml).",
        ),
    ] = "fixtures,benchmark-java",
    triage: Annotated[bool, typer.Option(help="Let the model review findings (slower).")] = True,
    sample: Annotated[
        int, typer.Option(help="Benchmark review sample: cases per category and class.")
    ] = 3,
    out_dir: Annotated[Path, typer.Option("--out", help="Where result files go.")] = Path(
        "eval/results"
    ),
    memory_mode: Annotated[
        str,
        typer.Option(
            "--memories",
            help="none | leave-one-out (notes from the other labels) | poisoned (adversarial: a wrong "
            "'false alarm' note on every finding). Local targets only.",
        ),
    ] = "none",
    config: ConfigOption = None,
) -> None:
    """Run the evaluation and write eval/results/<date>-<model>.json."""
    if memory_mode not in ("none", "leave-one-out", "poisoned"):
        raise typer.BadParameter("--memories must be none, leave-one-out or poisoned")
    cfg = _load(config)
    selected = [n.strip() for n in names.split(",") if n.strip()]

    def progress(message: str) -> None:
        if not message.startswith("  "):  # per-finding lines are too chatty
            console.print(f"[dim]{message}[/dim]")

    from .evaluation.local import load_local_targets

    result = run_eval(cfg, targets_file=EVAL_TARGETS, fixtures_dir=EVAL_FIXTURES, selected=selected,
                      triage=triage, sample=sample, client=LLMClient(cfg.llm) if triage else None,
                      progress=progress,
                      local_targets=load_local_targets(EVAL_LOCAL), memory_mode=memory_mode)  # fmt: skip
    path = write_result(out_dir, result)
    table = Table(title=f"Results ({', '.join(result['meta']['models'])})")
    table.add_column("metric")
    table.add_column("value")
    for k, v in headline(result).items():
        table.add_row(
            k,
            "-"
            if v is None
            else (
                f"{v:.1%}"
                if isinstance(v, float) and v <= 1 and "seconds" not in k and "tokens" not in k
                else str(v)
            ),
        )
    console.print(table)
    for name, why in result["skipped"].items():
        console.print(f"[yellow]skipped {name}: {why}[/yellow]")
    for name, r in result["results"].items():
        checks = r.get("checks")
        if checks:
            ok = {k: v for k, v in checks.items() if k.endswith(("80", "30", "5"))}
            console.print(
                f"{name} targets: "
                + ", ".join(
                    f"{k}={'pass' if v else 'FAIL'}" for k, v in ok.items() if v is not None
                )
            )
    console.print(f"wrote {path}")


@eval_app.command("compare")
def eval_compare(
    before: Annotated[Path, typer.Argument(help="Older result file.")],
    after: Annotated[Path, typer.Argument(help="Newer result file.")],
) -> None:
    """Compare two result files (models, prompts or scanner changes) side by side."""
    a = headline(json.loads(before.read_text(encoding="utf-8")))
    b = headline(json.loads(after.read_text(encoding="utf-8")))
    table = Table(title=f"{before.name} -> {after.name}")
    for col in ("metric", "before", "after", "change"):
        table.add_column(col)
    for key in sorted(set(a) | set(b)):
        x, y = a.get(key), b.get(key)
        change = (
            f"{y - x:+.3f}" if isinstance(x, (int, float)) and isinstance(y, (int, float)) else ""
        )
        table.add_row(key, "-" if x is None else str(x), "-" if y is None else str(y), change)
    console.print(table)


memory_app = typer.Typer(name="memory", help="Team memories: notes that guide future triage.",
                         no_args_is_help=True)  # fmt: skip
app.add_typer(memory_app)


def _memories_path(config: Config) -> Path:
    return config.data.dir / "memories.json"


@memory_app.command("list")
def memory_list(file: Annotated[Path | None, typer.Option("--file")] = None,
                config: ConfigOption = None) -> None:  # fmt: skip
    """Show every memory, with the scope it applies to."""
    path = file or _memories_path(_load(config))
    memories = load_memories(path)
    table = Table(title=str(path))
    for col in ("id", "kind", "rule", "path", "cwe", "on", "text"):
        table.add_column(col)
    for m in memories:
        table.add_row(m.id, m.kind, m.rule or "any", m.path or "any", m.cwe or "any",
                      "yes" if m.enabled else "no", m.text)  # fmt: skip
    console.print(table if memories else "no memories yet")


@memory_app.command("add")
def memory_add(
    text: Annotated[str, typer.Argument(help="What a reviewer should know, in a sentence or two.")],
    kind: Annotated[str, typer.Option(help="false_positive | confirmed | accepted_risk | context.")] = "context",
    rule: Annotated[str, typer.Option(help="Rule id or its last segment; empty = any rule.")] = "",
    path: Annotated[str, typer.Option(help="Directory prefix or glob; empty = anywhere.")] = "",
    cwe: Annotated[str, typer.Option(help="e.g. CWE-22; empty = any weakness.")] = "",
    file: Annotated[Path | None, typer.Option("--file")] = None,
    config: ConfigOption = None,
) -> None:  # fmt: skip
    """Add a memory by hand."""
    target = file or _memories_path(_load(config))
    try:
        memory = Memory(text=text, kind=kind, rule=rule, path=path, cwe=cwe)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    save_memories(target, add_memory(load_memories(target), memory))
    console.print(f"added memory {memory.id} -> {target}")


@memory_app.command("rm")
def memory_rm(memory_id: Annotated[str, typer.Argument()],
              file: Annotated[Path | None, typer.Option("--file")] = None,
              config: ConfigOption = None) -> None:  # fmt: skip
    """Delete a memory by id."""
    target = file or _memories_path(_load(config))
    before = load_memories(target)
    after = remove_memory(before, memory_id)
    if len(after) == len(before):
        raise typer.BadParameter(f"no memory with id {memory_id}")
    save_memories(target, after)
    console.print(f"removed {memory_id}")


@memory_app.command("from-decisions")
def memory_from_decisions(
    scan_file: Annotated[Path, typer.Argument(help="Findings JSON written by `gapscan scan`.")],
    decisions: Annotated[Path, typer.Argument(help="gapscan-decisions.json from the dashboard.")],
    file: Annotated[Path | None, typer.Option("--file")] = None,
    config: ConfigOption = None,
) -> None:  # fmt: skip
    """Turn reviewer decisions that carry a real note into memories (decisions without one teach nothing)."""
    target = file or _memories_path(_load(config))
    data = ScanResult.model_validate_json(scan_file.read_text(encoding="utf-8"))
    by_id = {f.id: f for f in data.findings}
    memories = load_memories(target)
    added = 0
    for d in load_decisions(decisions).decisions:
        finding = by_id.get(d.finding_id)
        made = from_decision(finding, d.decision, d.note, d.by) if finding else None
        if made:
            memories = add_memory(memories, made)
            added += 1
    save_memories(target, memories)
    console.print(
        f"{added} memories from {len(load_decisions(decisions).decisions)} decisions -> {target}"
    )


@memory_app.command("export-dataset")
def memory_export_dataset(
    scan_file: Annotated[Path, typer.Argument(help="Findings JSON written by `gapscan scan`.")],
    decisions: Annotated[Path, typer.Argument(help="gapscan-decisions.json from the dashboard.")],
    target: Annotated[Path, typer.Option("--target", "-t", help="The scanned project.")] = Path(
        "."
    ),
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("gapscan-dataset"),
    config: ConfigOption = None,
) -> None:
    """Data flywheel (opt-in): export reviewer decisions as a local fine-tuning dataset
    (train + held-out). Needs `[flywheel] enabled = true`; nothing leaves this machine."""
    from .flywheel import FlywheelDisabled, export_dataset

    cfg = _load(config)
    data = ScanResult.model_validate_json(scan_file.read_text(encoding="utf-8"))
    try:
        stats = export_dataset(cfg, data, load_decisions(decisions), target, out)
    except FlywheelDisabled as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(code=1) from exc
    console.print(
        f"{stats.train} training and {stats.heldout} held-out examples "
        f"({stats.skipped} decisions skipped) -> {stats.out_dir}"
    )


data_app = typer.Typer(name="data", help="Offline data: OWASP sources and vulnerability databases.",
                       no_args_is_help=True)  # fmt: skip
app.add_typer(data_app)


def _store(config: Config) -> RawStore:
    return RawStore(config.data.dir / "owasp")


@data_app.command("fetch")
def data_fetch(config: ConfigOption = None) -> None:
    """Download OWASP Top 10:2025, ASVS 5.0.0 and OpenCRE into data/owasp/ (needs network)."""
    cfg = _load(config)
    counts = fetch_owasp(_store(cfg))
    for name, n in counts.items():
        console.print(f"{name}: {n} files")
    console.print(f"Saved raw files + manifest under {cfg.data.dir / 'owasp'}")


@data_app.command("fetch-vulns")
def data_fetch_vulns(
    java_db: Annotated[
        bool, typer.Option("--java-db", help="Also Trivy's Java DB (about 2.6 GB).")
    ] = False,
    then_watch: Annotated[
        bool,
        typer.Option(
            "--watch",
            help="Afterwards, re-check every saved project and report advisories not reported "
            "before (the zero-day check `gapscan schedule enable` runs daily).",
        ),
    ] = False,
    notify: Annotated[
        bool, typer.Option("--notify", help="With --watch: a desktop notification on new alerts.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Download the vulnerability data a scan checks dependencies against: the OSV and Trivy
    databases, CISA KEV and EPSS (needs network once; the scan itself stays offline)."""
    cfg = _load(config)
    console.print("downloading CISA KEV and EPSS ...")
    dates = fetch_enrichment(RawStore(cfg.data.dir / "enrichment"))
    console.print("downloading the OSV database (about 260 MB) ...")
    osv_date = fetch_osv_db(cfg.scanners.osv.db_dir)
    console.print("downloading the Trivy database ...")
    trivy_date = fetch_trivy_db(cfg.scanners.trivy.cache_dir, java_db=java_db)
    console.print(
        f"OSV {osv_date}, Trivy {trivy_date}, KEV {dates.get('cisa_kev', '?')}, "
        f"EPSS {dates.get('epss', '?')}. Check with `gapscan doctor`.",
        markup=False,
    )
    if then_watch:
        _run_watch(cfg, None, True, None, None, notify, False, True)


schedule_app = typer.Typer(
    name="schedule",
    help="A daily zero-day check: fresh vulnerability data, every saved project re-checked.",
    no_args_is_help=True,
)
app.add_typer(schedule_app)


@schedule_app.command("enable")
def schedule_enable(
    at: Annotated[str, typer.Option("--at", help="Time of day, HH:MM (local time).")] = "09:00",
    fetch: Annotated[
        bool,
        typer.Option(
            "--fetch/--no-fetch",
            help="Download fresh vulnerability data first (default), or only re-check against "
            "data you refresh yourself (an offline bundle on an air-gapped machine).",
        ),
    ] = True,
    config: ConfigOption = None,
) -> None:
    """Run the zero-day check every day: download the vulnerability data, re-check every project
    saved in the local manager, and notify only about advisories not reported before. Uses the
    system's scheduler (launchd on macOS, a systemd user timer on Linux); nothing stays running."""
    from . import schedule

    cfg = _load(config)
    log = (cfg.data.dir / "watch" / "schedule.log").resolve()
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        plan = schedule.plan_enable(at, fetch=fetch, log=log)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    if plan.kind in ("cron", "manual"):
        console.print(plan.note, markup=False)
        return
    problems = schedule.apply(plan)
    for p in problems:
        console.print(f"[yellow]{p}[/yellow]", markup=True)
    if problems:
        raise typer.Exit(code=1)
    what = "downloads fresh data and re-checks" if fetch else "re-checks"
    console.print(
        f"Daily at {at}: GapScan {what} every saved project and notifies you about new "
        f"advisories. Log: {log}. Turn it off with `gapscan schedule disable`.",
        markup=False,
    )


@schedule_app.command("disable")
def schedule_disable() -> None:
    """Stop the daily zero-day check."""
    from . import schedule

    plan = schedule.plan_disable()
    if schedule.is_enabled() is None:
        console.print("No daily check is scheduled.")
        return
    schedule.apply(plan, remove=True)
    console.print("The daily zero-day check is off.")


@schedule_app.command("status")
def schedule_status() -> None:
    """Show whether the daily zero-day check is on."""
    from . import schedule

    found = schedule.is_enabled()
    console.print(f"On ({found})." if found else "Off. Turn it on with `gapscan schedule enable`.",
                  markup=False)  # fmt: skip


@data_app.command("fetch-kb")
def data_fetch_kb(config: ConfigOption = None) -> None:
    """Download the knowledge-base sources (CWE, Cheat Sheets, API Top 10, GenAI Top 10, MASVS)."""
    cfg = _load(config)
    counts = fetch_kb_sources(_store(cfg), RawStore(cfg.data.dir / "mitre"))
    for name, n in counts.items():
        console.print(f"{name}: {n} files")
    console.print("Raw files + manifests saved. Next: `gapscan kb build`.")


@data_app.command("build-mappings")
def data_build_mappings(config: ConfigOption = None) -> None:
    """Rebuild the CWE -> Top 10:2025 / ASVS 5.0.0 tables from the stored raw OWASP files."""
    from .owasp.build import build

    stats = build(_store(_load(config)))
    for key, n in stats.items():
        console.print(f"{key}: {n}")
    console.print(
        "Review `git diff packages/gapscan-security/src/gapscan/owasp/mappings/` before committing."
    )


@data_app.command("list")
def data_list(config: ConfigOption = None) -> None:
    """List stored raw files with source, version and checksum."""
    m = _store(_load(config)).manifest()
    table = Table(title=f"{len(m.entries)} raw files")
    for col in ("path", "source", "version", "bytes", "sha256"):
        table.add_column(col)
    for e in m.entries:
        table.add_row(e.path, e.source, e.version, str(e.bytes), e.sha256[:12])
    console.print(table)


@data_app.command("show")
def data_show(path: Annotated[str, typer.Argument(help="Path as printed by `data list`.")],
              config: ConfigOption = None) -> None:  # fmt: skip
    """Print a stored file exactly as downloaded (raw bytes, no formatting)."""
    try:
        raw = _store(_load(config)).read_raw(path)
    except (OSError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    sys.stdout.buffer.write(raw)
    sys.stdout.flush()


@data_app.command("verify")
def data_verify(config: ConfigOption = None) -> None:
    """Check every stored file against its recorded checksum."""
    problems = _store(_load(config)).verify()
    for p in problems:
        console.print(f"[red]{p}[/red]")
    if problems:
        raise typer.Exit(code=1)
    console.print("[green]All raw files intact.[/green]")


@app.command()
def bundle(
    out: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="Bundle file (default gapscan-bundle-<date>.tar.gz)."),
    ] = None,
    refresh: Annotated[
        bool,
        typer.Option(
            help="Download fresh data first (needs network). --no-refresh packages what is local."
        ),
    ] = True,
    semgrep_rules: Annotated[
        bool,
        typer.Option(
            "--include-semgrep-community-rules",
            help="Ship the Semgrep community rules (internal use only).",
        ),
    ] = False,
    accept_rules_license: Annotated[
        bool,
        typer.Option(
            "--accept-semgrep-rules-license",
            help="Confirm you have read the Semgrep Rules License v1.0.",
        ),
    ] = False,
    java_db: Annotated[
        bool, typer.Option("--java-db", help="Include Trivy's Java DB (about 2.6 GB).")
    ] = False,
    model: Annotated[
        str | None, typer.Option(help="Ollama model to ship, e.g. qwen3-coder:30b.")
    ] = None,
    wheels: Annotated[
        bool, typer.Option("--wheels", help="Also download the Python dependencies as wheels.")
    ] = False,
    compress: Annotated[
        bool, typer.Option(help="gzip the archive (slower to build, smaller).")
    ] = True,
    rebuild_kb: Annotated[
        bool, typer.Option(help="Rebuild the knowledge base after refreshing.")
    ] = True,
    config: ConfigOption = None,
) -> None:
    """Build the offline data bundle for air-gapped machines (run on a connected machine)."""
    import tempfile

    cfg = _load(config)
    versions: dict[str, str] = {}
    try:
        if refresh:
            versions = refresh_all(
                cfg,
                java_db=java_db,
                rebuild_kb=rebuild_kb,
                progress=lambda m: console.print(f"[dim]{m}[/dim]"),
            )
        else:
            console.print(
                "[yellow]--no-refresh: packaging the data already on this machine[/yellow]"
            )
        out = out or Path(f"gapscan-bundle-{datetime.now(UTC).strftime('%Y-%m-%d')}.tar.gz")
        with tempfile.TemporaryDirectory() as tmp:
            wheels_dir = download_wheels(Path(tmp) / "wheels") if wheels else None
            manifest = build_bundle(
                cfg.data.dir, out,
                BundleOptions(include_semgrep_rules=semgrep_rules, accept_semgrep_license=accept_rules_license,
                              include_java_db=java_db, model=model, wheels_dir=wheels_dir, compress=compress, versions=versions),
            )  # fmt: skip
    except (BundleError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    size = out.stat().st_size / 1e6
    console.print(f"Bundle {out} ({size:.0f} MB, {len(manifest.files)} files)")
    console.print(f"Snapshots: {manifest.snapshots}")
    console.print(
        f"sha256 (verify out of band): {out.with_suffix(out.suffix + '.sha256').read_text().split()[0]}"
    )
    console.print("Carry it to the air-gapped machine and run: gapscan update --from <bundle>")


@app.command()
def serve(
    port: Annotated[int, typer.Option(help="Port to listen on (loopback only).")] = 8765,
    host: Annotated[
        str, typer.Option(help="Address to bind; only loopback addresses are accepted.")
    ] = "127.0.0.1",
    open_browser: Annotated[
        bool, typer.Option("--open/--no-open", help="Open the UI in your browser.")
    ] = True,
    config: ConfigOption = None,
) -> None:
    """Start the management UI: projects, scans, history, reports and settings in your browser."""
    import webbrowser

    from .server import build_server

    cfg = _load(config)
    try:
        server = build_server(cfg, host=host, port=port)
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1)):
            console.print(
                f"[red]Port {port} is already in use: GapScan (or another program) is probably "
                f"still running.[/red] Stop it (Ctrl-C in its terminal, or `lsof -ti tcp:{port} | "
                f"xargs kill` on macOS/Linux), or pick another port: `gapscan serve --port {port + 1}`."
            )
        else:
            console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print("GapScan manager running. Open this address (it contains this session's token):")
    console.print(f"  [bold]{server.url()}[/bold]")
    console.print("Only this computer can reach it. Press Ctrl-C to stop.")
    if open_browser:
        webbrowser.open(server.url())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("stopping ...")
    finally:
        server.jobs.stop()
        server.server_close()


@app.command("app")
def desktop_app(config: ConfigOption = None) -> None:
    """Open GapScan in its own window (the desktop app). Needs the desktop extra: `uv sync --group desktop`."""
    try:
        from . import desktop
    except ImportError as exc:  # pragma: no cover - depends on the install
        console.print(f"[red]The desktop window is not installed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    cfg = _load(config)
    try:
        raise typer.Exit(code=desktop.run(cfg))
    except desktop.AlreadyRunning as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(code=0) from exc
    except ImportError as exc:
        console.print(
            f"[red]pywebview is not installed ({exc}). Run: uv sync --group desktop[/red]"
        )
        raise typer.Exit(code=1) from exc


@app.command()
def update(
    source: Annotated[Path, typer.Option("--from", help="Bundle made by `gapscan bundle`.")],
    force: Annotated[
        bool, typer.Option(help="Allow replacing newer data with an older bundle.")
    ] = False,
    verify_only: Annotated[
        bool, typer.Option(help="Check the bundle's integrity and install nothing.")
    ] = False,
    no_model: Annotated[
        bool, typer.Option(help="Do not import the bundled model into Ollama.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Import a bundle on an air-gapped machine: verifies every checksum before touching installed data."""
    cfg = _load(config)
    try:
        if verify_only:
            manifest = verify_bundle(source)
            console.print(
                f"[green]Bundle intact[/green]: {len(manifest.files)} files, built {manifest.created_at}, snapshots {manifest.snapshots}"
            )
            return
        res = import_bundle(cfg.data.dir, source, force=force, install_model=not no_model)
    except (UpdateError, OSError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    for w in res.warnings:
        console.print(f"[yellow]{w}[/yellow]")
    console.print(
        f"Installed {', '.join(res.sections)} into {cfg.data.dir}; snapshots {res.manifest.snapshots}"
    )
    if res.model:
        console.print(f"Model {res.model} imported into the local Ollama store")


if __name__ == "__main__":
    app()
