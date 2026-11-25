import type { ComponentChildren, JSX } from "preact";
import { useEffect, useLayoutEffect, useState } from "preact/hooks";
import { Icon, SevGlyph, Spinner } from "./icons";
import type { QueueRun, RunOptions, Scan } from "./api";
import { ACTIVE } from "./api";
import { clock, duration } from "./useApi";
import type { Severity, VerdictKey } from "../types";
import { SEV_LABEL, VERDICT_LABEL } from "../format";

export function Err({ text }: { text: string }) { return text ? <div class="cc-err" role="alert">{text}</div> : null; }

export function StatusBadge({ s }: { s: string }): JSX.Element {
  const map: Record<string, [string, string, JSX.Element | null]> = {
    done: ["ok", "Succeeded", <Icon name="check" size={12} />],
    failed: ["bad", "Failed", <Icon name="x" size={12} />],
    interrupted: ["bad", "Interrupted", <Icon name="x" size={12} />],
    cancelled: ["", "Cancelled", <Icon name="stop" size={11} />],
    running: ["run", "Running", <Spinner size={12} />],
    queued: ["", "Queued", <Icon name="clock" size={12} />],
  };
  const [cls, label, icon] = map[s] ?? ["", s, null];
  return <span class={`badge2 ${cls}`}>{icon}{label}</span>;
}

export function Sev({ level }: { level: Severity }): JSX.Element {
  return <span class={`sev2 ${level}`}><SevGlyph level={level} />{SEV_LABEL[level]}</span>;
}

const VERDICT_SHORT: Record<VerdictKey, string> = {
  true_positive: "Confirmed", likely_true_positive: "Likely", needs_review: "Uncertain",
  false_positive: "Likely false positive", not_triaged: "Not reviewed", triage_failed: "Review failed",
};
export function Verdict({ v }: { v: VerdictKey }): JSX.Element {
  const icon = v === "true_positive" || v === "likely_true_positive" ? <Icon name="check" size={12} />
    : v === "false_positive" ? <Icon name="x" size={12} /> : v === "needs_review" ? <Icon name="help" size={12} /> : <Icon name="pause" size={12} />;
  return <span class="vpill" title={VERDICT_LABEL[v]}>{icon}{VERDICT_SHORT[v]}</span>;
}
export const verdictShort = VERDICT_SHORT;

export function Grade({ g, n }: { g: string | null; n?: number | null }): JSX.Element {
  if (!g) return <span class="cc-note">no score yet</span>;
  return <span style="font-family:var(--mono)"><b>{n != null ? n.toFixed(0) : ""}</b> {g}</span>;
}

// ---- run pipeline -------------------------------------------------------------------------

export interface Step { id: string; label: string }
export function stepsFor(opts: RunOptions): Step[] {
  const steps: Step[] = [{ id: "scanning", label: "Scan" }, { id: "normalizing", label: "Normalize" }];
  if (opts.triage && !opts.rebuild) {
    steps.push({ id: "triaging", label: "AI review" });
    if (opts.deep_dive && (opts.deep_dive_limit ?? 0) > 0) steps.push({ id: "investigating", label: "Deep dive" });
    steps.push({ id: "summarizing", label: "Summary" });
  }
  steps.push({ id: "reporting", label: "Report" });
  return steps;
}
export function stepIndex(phase: string, steps: Step[]): number {
  const i = steps.findIndex((s) => s.id === phase);
  return i >= 0 ? i : phase === "done" ? steps.length : -1;
}

type RunLike = Pick<Scan, "status" | "phase" | "options" | "stats" | "progress_done" | "progress_total" | "error">;

export function Pipeline({ run }: { run: RunLike }): JSX.Element {
  const steps = stepsFor(run.options);
  const at = run.status === "done" ? steps.length : stepIndex(run.phase, steps);
  return (
    <ol class="pipe" style="list-style:none;padding:0" aria-label="Run steps">
      {steps.map((s, i) => {
        const failedAt = run.status === "failed" ? steps.findIndex((x) => x.id === run.stats.failed_at) : -1;
        const state = run.status === "failed" && i === (failedAt >= 0 ? failedAt : Math.max(at, 0)) ? "bad" : run.status === "failed" && failedAt >= 0 && i < failedAt ? "done" : i < at ? "done" : i === at && ACTIVE.includes(run.status) ? "now" : "wait";
        let detail = state === "wait" ? "Waiting" : state === "now" ? "Running" : state === "bad" ? "Stopped" : "Done";
        if (s.id === "scanning" && run.stats.raw != null && state === "done") detail = `Done · ${run.stats.raw} raw`;
        if (s.id === "normalizing" && run.stats.merged != null && state === "done") detail = `Done · ${run.stats.merged} unique`;
        if (s.id === "triaging" && state === "now") detail = `Running · ${run.progress_done} of ${run.progress_total}`;
        if (s.id === "triaging" && state === "done") detail = `Done · ${run.progress_total} reviewed`;
        const dd = run.stats.deep_dive;
        if (s.id === "investigating" && dd && state === "now") detail = `Running · ${dd.investigations} of ${dd.total}`;
        if (s.id === "investigating" && state === "done") detail = dd ? `Done · ${dd.investigations} issues` : "Skipped";
        return (
          <li class={`st ${state}`} key={s.id}>
            <span class="dot">{state === "done" ? <Icon name="check" size={12} /> : state === "bad" ? <Icon name="x" size={12} /> : null}</span>
            <span class="nm">{s.label}</span><span class="ds">{detail}</span>
          </li>
        );
      })}
    </ol>
  );
}

export function percent(run: Pick<QueueRun, "phase" | "progress_done" | "progress_total" | "options">): number {
  const steps = stepsFor(run.options);
  const at = Math.max(stepIndex(run.phase, steps), 0);
  const dd = (run as Partial<Pick<Scan, "stats">>).stats?.deep_dive;
  const within = run.phase === "triaging" && run.progress_total ? run.progress_done / run.progress_total
    : run.phase === "investigating" && dd?.total ? dd.investigations / dd.total : 0;
  return Math.min(99, Math.round(((at + within) / steps.length) * 100));
}

export function stepLabel(run: Pick<QueueRun, "phase" | "options" | "status">): string {
  const steps = stepsFor(run.options);
  if (run.status === "queued") return "waiting in the queue";
  const at = Math.max(stepIndex(run.phase, steps), 0);
  return `${steps[at]?.label ?? "Working"} · step ${at + 1} of ${steps.length}`;
}

export function presetLabel(o: RunOptions, kind?: string): string {
  if (kind === "dryrun") return "Dry run";
  return o.rebuild ? "Report rebuild" : o.triage ? "Full scan + AI review" : "Scanners only";
}

export function elapsed(run: { started_at: string | null; status: string }): string {
  return run.started_at ? clock(Math.round((Date.now() - Date.parse(run.started_at)) / 1000)) : "00:00";
}
export { duration };

// ---- drawer -------------------------------------------------------------------------------

export function Drawer({ title, onClose, children }: { title: ComponentChildren; onClose: () => void; children: ComponentChildren }): JSX.Element {
  useLayoutEffect(() => {  // before paint, so Escape works as soon as the drawer is visible
    const on = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, [onClose]);
  return (
    <>
      <div class="cc-drawer-bg" onClick={onClose} />
      <div class="cc-drawer" role="dialog" aria-modal="true" aria-label="Details">
        <header><h2>{title}</h2><button class="btn sm" onClick={onClose} aria-label="Close (Escape)"><Icon name="x" size={12} /> Close</button></header>
        <div class="body">{children}</div>
      </div>
    </>
  );
}

export function Segmented<T extends string>({ value, options, onChange, label, block }: { value: T; options: { id: T; label: string; disabled?: boolean }[]; onChange: (v: T) => void; label: string; block?: boolean }) {
  return (
    <div class={`cc-seg${block ? " block" : ""}`} role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} type="button" role="radio" aria-checked={value === o.id} disabled={o.disabled} onClick={() => onChange(o.id)}>{o.label}</button>
      ))}
    </div>
  );
}

/** The "scanner unavailable" notice: an empty list must never read as "clean" when a tool was missing. */
export function ScannerNotice({ scanners, names, what }: { scanners: { name: string; status: string; error: string }[]; names: string[]; what: string }): JSX.Element | null {
  const missing = scanners.filter((s) => names.includes(s.name) && s.status !== "ok");
  if (!missing.length) return null;
  const list = missing.map((s) => s.name).join(" and ");
  return (
    <div class="fd-banner grey" role="note">
      <b><Icon name="stop" size={12} /> {list} {missing.length === 1 ? "was" : "were"} unavailable in this run</b>
      <p>{what} from {list} {missing.length === 1 ? "is" : "are"} missing from this view. An empty list here does not mean it is clean. <a href="#/health" onClick={(e) => { e.preventDefault(); void import("../store").then((m) => m.navigate("health")); }}>How to fix</a></p>
    </div>
  );
}

export function PageHead({ title, sub, actions }: { title: ComponentChildren; sub?: ComponentChildren; actions?: ComponentChildren }): JSX.Element {
  return <div class="cc-h"><div><h1>{title}</h1>{sub ? <p>{sub}</p> : null}</div>{actions ? <div class="cc-actions">{actions}</div> : null}</div>;
}

export function Skeleton({ rows = 4 }: { rows?: number }): JSX.Element {
  return (
    <div class="skel" role="status" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <div class="skel-row" key={i}><i style="width:18%" /><i style={`width:${50 - i * 6}%`} /><i style="width:12%" /></div>)}
    </div>
  );
}

export function SevGlyphLabel({ level, n }: { level: Severity; n: number }): JSX.Element {
  return <span style="display:inline-flex;gap:4px;align-items:center"><SevGlyph level={level} />{n} · {SEV_LABEL[level]}</span>;
}

export function ConnectionBanner({ lastOk, onRetry }: { lastOk: number; onRetry: () => void }): JSX.Element {
  const t = new Date(lastOk).toLocaleTimeString("en-GB");
  return (
    <div class="fd-banner warn" role="alert" style="margin:0 0 16px">
      <b><Icon name="warn" size={13} /> Live updates paused</b>
      <p>The server did not answer. Showing the last known state from {t}. A scan that is running keeps going on the server. Trying again every few seconds.</p>
      <button class="btn sm" onClick={onRetry}>Retry now</button>
    </div>
  );
}

export function ConfirmDialog({ title, children, confirm, danger, onCancel, onConfirm, typed }: { title: string; children: ComponentChildren; confirm: string; danger?: boolean; onCancel: () => void; onConfirm: () => void; typed?: string }): JSX.Element {
  const [text, setText] = useState("");
  const ready = !typed || text === typed;
  return (
    <>
      <div class="cc-drawer-bg" onClick={onCancel} />
      <div class="dlg" role="alertdialog" aria-modal="true" aria-label={title}>
        <h2>{title}</h2>
        <div style="font-size:13px;color:var(--text-2);line-height:20px">{children}</div>
        {typed && <label class="cc-field" style="margin-top:12px"><span>Type the project name to confirm</span><input class="cc-input mono" autoFocus value={text} placeholder={typed} aria-label="Type the project name to confirm" onInput={(e) => setText(e.currentTarget.value)} /></label>}
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:14px">
          <button class="btn" onClick={onCancel} autoFocus={!typed}>Keep</button>
          <button class={`btn ${danger ? "warn" : "primary"}`} style={danger ? "background:var(--sev-high);color:var(--surface);border-color:var(--sev-high)" : ""} disabled={!ready} onClick={onConfirm}>{confirm}</button>
        </div>
      </div>
    </>
  );
}
