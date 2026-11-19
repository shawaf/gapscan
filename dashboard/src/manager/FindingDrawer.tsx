import { useMemo, useState } from "preact/hooks";
import { api } from "./api";
import { Sev, Verdict } from "./common";
import { Icon } from "./icons";
import { useLoad } from "./useApi";
import { CodeView } from "../components/CodeView";
import { DeepDive } from "../components/DeepDive";
import { useData } from "../context";
import { DECISION_LABEL, effectiveSeverity, location, VERDICT_LABEL } from "../format";
import { decisionStore, navigate, routeStore, setDecision, useStore } from "../store";
import type { DecisionKind, VerdictKey } from "../types";

interface HistoryRow { run: number; at: string | null; status: "new" | "unchanged" | null; verdict: VerdictKey; confidence: number | null; severity: string; open: boolean; decision: string | null }

const DECISIONS: [DecisionKind, string][] = [["accepted_risk", "Accept risk"], ["false_positive", "False positive"], ["fixed", "Fixed"]];
const level = (c: number) => (c >= 0.8 ? "high" : c >= 0.5 ? "medium" : "low");

export function FindingDrawer({ id, ids }: { id: string; ids: string[] }) {
  const { data, byId } = useData();
  const decisions = useStore(decisionStore);
  const route = useStore(routeStore);
  const row = byId.get(id);
  const d = data.details[id];
  const dec = decisions[id];
  // One drawer instance per finding (keyed by the caller), so the note starts from the saved decision and
  // is never reset by an effect that could run after the reviewer has already started typing.
  const [note, setNote] = useState(() => decisions[id]?.note ?? "");
  const pid = route.project;
  const hist = useLoad<HistoryRow[]>(() => (pid ? api<HistoryRow[]>("GET", `/api/projects/${pid}/findings/${encodeURIComponent(id)}/history`) : Promise.resolve([])), [pid, id]);
  const pos = ids.indexOf(id);
  const go = (delta: number) => { const next = ids[pos + delta]; if (next) navigate("findings", next); };
  const flagged = d?.code.filter((l) => l[2]).length ?? 0;
  const lines = d?.code.filter((l) => l[0]).map((l) => l[0]) ?? [];
  const injection = (d?.policy_notes ?? []).some((p) => /prompt-injection|steer the reviewer/i.test(p));
  const toolCounts = useMemo(() => {
    const m = new Map<string, number>();
    d?.tool_calls.forEach((t) => m.set(t.tool, (m.get(t.tool) ?? 0) + 1));
    return [...m.entries()];
  }, [d]);
  const ready = note.trim().length >= 3;

  if (!row) {
    return <div class="cc-drawer" role="dialog" aria-modal="false" aria-label="Finding details"><header><h2>Finding not found</h2><button class="btn sm" onClick={() => navigate("findings")}>Close</button></header></div>;
  }
  const sev = effectiveSeverity(row);
  const cweName = row.cwe[0] ? (d?.cwe_names[row.cwe[0]] ?? "") : "";
  const hasReview = !!d?.reasoning;
  const evidenceMsgs = d?.scanner_messages.filter((m) => m.message) ?? [];

  return (
    <div class="cc-drawer fd" role="dialog" aria-modal="false" aria-label={`Finding: ${row.title}`}>
      <header>
        <span class="mono cc-note">GS-{row.id.slice(0, 4).toUpperCase()} <span style="font-family:var(--font)">Finding {pos >= 0 ? pos + 1 : "?"} of {ids.length}</span></span>
        <span style="display:flex;gap:6px;align-items:center">
          <button class="btn sm" onClick={() => go(-1)} disabled={pos <= 0} aria-label="Previous finding (k)">↑ <span class="mono">k</span></button>
          <button class="btn sm" onClick={() => go(1)} disabled={pos < 0 || pos >= ids.length - 1} aria-label="Next finding (j)">↓ <span class="mono">j</span></button>
          <span class="cc-key">Esc</span>
          <button class="btn sm" onClick={() => navigate("findings")} aria-label="Close details (Escape)"><Icon name="x" size={12} /></button>
        </span>
      </header>
      <div class="body">
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><Sev level={sev} /><h2 style="font-size:18px;line-height:26px;margin:0">{row.title}</h2></div>
        <p class="mono" style="font-size:12px;color:var(--text-2);margin:6px 0 10px">{location(row)}{d?.function ? ` · ${d.function}()` : ""}</p>
        <div class="fd-chips">
          {row.cwe[0] && <span class="chip2">{row.cwe[0]}{cweName ? ` ${cweName}` : ""}</span>}
          {row.owasp[0] && <span class="chip2">OWASP {row.owasp[0]}</span>}
          {row.asvs[0] && <span class="chip2">ASVS {row.asvs[0]}</span>}
          <span class="chip2 soft">{row.llm_only ? "AI-only, no scanner match" : `Scanner-confirmed · ${row.scanners.length} scanner${row.scanners.length === 1 ? "" : "s"}`}</span>
          {row.status && <span class="chip2 soft">{row.status === "new" ? "New since the previous run" : "Unchanged since the previous run"}</span>}
          {row.kev && <span class="chip2 bad">CISA KEV</span>}
          {row.internet_facing && <span class="chip2 soft">internet-facing</span>}
          {row.is_test_code && <span class="chip2 soft">test code</span>}
          {row.is_tooling_code && <span class="chip2 soft">dev tooling</span>}
          {row.cve.slice(0, 3).map((c) => <span class="chip2" key={c}>{c}</span>)}
        </div>
        {row.package && <p style="font-size:13px;margin:10px 0 0">Package <b>{row.package}</b> {row.version} {row.fixed_version ? <>→ fixed in <b>{row.fixed_version}</b></> : <span class="cc-note">(no fixed version known)</span>}{row.epss != null && <span class="cc-note"> · exploit probability {(row.epss * 100).toFixed(1)}%</span>}</p>}

        {injection && (
          <div class="fd-banner warn" role="status"><b><Icon name="pause" size={13} /> Possible prompt-injection attempt, held for human review</b>
            <p>This finding contains text that tries to instruct the AI reviewer. No AI verdict was produced as a final answer. The text is shown as plain text.</p>
            {d?.code.filter((l) => l[2]).slice(0, 3).map((l, i) => <pre key={i} class="mono">{`${row.file ?? ""}:${l[0]}\n${l[1]}`}</pre>)}
          </div>
        )}

        <section class="fd-decide" aria-label="Your decision">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap"><b>Your decision</b>
            <span style="display:flex;gap:6px">{DECISIONS.map(([k, label]) => <button key={k} class="btn sm" aria-pressed={dec?.decision === k} disabled={!ready && dec?.decision !== k} onClick={() => setDecision(id, k, note.trim())}>{label}</button>)}</span></div>
          <label class="cc-note" style="display:block;margin:10px 0 4px">Note, required for a decision</label>
          <input class="cc-input" value={note} onInput={(e) => setNote(e.currentTarget.value)} placeholder="Why this decision?" aria-label="Decision note" />
          <p class="cc-note" style="margin:8px 0 0">{dec ? <>Marked <b>{DECISION_LABEL[dec.decision]}</b>{dec.date ? ` on ${dec.date}` : ""}. <button class="btn ghost sm" style="padding:0" onClick={() => setDecision(id, null)}>Clear decision</button></> : "No decision yet. Decisions are stored with the project and carry across scans."}</p>
        </section>

        <div class="fd-h"><span>Code</span>{d && d.code.length > 0 && <span class="cc-note" style="text-transform:none;letter-spacing:0">Lines {lines[0]} to {lines[lines.length - 1]} · {flagged} flagged <button class="btn sm" style="margin-left:8px" onClick={() => void navigator.clipboard?.writeText(location(row))}>Copy path</button></span>}</div>
        {d && d.code.length > 0 ? <div class="fd-code"><div class="fd-file mono">{row.file}</div><CodeView lines={d.code} language={d.language} /></div> : <p class="cc-note">No source context available for this finding.</p>}

        {evidenceMsgs.length > 0 && (
          <>
            <div class="fd-h"><span>Scanner evidence</span></div>
            <div class="fd-box">
              {evidenceMsgs.map((m, i) => <div key={i} class="fd-ev"><b>{m.scanner}</b> <span class="mono cc-note">{m.rule}</span><p>{m.message}</p></div>)}
            </div>
          </>
        )}

        {hasReview && d ? (
          <section class="fd-ai" aria-label="AI review">
            <div class="fd-aih"><span style="display:flex;gap:10px;align-items:center"><b class="cap">AI review</b><span class="ai-tag">AI-generated · {d.model}</span></span><span class="cc-note">Based on the scanner evidence above</span></div>
            <p style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:10px 0"><Verdict v={row.verdict} />
              {row.confidence != null && <span class="conf" style="font-size:12px">Confidence <i style="width:80px"><b style={`width:${row.confidence * 100}%`} /></i><b>{row.confidence.toFixed(2)}</b> {level(row.confidence)}</span>}</p>
            <h4>Reasoning</h4><p>{d.reasoning}</p>
            {d.exploit_scenario && <><h4>Exploit scenario</h4><p>{d.exploit_scenario}</p></>}
            {d.fix_suggestion && <><h4>Fix suggestion</h4><p>{d.fix_suggestion}</p></>}
            {d.policy_notes.filter(() => !injection).map((p, i) => <p key={i} class="fd-banner warn" style="margin:8px 0">{p}</p>)}
            {(d.memory_notes?.length ?? 0) > 0 && <details><summary>Team memories shown to the model ({d.memory_notes.length})</summary><ul>{d.memory_notes.map((m, i) => <li key={i} class="mono" style="font-size:12px">{m}</li>)}</ul><p class="cc-note">Notes your reviewers wrote. They are context, never proof. Manage them in Settings.</p></details>}
            <div class="fd-tools">Tools used, {d.tool_calls.length} call{d.tool_calls.length === 1 ? "" : "s"}{toolCounts.map(([t, n]) => <span class="chip2 soft mono" key={t}>{t} ×{n}</span>)}<span class="cc-note" style="margin-left:auto">{d.prompt_version}</span></div>
          </section>
        ) : !injection && (
          <section class="fd-ai" aria-label="AI review"><div class="fd-aih"><b class="cap">AI review</b></div>
            <p class="cc-note" style="margin:10px 0 0">{row.verdict === "triage_failed" ? `The model's answer was invalid after retries (${VERDICT_LABEL[row.verdict]}). This needs a person.` : "This finding was not reviewed by the model. Start a run with AI review, or raise the number of findings to review."}</p></section>
        )}

        {d?.deep_dive && <section aria-label="Deep dive" style="margin-top:16px"><DeepDive dd={d.deep_dive} /></section>}

        {d && (d.callers.length > 0 || d.untrusted_sources.length > 0) && (
          <div class="fd-cols">
            <div><div class="fd-h"><span>Callers · {d.callers.length}</span></div>{d.callers.length === 0 && <p class="cc-note">None found by name.</p>}
              {d.callers.map((c, i) => <p key={i} class="mono" style="font-size:12px;margin:0 0 8px"><a href="#" onClick={(e) => e.preventDefault()}>{c.file}:{c.line}</a><br />{c.function ? `${c.function}()` : "module level"}</p>)}</div>
            <div><div class="fd-h"><span>Untrusted input sources · {d.untrusted_sources.length}</span></div>{d.untrusted_sources.length === 0 && <p class="cc-note">None detected in this function.</p>}
              {d.untrusted_sources.map((u, i) => <p key={i} style="font-size:13px;margin:0 0 8px"><b>{u.kind.replace("_", " ")}</b><br /><span class="mono" style="font-size:12px">line {u.line}: {u.text}</span></p>)}</div>
          </div>
        )}
        {d && d.references.length > 0 && <><div class="fd-h"><span>Cheat sheets, bundled offline copies</span></div><ul style="margin:0;padding-left:18px">{d.references.map((r) => <li key={r}>{r}</li>)}</ul></>}

        <div class="fd-h" style="margin-top:20px;border-top:1px solid var(--line);padding-top:16px"><span>History</span></div>
        {hist.data && hist.data.length > 0 ? hist.data.map((h) => (
          <p key={h.run} style="font-size:13px;margin:0 0 6px"><b class="mono">Run #{h.run}</b> · {h.status === "new" ? "New" : h.status === "unchanged" ? "Unchanged" : h.open ? "Open" : "Dismissed"} · {h.verdict && h.verdict !== "not_triaged" ? `AI verdict ${VERDICT_LABEL[h.verdict].toLowerCase()}${h.confidence != null ? `, ${h.confidence.toFixed(2)}` : ""}` : "not reviewed"}{h.decision ? ` · decision ${h.decision.replace("_", " ")}` : ""}</p>
        )) : <p class="cc-note">{hist.loading ? "Loading..." : "Only seen in this run so far."}</p>}
      </div>
    </div>
  );
}
