import { useEffect, useState } from "preact/hooks";
import { AiText, SeverityBadge, Tags, VerdictBadge } from "./Badges";
import { CodeView } from "./CodeView";
import { DeepDive } from "./DeepDive";
import { useData } from "../context";
import { DECISION_LABEL, effectiveSeverity, location, pct } from "../format";
import { decisionStore, navigate, setDecision, useStore } from "../store";
import type { DecisionKind } from "../types";

export function Detail({ id }: { id: string }) {
  const { data, byId } = useData();
  const decisions = useStore(decisionStore);
  const row = byId.get(id);
  const [note, setNote] = useState("");
  useEffect(() => setNote(decisions[id]?.note ?? ""), [id]);
  if (!row) {
    return <div class="drawer" role="dialog" aria-label="Finding details"><button class="btn close" onClick={() => navigate("findings")}>Close</button><p>Finding not found.</p></div>;
  }
  const d = data.details[id];
  const dec = decisions[id];
  const decide = (k: DecisionKind) => setDecision(id, k, note);

  return (
    <div class="drawer" role="dialog" aria-modal="false" aria-label={`Finding: ${row.title}`}>
      <button class="btn close" onClick={() => navigate("findings")} aria-label="Close details (Escape)">Close ✕</button>
      <h2>{row.title}</h2>
      <p>
        <SeverityBadge severity={effectiveSeverity(row)} />{" "}
        <VerdictBadge verdict={row.verdict} />{" "}
        {row.confidence != null && <span class="muted">model confidence {pct(row.confidence * 100)}</span>}
        {row.severity_adjusted && <span class="muted"> · scanner said {row.severity}</span>}
      </p>
      <p class="mono">{location(row)} · rule {row.rule_id}</p>
      <p>
        <Tags items={row.cwe} />
        <Tags items={row.owasp} />
        {row.kev && <Tags items={[]} kev />}
        {row.cve.length > 0 && <Tags items={row.cve} />}
        {row.internet_facing && <span class="tag">internet-facing</span>}
        {row.is_test_code && <span class="tag">test code</span>}
        {row.is_tooling_code && <span class="tag">dev tooling</span>}
        {row.status && <span class="tag">{row.status === "new" ? "new since baseline" : "still open"}</span>}
      </p>
      {row.package && (
        <p>Package <b>{row.package}</b> {row.version} {row.fixed_version ? <>→ fixed in <b>{row.fixed_version}</b></> : <span class="muted">(no fixed version known)</span>}{row.epss != null && <span class="muted"> · EPSS {pct(row.epss * 100, 1)}</span>}</p>
      )}

      <h3>Evidence from the scanners</h3>
      <p class="muted">Reported by {row.scanners.join(", ")}. LLM-only findings are labeled; this one is {row.llm_only ? "LLM-only" : "backed by scanner evidence"}.</p>
      {d?.scanner_messages.filter((m) => m.message).map((m, i) => <p key={i}><b>{m.scanner}</b> <span class="mono">{m.rule}</span><br />{m.message}</p>)}
      {d && (d.code.length > 0 || row.file) && (
        <>
          {d.function && <p class="muted">Inside <span class="mono">{d.function}()</span></p>}
          <CodeView lines={d.code} language={d.language} />
        </>
      )}
      {d && d.untrusted_sources.length > 0 && (
        <details><summary>Untrusted input sources in this function ({d.untrusted_sources.length})</summary>
          <ul>{d.untrusted_sources.map((u, i) => <li key={i}><span class="tag">{u.kind}</span> line {u.line}: <span class="mono">{u.text}</span></li>)}</ul>
        </details>
      )}
      {d && d.callers.length > 0 && (
        <details><summary>Callers found by name ({d.callers.length})</summary>
          <ul>{d.callers.map((c, i) => <li key={i} class="mono">{c.file}:{c.line}{c.function ? ` in ${c.function}()` : ""}<br /><span class="muted">{c.snippet}</span></li>)}</ul>
        </details>
      )}

      {d?.reasoning ? (
        <>
          <h3>Review</h3>
          <AiText model={d.model}>
            <p>{d.reasoning}</p>
            {d.exploit_scenario && <p><b>How it could be exploited:</b> {d.exploit_scenario}</p>}
            {d.fix_suggestion && <p><b>Suggested fix:</b> {d.fix_suggestion}</p>}
          </AiText>
          {d.policy_notes.map((p, i) => <p key={i} class="card warn">{p}</p>)}
          {(d.memory_notes?.length ?? 0) > 0 && (
            <details><summary>Team memories shown to the model ({d.memory_notes.length})</summary>
              <ul>{d.memory_notes.map((m, i) => <li key={i} class="mono">{m}</li>)}</ul>
              <p class="muted">Notes your reviewers wrote. They are context, never proof: manage them with `gapscan memory`.</p>
            </details>
          )}
          {d.references.length > 0 && <ul>{d.references.map((r) => <li key={r}>{r}</li>)}</ul>}
          {d.tool_calls.length > 0 && (
            <details><summary>How the model checked ({d.tool_calls.length} tool calls)</summary>
              <ul>{d.tool_calls.map((t, i) => <li key={i} class="mono">{t.tool}({Object.values(t.args).join(", ")}) {t.ok ? "" : "— failed"} {t.outcome ? `· ${t.outcome}` : ""}</li>)}</ul>
              <p class="muted">Prompt {d.prompt_version}</p>
            </details>
          )}
        </>
      ) : <p class="muted">This finding was not reviewed by the model.</p>}
      {d?.deep_dive && <DeepDive dd={d.deep_dive} />}

      <h3>Reviewer decision</h3>
      {dec && <p>Marked <b>{DECISION_LABEL[dec.decision]}</b>{dec.note ? `: ${dec.note}` : ""} {dec.date && <span class="muted">({dec.date})</span>}</p>}
      <div class="filters">
        <label>Note<input type="text" value={note} onInput={(e) => setNote((e.currentTarget as HTMLInputElement).value)} placeholder="why?" style={{ minWidth: "260px" }} /></label>
        {(Object.keys(DECISION_LABEL) as DecisionKind[]).map((k) => (
          <button key={k} class="btn" aria-pressed={dec?.decision === k} onClick={() => decide(k)}>{DECISION_LABEL[k]}</button>
        ))}
        {dec && <button class="btn" onClick={() => setDecision(id, null)}>Clear</button>}
      </div>
      <p class="muted">Decisions are stored in this browser. Use “Export decisions” on the findings page and pass the file to <span class="mono">gapscan report --decisions</span> so they carry over.</p>
    </div>
  );
}
