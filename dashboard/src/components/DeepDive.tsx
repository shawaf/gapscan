import { AiText } from "./Badges";
import type { DeepDive as DeepDiveData, EvidenceEffect } from "../types";

const EFFECT_LABEL: Record<EvidenceEffect, string> = { protects: "in place", undermines: "problem", missing: "missing" };
const PROTECTION_LABEL: Record<string, string> = {
  absent: "No protection", partial: "Partly protected", bypassed: "Protection bypassed", present: "Protection present",
};

/** The grounded deep-dive investigation. Every ref shown here was seen by the
 *  model in a tool result; claims it could not back were dropped in Python and are only counted. */
export function DeepDive({ dd }: { dd: DeepDiveData }) {
  if (dd.failed) {
    return (
      <>
        <h3>Deep dive</h3>
        <p class="card warn">The deep-dive investigation failed{dd.error ? `: ${dd.error}` : ""}. The review above still applies.</p>
      </>
    );
  }
  return (
    <>
      <h3>Deep dive</h3>
      <AiText label="AI investigation, refs checked" model={dd.model}>
        <p><span class="tag">{PROTECTION_LABEL[dd.protection] ?? dd.protection}</span> {dd.summary}</p>
        {dd.evidence.length > 0 && (
          <>
            <h4>Evidence</h4>
            <ul>{dd.evidence.map((e, i) => (
              <li key={i}>
                <span class={`tag effect-${e.effect}`}>{EFFECT_LABEL[e.effect]}</span> {e.claim}{" "}
                {e.ref && <span class="mono muted">{e.ref}</span>}
                {e.search && <span class="muted"> (search for “<span class="mono">{e.search}</span>” {e.search_scope ? <>in <span class="mono">{e.search_scope}</span> </> : "across the project "}found nothing)</span>}
              </li>
            ))}</ul>
          </>
        )}
        {dd.scope.length > 0 && (
          <>
            <h4>Where it applies</h4>
            <ul>{dd.scope.map((s, i) => (
              <li key={i}><span class="tag">{s.affected ? "affected" : "not affected"}</span> {s.where} <span class="mono muted">{s.ref}</span></li>
            ))}</ul>
          </>
        )}
        {dd.related.length > 0 && (
          <>
            <h4>Same root cause elsewhere ({dd.related.length})</h4>
            <ul>{dd.related.map((r, i) => <li key={i}><span class="mono">{r.ref}</span> {r.note}</li>)}</ul>
          </>
        )}
        {dd.remediation.length > 0 && (
          <>
            <h4>Fix, in order</h4>
            <ol>{dd.remediation.map((s, i) => <li key={i}>{s}</li>)}</ol>
          </>
        )}
        {dd.verification.length > 0 && (
          <>
            <h4>How to verify</h4>
            <ul>{dd.verification.map((s, i) => <li key={i}>{s}</li>)}</ul>
          </>
        )}
        {dd.target_state && <p><b>Done when:</b> {dd.target_state}</p>}
      </AiText>
      <p class="muted">
        {dd.covers > 1 && `Shared by ${dd.covers} scanner results for the same issue · `}
        {dd.tool_calls} tool calls · prompt {dd.prompt_version}
        {dd.dropped > 0 && ` · ${dd.dropped} claim${dd.dropped === 1 ? "" : "s"} removed because the tools' results did not back ${dd.dropped === 1 ? "it" : "them"}`}
      </p>
    </>
  );
}
