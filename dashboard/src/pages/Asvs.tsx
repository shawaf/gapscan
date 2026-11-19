import { useMemo, useState } from "preact/hooks";
import { useData } from "../context";
import { navigate } from "../store";
import { num, pct } from "../format";
import type { AsvsStatus } from "../types";

const LABEL: Record<AsvsStatus, string> = {
  evidence_of_failure: "Evidence of failure", no_issue_found_by_tools: "No finding for mapped CWEs", manual_review_required: "Manual review required",
};
const GLYPH: Record<AsvsStatus, string> = { evidence_of_failure: "✕", no_issue_found_by_tools: "·", manual_review_required: "?" };

export function Asvs() {
  const { data } = useData();
  const a = data.asvs;
  const [filter, setFilter] = useState<AsvsStatus | "all">("all");
  const [chapter, setChapter] = useState<string>("");
  const chapters = useMemo(() => {
    const m = new Map<string, { total: number; fail: number; ok: number; manual: number }>();
    for (const r of a?.requirements ?? []) {
      const c = m.get(r.chapter) ?? { total: 0, fail: 0, ok: 0, manual: 0 };
      c.total++;
      if (r.status === "evidence_of_failure") c.fail++; else if (r.status === "no_issue_found_by_tools") c.ok++; else c.manual++;
      m.set(r.chapter, c);
    }
    return [...m.entries()];
  }, [a]);
  if (!a) return <div class="empty">ASVS coverage was not computed for this report.</div>;
  const shown = a.requirements.filter((r) => (filter === "all" || r.status === filter) && (!chapter || r.chapter === chapter));

  return (
    <div>
      <h1>ASVS {data.freshness.owasp["OWASP ASVS"] ?? "5.0.0"} coverage, level {a.level}</h1>
      <div class="card warn" role="note">{a.note}</div>
      <div class="grid cols-3" style={{ marginTop: "14px" }}>
        <div class="card kpi"><span class="v">{pct(a.tool_verifiable_pct, 1)}</span><span class="l">of {a.total} requirements map to weakness classes that scanners report on</span></div>
        <div class="card kpi"><span class="v">{pct(a.manual_pct, 1)}</span><span class="l">need manual review ({a.manual_review_required})</span></div>
        <div class="card kpi"><span class="v">{num(a.evidence_of_failure)}</span><span class="l">requirements with evidence of failure</span></div>
      </div>
      <div class="card" style={{ marginTop: "14px" }}>
        <h2>By chapter</h2>
        <table class="t"><thead><tr><th>Chapter</th><th class="num">Requirements</th><th class="num">Evidence of failure</th><th class="num">No finding for mapped CWEs</th><th class="num">Manual review</th></tr></thead>
          <tbody>{chapters.map(([name, c]) => (
            <tr key={name}><td><button class="btn" aria-pressed={chapter === name} onClick={() => setChapter(chapter === name ? "" : name)}>{name}</button></td><td class="num">{c.total}</td><td class="num">{c.fail}</td><td class="num">{c.ok}</td><td class="num">{c.manual}</td></tr>
          ))}</tbody></table>
      </div>
      <div class="card" style={{ marginTop: "14px" }}>
        <h2>Requirements ({shown.length})</h2>
        <div class="chips" role="group" aria-label="Status filter">
          <button class="chip" aria-pressed={filter === "all"} onClick={() => setFilter("all")}>All</button>
          {(Object.keys(LABEL) as AsvsStatus[]).map((s) => <button key={s} class="chip" aria-pressed={filter === s} onClick={() => setFilter(s)}>{GLYPH[s]} {LABEL[s]}</button>)}
        </div>
        <div class="matrix" role="list" aria-label="ASVS requirements" style={{ margin: "10px 0" }}>
          {shown.map((r) => <div key={r.id} role="listitem" class={`cell-box st-${r.status}`} title={`${r.id.replace("v5.0.0-", "")} · ${LABEL[r.status]}\n${r.text}`}>{GLYPH[r.status]}</div>)}
        </div>
        <details><summary>List view</summary>
          <table class="t"><thead><tr><th>ID</th><th>Status</th><th>Requirement</th><th>Findings</th></tr></thead>
            <tbody>{shown.slice(0, 400).map((r) => (
              <tr key={r.id}><td class="mono">{r.id.replace("v5.0.0-", "")}</td><td><span class={`badge st-${r.status}`}>{GLYPH[r.status]} {LABEL[r.status]}</span></td><td>{r.text}</td>
                <td>{r.finding_ids.slice(0, 3).map((f) => <a key={f} href={`#/findings/${encodeURIComponent(f)}`} onClick={(e) => { e.preventDefault(); navigate("findings", f); }}>open </a>)}</td></tr>
            ))}</tbody></table>
        </details>
      </div>
    </div>
  );
}
