import { useMemo, useState } from "preact/hooks";
import { useData } from "../context";
import { navigate } from "../store";
import { num, pct } from "../format";
import type { AsvsStatus } from "../types";

// The gap model's main screen: every control of every standard GapScan maps to,
// with the same three honest statuses as the ASVS page. A control is never shown as "met".
const LABEL: Record<AsvsStatus, string> = {
  evidence_of_failure: "Evidence of failure", no_issue_found_by_tools: "No finding (checkable)", manual_review_required: "Manual review required",
};
const GLYPH: Record<AsvsStatus, string> = { evidence_of_failure: "✕", no_issue_found_by_tools: "·", manual_review_required: "?" };
const NOTE = "\"No finding (checkable)\" means automated evidence can speak to the control and found nothing. That is not proof the control is met. Controls nothing automated can check are listed as manual review and are never counted as passed.";

export function Coverage() {
  const { data } = useData();
  const targets = data.coverage ?? [];
  const [sel, setSel] = useState(0);
  const [filter, setFilter] = useState<AsvsStatus | "all">("all");
  const [group, setGroup] = useState("");
  const t = targets[Math.min(sel, Math.max(targets.length - 1, 0))];
  const groups = useMemo(() => {
    const m = new Map<string, { total: number; fail: number; ok: number; manual: number }>();
    for (const c of t?.controls ?? []) {
      if (!c.group) continue;
      const g = m.get(c.group) ?? { total: 0, fail: 0, ok: 0, manual: 0 };
      g.total++;
      if (c.status === "evidence_of_failure") g.fail++; else if (c.status === "no_issue_found_by_tools") g.ok++; else g.manual++;
      m.set(c.group, g);
    }
    return [...m.entries()];
  }, [t]);
  if (!t) return <div class="empty">Coverage per standard was not computed for this report.</div>;
  const shown = t.controls.filter((c) => (filter === "all" || c.status === filter) && (!group || c.group === group));
  const pick = (i: number) => { setSel(i); setGroup(""); setFilter("all"); };

  return (
    <div>
      <h1>Coverage by standard</h1>
      <div class="chips" role="tablist" aria-label="Standard">
        {targets.map((x, i) => (
          <button key={x.target} role="tab" class="chip" aria-selected={i === sel} aria-pressed={i === sel} onClick={() => pick(i)}>
            {x.name} {x.version}{x.evidence_of_failure ? ` · ${x.evidence_of_failure} failing` : ""}
          </button>
        ))}
      </div>
      <div class="card warn" role="note" style={{ marginTop: "14px" }}>{NOTE}</div>
      <div class="grid cols-3" style={{ marginTop: "14px" }}>
        <div class="card kpi"><span class="v">{num(t.evidence_of_failure)}</span><span class="l">of {t.total} controls{t.level ? ` (level ${t.level})` : ""} with evidence of failure</span></div>
        <div class="card kpi"><span class="v">{pct(t.tool_verifiable_pct, 1)}</span><span class="l">can be checked by automated evidence</span></div>
        <div class="card kpi"><span class="v">{num(t.manual_review_required)}</span><span class="l">need manual review (never counted as passed)</span></div>
      </div>
      {groups.length > 0 && (
        <div class="card" style={{ marginTop: "14px" }}>
          <h2>By group</h2>
          <table class="t"><thead><tr><th>Group</th><th class="num">Controls</th><th class="num">Evidence of failure</th><th class="num">No finding (checkable)</th><th class="num">Manual review</th></tr></thead>
            <tbody>{groups.map(([name, g]) => (
              <tr key={name}><td><button class="btn" aria-pressed={group === name} onClick={() => setGroup(group === name ? "" : name)}>{name}</button></td><td class="num">{g.total}</td><td class="num">{g.fail}</td><td class="num">{g.ok}</td><td class="num">{g.manual}</td></tr>
            ))}</tbody></table>
        </div>
      )}
      <div class="card" style={{ marginTop: "14px" }}>
        <h2>Controls ({shown.length})</h2>
        <div class="chips" role="group" aria-label="Status filter">
          <button class="chip" aria-pressed={filter === "all"} onClick={() => setFilter("all")}>All</button>
          {(Object.keys(LABEL) as AsvsStatus[]).map((s) => <button key={s} class="chip" aria-pressed={filter === s} onClick={() => setFilter(s)}>{GLYPH[s]} {LABEL[s]}</button>)}
        </div>
        <table class="t" style={{ marginTop: "10px" }}><thead><tr><th>Control</th><th>Status</th><th>Title</th><th>Gaps</th></tr></thead>
          <tbody>{shown.slice(0, 500).map((c) => (
            <tr key={c.id}><td class="mono">{c.id}</td><td><span class={`badge st-${c.status}`}>{GLYPH[c.status]} {LABEL[c.status]}</span></td><td>{c.title}</td>
              <td>{c.finding_ids.length ? <>
                {c.finding_ids.slice(0, 3).map((f) => <a key={f} href={`#/findings/${encodeURIComponent(f)}`} onClick={(e) => { e.preventDefault(); navigate("findings", f); }}>open </a>)}
                {c.finding_ids.length > 3 ? `+${c.finding_ids.length - 3}` : ""}</> : ""}</td></tr>
          ))}</tbody></table>
      </div>
    </div>
  );
}
