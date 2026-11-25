import { useMemo, useState } from "preact/hooks";
import { Drawer, PageHead } from "./common";
import { StatTile } from "./tiles";
import { SevGlyph } from "./icons";
import { useData } from "../context";
import { emptyCriteria } from "../filters";
import { num, SEV_LABEL, SEVERITIES } from "../format";
import { findingsUi } from "../pages/Findings";
import { navigate } from "../store";
import type { AsvsStatus, Severity } from "../types";

/** OWASP's own text carries markdown links and bold markers; show it as plain text. */
const plain = (t: string): string => t.replace(/\*\*/g, "").replace(/\[([^\]]+)\]\([^)]*\)/g, "$1").replace(/\*(\w)/g, "$1");
const worst = (by: Record<string, number>): Severity | "none" => SEVERITIES.find((s) => (by[s] ?? 0) > 0) ?? "none";

export function OwaspPage() {
  const { data } = useData();
  const edition = data.freshness.owasp["OWASP Top 10"] ?? "2025";
  const open = (id: string) => { findingsUi.set((p) => ({ ...p, criteria: { ...emptyCriteria(), owasp: id }, cursor: 0 })); navigate("findings"); };
  const total = data.owasp.reduce((n, o) => n + o.finding_ids.length, 0);
  return (
    <>
      <PageHead title={`OWASP Top 10:${edition}`} sub={`${num(total)} gaps mapped through their CWE. Click a category to see its gaps.`} />
      <div class="heat" role="list" aria-label="OWASP Top 10 categories">
        {data.owasp.map((o) => {
          const w = worst(o.by_severity);
          const n = o.finding_ids.length;
          return (
            <div key={o.id} role="listitem" style="display:flex"><button class={`tile ${w}`} style="flex:1" onClick={() => open(o.id)} aria-label={`${o.id} ${o.name}: ${n} open findings${w === "none" ? "" : `, worst severity ${SEV_LABEL[w]}`}`}>
              <span class="top"><span class="id">{o.id.split(":")[0]}</span><span class="n">{n}</span></span>
              <span class="nm">{o.name}</span>
              <span class="sv">{n === 0 ? <span>No open findings</span> : SEVERITIES.filter((s) => (o.by_severity[s] ?? 0) > 0).map((s) => <span key={s} title={SEV_LABEL[s]}><SevGlyph level={s} />{o.by_severity[s]}</span>)}</span>
            </button></div>
          );
        })}
      </div>
      <section class="cc-card" style="padding:0">
        <div class="tbl-wrap" style="border:0"><table class="tbl"><thead><tr><th>Category</th>{SEVERITIES.map((s) => <th class="num" key={s}>{SEV_LABEL[s]}</th>)}<th class="num">Open</th><th>Cheat sheets</th></tr></thead>
          <tbody>
            {data.owasp.map((o) => (
              <tr key={o.id} class="click" onClick={() => o.finding_ids.length && open(o.id)}>
                <td><b>{o.id.split(":")[0]}</b> {o.name}<span class="sub">{plain(o.description)}</span></td>
                {SEVERITIES.map((s) => <td class="num" key={s} style={o.by_severity[s] ? "" : "color:var(--text-3)"}>{o.by_severity[s] ?? 0}</td>)}
                <td class="num"><b>{o.finding_ids.length}</b></td>
                <td style="min-width:180px">{o.cheatsheets.map((c) => <a key={c.url} href={c.url} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} style="display:block">{c.title}</a>)}</td>
              </tr>
            ))}
          </tbody></table></div>
      </section>
      <p class="cc-note" style="margin-top:12px">Category names and requirement text are from OWASP (CC BY-SA 4.0).</p>
    </>
  );
}

const ASVS_LABEL: Record<AsvsStatus, string> = { evidence_of_failure: "Gap found", no_issue_found_by_tools: "No issue found", manual_review_required: "Needs a person" };

export function AsvsPage() {
  const { data } = useData();
  const a = data.asvs;
  const [filter, setFilter] = useState<AsvsStatus | "all">("all");
  const [open, setOpen] = useState("");
  const chapters = useMemo(() => {
    const m = new Map<string, { fail: number; ok: number; manual: number }>();
    for (const r of a?.requirements ?? []) {
      const c = m.get(r.chapter) ?? { fail: 0, ok: 0, manual: 0 };
      if (r.status === "evidence_of_failure") c.fail++; else if (r.status === "no_issue_found_by_tools") c.ok++; else c.manual++;
      m.set(r.chapter, c);
    }
    return [...m.entries()].sort((x, y) => y[1].fail - x[1].fail);
  }, [a]);
  if (!a) return <><PageHead title="ASVS coverage" /><div class="cc-card cc-empty"><h2>ASVS coverage was not computed for this report</h2></div></>;
  const edition = data.freshness.owasp["OWASP ASVS"] ?? "5.0.0";
  const shown = a.requirements.filter((r) => r.chapter === open && (filter === "all" || r.status === filter));
  return (
    <>
      <PageHead title="ASVS coverage" sub={`OWASP ASVS ${edition} · level ${a.level} · ${data.meta.project}`} />
      <div class="mx-tiles">
        <StatTile label="Controls in scope" value={num(a.total)} note={`${chapters.length} chapters at level ${a.level}`} />
        <StatTile dot="var(--gap, var(--sev-critical-fill))" label="Gap found" value={num(a.evidence_of_failure)} note="Evidence the control fails" />
        <StatTile dot="var(--bar-clear, var(--clear))" label="Checked, no issue" value={num(a.no_issue_found_by_tools)} note="Not proof the control is met" />
        <StatTile dot="var(--review, var(--text-3))" label="Needs a person" value={num(a.manual_review_required)} note="Tools can't decide these" />
        <StatTile label="Tool verifiable" value={a.tool_verifiable_pct.toFixed(0)} unit="%"><div class="bar2"><i style={`width:${a.tool_verifiable_pct}%`} /></div></StatTile>
      </div>
      <section class="cc-card" aria-label="Chapters">
        <p class="mx-ct"><b>Chapters</b><span>sorted by gaps</span><span class="mx-legend"><span><i class="mx-dot s-fail" />Gap</span><span><i class="mx-dot s-ok" />No issue</span><span><i class="mx-dot s-man" />Needs a person</span></span></p>
        <div class="mx-chapters">
          {chapters.map(([name, c]) => {
            const [, id, label] = /^(V\d+)\s+(.*)$/.exec(name) ?? ["", "", name];
            return (
              <button class="mx-chapter chapter-row" key={name} onClick={() => { setFilter("all"); setOpen(name); }}>
                <span class="nm"><span class="mono">{id}</span><span>{label}</span></span>
                <span class="seg3" aria-hidden="true"><i class="s-fail" style={`flex:${c.fail}`} /><i class="s-ok" style={`flex:${c.ok}`} /><i class="s-man" style={`flex:${c.manual}`} /></span>
                <span class="mx-meta"><span><b>{c.fail}</b> gaps</span><span>{c.ok} no issue</span><span>{c.manual} manual</span></span>
              </button>
            );
          })}
        </div>
      </section>
      <p class="cc-note" style="margin-top:12px">{a.note} Requirement text is from OWASP ASVS (CC BY-SA 4.0).</p>
      {open && (
        <Drawer title={open} onClose={() => setOpen("")}>
          <div class="cc-chips" role="group" aria-label="Status filter" style="margin-bottom:12px"><button class="cc-chip" aria-pressed={filter === "all"} onClick={() => setFilter("all")}>All</button>
            {(Object.keys(ASVS_LABEL) as AsvsStatus[]).map((s) => <button key={s} class="cc-chip" aria-pressed={filter === s} onClick={() => setFilter(s)}>{ASVS_LABEL[s]}</button>)}</div>
          <div class="tbl-wrap"><table class="tbl"><tbody>{shown.map((r) => (
            <tr class="req" key={r.id}><td class="mono" style="font-size:12px">{r.id.replace(/^v[\d.]+-/, "")}</td><td>{r.text}</td>
              <td><span class={`badge2 ${r.status === "evidence_of_failure" ? "bad" : r.status === "no_issue_found_by_tools" ? "ok" : ""}`}>{ASVS_LABEL[r.status]}</span>
                {r.finding_ids.slice(0, 3).map((f, i) => <a key={f} href="#" style="display:block;font-size:12px" onClick={(e) => { e.preventDefault(); navigate("findings", f); }}>gap {i + 1}</a>)}</td></tr>
          ))}</tbody></table></div>
        </Drawer>
      )}
    </>
  );
}
