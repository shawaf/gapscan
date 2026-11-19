import { Fragment } from "preact";
import { useMemo, useState } from "preact/hooks";
import { PageHead } from "./common";
import { Icon, SevGlyph } from "./icons";
import { useData } from "../context";
import { emptyCriteria } from "../filters";
import { num, pct, SEV_LABEL, SEVERITIES } from "../format";
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
      <PageHead title={`OWASP Top 10:${edition}`} sub={<>Every finding is mapped through its CWE to the {edition} categories using OWASP's published CWE lists. Dependencies count under A03, software supply chain. Findings without a mapped CWE are not forced into a category.</>} />
      <p class="cc-note" style="margin:0 0 10px">Heat view: each tile shows the open findings in a category and takes its color from the worst severity inside it. Click a tile to open those findings. {num(total)} findings are mapped in all.</p>
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

const ASVS_LABEL: Record<AsvsStatus, string> = { evidence_of_failure: "Evidence of failure", no_issue_found_by_tools: "No finding for mapped CWEs", manual_review_required: "Manual review required" };

export function AsvsPage() {
  const { data } = useData();
  const a = data.asvs;
  const [filter, setFilter] = useState<AsvsStatus | "all">("all");
  const [openChapter, setOpenChapter] = useState("");
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
  if (!a) return <><PageHead title="ASVS coverage" /><div class="cc-card cc-empty"><h2>ASVS coverage was not computed for this report</h2></div></>;
  const edition = data.freshness.owasp["OWASP ASVS"] ?? "5.0.0";
  const inChapter = (name: string) => a.requirements.filter((r) => r.chapter === name && (filter === "all" || r.status === filter));
  return (
    <>
      <PageHead title={`ASVS ${edition} coverage, level ${a.level}`} sub="The chapter matrix shows, per chapter, which requirements have evidence of failure, which have no finding for their mapped weaknesses, and which only a person can judge." />
      <div class="fd-banner warn" role="note" style="margin-top:0"><b><Icon name="warn" size={13} /> Read this before using the numbers</b><p>{a.note}</p></div>
      <div class="state3">
        <div><span class="v">{num(a.evidence_of_failure)}</span><span class="l"><Icon name="x" size={14} /> {ASVS_LABEL.evidence_of_failure}</span><div class="seg3" style="margin-top:8px"><i class="s-fail" style={`flex:${a.evidence_of_failure || 0.0001}`} /><i style={`flex:${a.total - a.evidence_of_failure};background:var(--sunken)`} /></div></div>
        <div><span class="v">{pct(a.tool_verifiable_pct, 1)}</span><span class="l"><Icon name="check" size={14} /> of {a.total} map to weakness classes scanners report on ({num(a.no_issue_found_by_tools)} with no finding)</span><div class="seg3" style="margin-top:8px"><i class="s-ok" style={`flex:${a.tool_verifiable_pct}`} /><i style={`flex:${100 - a.tool_verifiable_pct};background:var(--sunken)`} /></div></div>
        <div><span class="v">{pct(a.manual_pct, 1)}</span><span class="l"><Icon name="help" size={14} /> need manual review ({num(a.manual_review_required)})</span><div class="seg3" style="margin-top:8px"><i class="s-man" style={`flex:${a.manual_pct}`} /><i style={`flex:${100 - a.manual_pct};background:var(--sunken)`} /></div></div>
      </div>
      <section class="cc-card" style="padding:0;margin-bottom:16px" aria-label="Chapter matrix">
        <div style="padding:16px 16px 8px;display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center"><h2 style="margin:0">Chapter matrix</h2>
          <div class="cc-chips" role="group" aria-label="Status filter"><button class="cc-chip" aria-pressed={filter === "all"} onClick={() => setFilter("all")}>All</button>
            {(Object.keys(ASVS_LABEL) as AsvsStatus[]).map((s) => <button key={s} class="cc-chip" aria-pressed={filter === s} onClick={() => setFilter(s)}>{ASVS_LABEL[s]}</button>)}</div></div>
        <div class="tbl-wrap" style="border:0;border-top:1px solid var(--line);border-radius:0 0 8px 8px">
          <table class="tbl"><thead><tr><th>Chapter</th><th class="num">Requirements</th><th>States</th><th class="num">Failure</th><th class="num">No finding</th><th class="num">Manual</th></tr></thead>
            <tbody>
              {chapters.map(([name, c]) => (
                <Fragment key={name}>
                  <tr class="chapter-row click" onClick={() => setOpenChapter(openChapter === name ? "" : name)} aria-expanded={openChapter === name}>
                    <td><b>{openChapter === name ? "▾" : "▸"} {name}</b></td><td class="num">{c.total}</td>
                    <td><div class="seg3" role="img" aria-label={`${c.fail} failure, ${c.ok} no finding, ${c.manual} manual`}><i class="s-fail" style={`flex:${c.fail}`} /><i class="s-ok" style={`flex:${c.ok}`} /><i class="s-man" style={`flex:${c.manual}`} /></div></td>
                    <td class="num" style={c.fail ? "color:var(--sev-high);font-weight:700" : "color:var(--text-3)"}>{c.fail}</td><td class="num">{c.ok}</td><td class="num">{c.manual}</td>
                  </tr>
                  {openChapter === name && inChapter(name).map((r) => (
                    <tr class="req" key={r.id}>
                      <td class="mono" style="font-size:12px">{r.id.replace(/^v[\d.]+-/, "")}</td>
                      <td colSpan={2}>{r.text}</td>
                      <td colSpan={3}><span class={`badge2 ${r.status === "evidence_of_failure" ? "bad" : r.status === "no_issue_found_by_tools" ? "ok" : ""}`}>{ASVS_LABEL[r.status]}</span>
                        {r.finding_ids.slice(0, 3).map((f, i) => <a key={f} href="#" style="margin-left:8px;font-size:12px" onClick={(e) => { e.preventDefault(); navigate("findings", f); }}>finding {i + 1}</a>)}</td>
                    </tr>
                  ))}
                </Fragment>
              ))}
            </tbody></table></div>
      </section>
      <p class="cc-note">Requirement text is from OWASP ASVS (CC BY-SA 4.0). A requirement with no finding is not shown as met: only the weakness classes the scanners report on were checked.</p>
    </>
  );
}
