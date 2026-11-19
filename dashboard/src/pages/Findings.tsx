import { useEffect, useMemo, useRef } from "preact/hooks";
import { SeverityBadge, VerdictBadge } from "../components/Badges";
import { Detail } from "../components/Detail";
import { VirtualList } from "../components/VirtualList";
import { useData } from "../context";
import { download, findingsCsv, reportFilename } from "../download";
import { emptyCriteria, filterRows, flatten, indexRows, sortRows, type Criteria, type GroupKey, type ListItem, type SortKey } from "../filters";
import { CATEGORY_LABEL, DECISION_LABEL, effectiveSeverity, location, num, pct, SEV_LABEL, SEVERITIES, VERDICT_LABEL, VERDICTS } from "../format";
import { decisionStore, exportDecisions, navigate, routeStore, Store, useStore } from "../store";
import type { Severity, VerdictKey } from "../types";

interface Ui { criteria: Criteria; sort: SortKey; dir: 1 | -1; group: GroupKey; collapsed: Set<string>; cursor: number }
export const findingsUi = new Store<Ui>({ criteria: emptyCriteria(), sort: "risk", dir: 1, group: "none", collapsed: new Set(), cursor: 0 });
const ROW = 38;

function toggle<T>(set: Set<T>, v: T): Set<T> {
  const n = new Set(set);
  if (n.has(v)) n.delete(v); else n.add(v);
  return n;
}

export function Findings() {
  const { data } = useData();
  const ui = useStore(findingsUi);
  const decisions = useStore(decisionStore);
  const route = useStore(routeStore);
  const search = useRef<HTMLInputElement>(null);
  const index = useMemo(() => indexRows(data.findings), [data]);

  const rows = useMemo(() => sortRows(filterRows(index, ui.criteria, decisions), ui.sort, ui.dir), [index, ui.criteria, ui.sort, ui.dir, decisions]);
  const items = useMemo(() => flatten(rows, ui.group, ui.collapsed), [rows, ui.group, ui.collapsed]);
  const rowItems = useMemo(() => items.filter((i): i is Extract<ListItem, { kind: "row" }> => i.kind === "row"), [items]);
  const selectedId = route.page === "findings" ? route.id : null;
  const selectedIndex = items.findIndex((i) => i.kind === "row" && i.row.id === selectedId);

  const set = (patch: Partial<Ui>) => findingsUi.set((p) => ({ ...p, ...patch }));
  const setCrit = (patch: Partial<Criteria>) => set({ criteria: { ...ui.criteria, ...patch } });
  const sortBy = (k: SortKey) => (ui.sort === k ? set({ dir: ui.dir === 1 ? -1 : 1 }) : set({ sort: k, dir: 1 }));

  // keyboard: / search, j/k move, Enter open, Escape close
  // The newest selection, read by the handler: effects re-register after paint, so an Escape pressed in
  // the first frame after opening a finding would otherwise see the previous (empty) selection.
  const selectedNow = useRef(selectedId);
  selectedNow.current = selectedId;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      const typing = el.tagName === "INPUT" || el.tagName === "SELECT" || el.tagName === "TEXTAREA";
      if (e.key === "Escape" && (selectedNow.current ?? selectedId)) { navigate("findings"); return; }
      if (typing) { if (e.key === "Escape") (el as HTMLInputElement).blur(); return; }
      if (e.key === "/") { e.preventDefault(); search.current?.focus(); return; }
      if (e.key === "j" || e.key === "k") {
        const rowsOnly = items.map((i, idx) => (i.kind === "row" ? idx : -1)).filter((i) => i >= 0);
        if (!rowsOnly.length) return;
        const cur = Math.max(0, rowsOnly.indexOf(selectedIndex >= 0 ? selectedIndex : ui.cursor));
        const next = rowsOnly[Math.max(0, Math.min(rowsOnly.length - 1, cur + (e.key === "j" ? 1 : -1)))] as number;
        set({ cursor: next });
        const it = items[next];
        if (it?.kind === "row" && selectedId) navigate("findings", it.row.id);
      }
      if (e.key === "Enter") { const it = items[selectedIndex >= 0 ? selectedIndex : ui.cursor]; if (it?.kind === "row") navigate("findings", it.row.id); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [items, selectedId, selectedIndex, ui.cursor]);

  const owaspIds = data.owasp.map((o) => o.id);
  const scanners = Object.keys(data.counts.by_scanner);
  const c = ui.criteria;
  const header = (k: SortKey, label: string) => (
    <button onClick={() => sortBy(k)} aria-label={`Sort by ${label}`}>{label}{ui.sort === k ? (ui.dir === 1 ? " ▲" : " ▼") : ""}</button>
  );

  return (
    <div>
      <h1>Findings</h1>
      <p class="muted">{num(rows.length)} of {num(data.findings.length)} findings shown. Press <kbd>/</kbd> to search, <kbd>j</kbd>/<kbd>k</kbd> to move, <kbd>Enter</kbd> to open, <kbd>Esc</kbd> to close.</p>
      <div class="filters" role="search">
        <label>Search<input ref={search} type="search" value={c.text} placeholder="title, rule, file, CWE, CVE" onInput={(e) => setCrit({ text: (e.currentTarget as HTMLInputElement).value })} /></label>
        <label>File / package<input type="text" value={c.path} onInput={(e) => setCrit({ path: (e.currentTarget as HTMLInputElement).value })} /></label>
        <label>CWE<input type="text" value={c.cwe} placeholder="e.g. 89" onInput={(e) => setCrit({ cwe: (e.currentTarget as HTMLInputElement).value })} style={{ minWidth: "80px" }} /></label>
        <label>OWASP<select value={c.owasp} onChange={(e) => setCrit({ owasp: (e.currentTarget as HTMLSelectElement).value })}><option value="">All</option>{owaspIds.map((o) => <option key={o}>{o}</option>)}</select></label>
        <label>Scanner<select value={c.scanner} onChange={(e) => setCrit({ scanner: (e.currentTarget as HTMLSelectElement).value })}><option value="">All</option>{scanners.map((o) => <option key={o}>{o}</option>)}</select></label>
        <label>Evidence<select value={c.evidence} onChange={(e) => setCrit({ evidence: (e.currentTarget as HTMLSelectElement).value as Criteria["evidence"] })}><option value="all">All</option><option value="scanner">Scanner-confirmed</option><option value="llm_only">LLM-only</option></select></label>
        <label>Min. confidence {pct(c.minConfidence * 100)}<input type="range" min="0" max="1" step="0.1" value={c.minConfidence} onInput={(e) => setCrit({ minConfidence: Number((e.currentTarget as HTMLInputElement).value) })} /></label>
        <label>Group by<select value={ui.group} onChange={(e) => set({ group: (e.currentTarget as HTMLSelectElement).value as GroupKey, collapsed: new Set() })}>{(["none", "file", "category", "owasp", "cwe", "scanner", "severity"] as GroupKey[]).map((g) => <option key={g} value={g}>{g}</option>)}</select></label>
      </div>
      <div class="filters">
        <div class="chips" role="group" aria-label="Severity">{SEVERITIES.map((s: Severity) => <button key={s} class="chip" aria-pressed={c.severities.has(s)} onClick={() => setCrit({ severities: toggle(c.severities, s) })}>{SEV_LABEL[s]}</button>)}</div>
        <div class="chips" role="group" aria-label="Verdict">{VERDICTS.map((v: VerdictKey) => <button key={v} class="chip" aria-pressed={c.verdicts.has(v)} onClick={() => setCrit({ verdicts: toggle(c.verdicts, v) })}>{VERDICT_LABEL[v]}</button>)}</div>
        <div class="chips" role="group" aria-label="Category">{Object.keys(CATEGORY_LABEL).map((k) => <button key={k} class="chip" aria-pressed={c.categories.has(k)} onClick={() => setCrit({ categories: toggle(c.categories, k) })}>{CATEGORY_LABEL[k]}</button>)}</div>
        <button class="chip" aria-pressed={c.showDismissed} onClick={() => setCrit({ showDismissed: !c.showDismissed })}>Show dismissed</button>
        <button class="btn" onClick={() => findingsUi.set({ ...ui, criteria: emptyCriteria() })}>Reset filters</button>
        <button class="btn" onClick={() => download(reportFilename(data, "csv"), findingsCsv(rows, decisions), "text/csv")}>Export CSV ({num(rows.length)})</button>
        <button class="btn" onClick={() => download("gapscan-decisions.json", exportDecisions(), "application/json")}>Export decisions ({Object.keys(decisions).length})</button>
      </div>

      <div class="vtable">
        <div class="vhead" role="row">
          {header("severity", "Severity")}{header("title", "Finding")}{header("location", "Location")}{header("verdict", "Review")}{header("confidence", "Conf.")}<span>CWE</span>{header("risk", "Risk")}
        </div>
        {items.length === 0 ? <div class="empty">No findings match these filters.</div> : (
          <VirtualList items={items} rowHeight={ROW} label="Findings" selectedIndex={selectedIndex >= 0 ? selectedIndex : ui.cursor}
            render={(item, i, top) => item.kind === "group" ? (
              <div class="vgroup" key={`g-${item.label}`} style={{ top: `${top}px` }} onClick={() => set({ collapsed: toggle(ui.collapsed, item.label) })} role="button" aria-expanded={!item.collapsed}>
                {item.collapsed ? "▸" : "▾"}&nbsp;{item.label}&nbsp;<span class="muted">({num(item.count)})</span>
              </div>
            ) : (
              <div class={`vrow${item.row.id === selectedId ? " sel" : ""}${!item.row.open || decisions[item.row.id] ? " dismissed" : ""}`} key={item.row.id} role="listitem" tabIndex={-1}
                style={{ top: `${top}px` }} data-row={i} onClick={() => { set({ cursor: i }); navigate("findings", item.row.id); }}>
                <span class="cell"><SeverityBadge severity={effectiveSeverity(item.row)} /></span>
                <span class="cell" title={item.row.title}>{item.row.title}{item.row.kev && <span class="tag kev"> KEV</span>}</span>
                <span class="cell mono" title={location(item.row)}>{location(item.row)}</span>
                <span class="cell">{decisions[item.row.id] ? <span class="badge v-false_positive">{DECISION_LABEL[decisions[item.row.id]!.decision]}</span> : <VerdictBadge verdict={item.row.verdict} />}</span>
                <span class="cell">{item.row.confidence != null ? pct(item.row.confidence * 100) : "-"}</span>
                <span class="cell mono">{item.row.cwe[0] ?? "-"}</span>
                <span class="cell" title="Points this finding adds to the risk score">{item.row.risk_points.toFixed(1)}</span>
              </div>
            )} />
        )}
      </div>
      <p class="muted">{rowItems.length ? "Rows are rendered on demand, so large reports stay fast." : ""}</p>
      {selectedId && <Detail id={selectedId} />}
    </div>
  );
}
