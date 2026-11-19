import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { VirtualList } from "../components/VirtualList";
import { useData } from "../context";
import { download, findingsCsv, reportFilename } from "../download";
import { emptyCriteria, filterRows, flatten, indexRows, sortRows, type Criteria, type SortKey } from "../filters";
import { CATEGORY_LABEL, DECISION_LABEL, effectiveSeverity, location, num, SEV_LABEL, SEVERITIES, VERDICT_LABEL, VERDICTS } from "../format";
import { findingsUi } from "../pages/Findings";
import { decisionStore, navigate, routeStore, setDecision, useStore } from "../store";
import type { DecisionKind, FindingRow, Severity, VerdictKey } from "../types";
import { Sev, Verdict } from "./common";
import { CheckList, Dropdown, PickList } from "./Dropdown";
import { FindingDrawer } from "./FindingDrawer";
import { Icon } from "./icons";

const ROW = 44;
type ColKey = "source" | "owasp" | "cwe" | "since" | "confidence";
const ALL_COLS: { id: ColKey; label: string }[] = [
  { id: "confidence", label: "Confidence" }, { id: "source", label: "Source" }, { id: "owasp", label: "OWASP" },
  { id: "cwe", label: "CWE" }, { id: "since", label: "Since previous run" },
];

interface SavedView { id: string; label: string; criteria: SerializedCriteria }
type SerializedCriteria = Omit<Criteria, "severities" | "verdicts" | "categories"> & { severities: Severity[]; verdicts: VerdictKey[]; categories: string[] };
const serialize = (c: Criteria): SerializedCriteria => ({ ...c, severities: [...c.severities], verdicts: [...c.verdicts], categories: [...c.categories] });
const revive = (c: SerializedCriteria): Criteria => ({ ...emptyCriteria(), ...c, severities: new Set(c.severities), verdicts: new Set(c.verdicts), categories: new Set(c.categories) });
const same = (a: Criteria, b: Criteria) => JSON.stringify(serialize(a)) === JSON.stringify(serialize(b));

function readViews(): SavedView[] { try { return JSON.parse(localStorage.getItem("gapscan.views") ?? "[]") as SavedView[]; } catch { return []; } }
function writeViews(v: SavedView[]): void { try { localStorage.setItem("gapscan.views", JSON.stringify(v)); } catch { /* ignore */ } }

const BUILTIN: { id: string; label: string; make: () => Criteria }[] = [
  { id: "all", label: "All open", make: emptyCriteria },
  { id: "new", label: "New since previous run", make: () => ({ ...emptyCriteria(), since: "new" }) },
  { id: "review", label: "Needs my review", make: () => ({ ...emptyCriteria(), verdicts: new Set<VerdictKey>(["needs_review", "triage_failed"]) }) },
  { id: "crit", label: "Critical and High", make: () => ({ ...emptyCriteria(), severities: new Set<Severity>(["critical", "high"]) }) },
  { id: "ai", label: "AI-only", make: () => ({ ...emptyCriteria(), evidence: "llm_only" }) },
];

export function FindingsExplorer() {
  const { data } = useData();
  const ui = useStore(findingsUi);
  const decisions = useStore(decisionStore);
  const route = useStore(routeStore);
  const search = useRef<HTMLInputElement>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [cols, setCols] = useState<Set<ColKey>>(new Set(ALL_COLS.map((c) => c.id)));
  const [views, setViews] = useState<SavedView[]>(readViews);
  const [bulk, setBulk] = useState<DecisionKind | null>(null);
  const [naming, setNaming] = useState(false);

  const index = useMemo(() => indexRows(data.findings), [data]);
  const c = ui.criteria;
  const setCrit = (patch: Partial<Criteria>) => findingsUi.set((p) => ({ ...p, criteria: { ...p.criteria, ...patch }, cursor: 0 }));
  const rows = useMemo(() => sortRows(filterRows(index, c, decisions), ui.sort, ui.dir), [index, c, ui.sort, ui.dir, decisions]);
  const items = useMemo(() => flatten(rows, ui.group, ui.collapsed), [rows, ui.group, ui.collapsed]);
  const rowIdx = useMemo(() => items.map((it, i) => (it.kind === "row" ? i : -1)).filter((i) => i >= 0), [items]);
  const selectedId = route.page === "findings" ? route.id : null;
  const selectedIndex = items.findIndex((i) => i.kind === "row" && i.row.id === selectedId);
  const counts = useMemo(() => Object.fromEntries(BUILTIN.map((v) => [v.id, filterRows(index, v.make(), decisions).length])), [index, decisions]);
  const owaspIds = data.owasp.map((o) => o.id);
  const scanners = Object.keys(data.counts.by_scanner);
  const cweList = useMemo(() => [...new Set(data.findings.flatMap((f) => f.cwe))].sort((a, b) => Number(a.slice(4)) - Number(b.slice(4))), [data]);

  // keyboard: / search, j/k move, Enter open, x select, Esc close. Reads the latest state through a ref
  // because effects re-register after paint (an early key press must not see stale values).
  const live = useRef({ items, rowIdx, cursor: ui.cursor, selectedId, selected });
  live.current = { items, rowIdx, cursor: ui.cursor, selectedId, selected };
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      const typing = el.tagName === "INPUT" || el.tagName === "SELECT" || el.tagName === "TEXTAREA";
      const s = live.current;
      if (e.key === "Escape" && s.selectedId) { navigate("findings"); return; }
      if (typing) { if (e.key === "Escape") (el as HTMLInputElement).blur(); return; }
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "/") { e.preventDefault(); search.current?.focus(); return; }
      const pos = Math.max(0, s.rowIdx.indexOf(s.cursor));
      if (e.key === "j" || e.key === "k") {
        const next = s.rowIdx[Math.max(0, Math.min(s.rowIdx.length - 1, pos + (e.key === "j" ? 1 : -1)))];
        if (next == null) return;
        findingsUi.set((p) => ({ ...p, cursor: next }));
        const it = s.items[next];
        if (it?.kind === "row" && s.selectedId) navigate("findings", it.row.id);
      }
      if (e.key === "Enter") { const it = s.items[s.cursor]; if (it?.kind === "row") navigate("findings", it.row.id); }
      if (e.key === "x") {
        const it = s.items[s.cursor];
        if (it?.kind === "row") { const n = new Set(s.selected); if (n.has(it.row.id)) n.delete(it.row.id); else n.add(it.row.id); setSelected(n); }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const allViews = [...BUILTIN.map((v) => ({ id: v.id, label: v.label, criteria: v.make(), saved: false })), ...views.map((v) => ({ id: v.id, label: v.label, criteria: revive(v.criteria), saved: true }))];
  const activeView = allViews.find((v) => same(v.criteria, c))?.id;
  const sortBy = (k: SortKey) => findingsUi.set((p) => (p.sort === k ? { ...p, dir: p.dir === 1 ? -1 : 1 } : { ...p, sort: k, dir: 1 }));
  const arrow = (k: SortKey) => (ui.sort === k ? (ui.dir === 1 ? " ↓" : " ↑") : "");
  const visibleRows = items.flatMap((i) => (i.kind === "row" ? [i.row] : []));
  const allSelected = visibleRows.length > 0 && visibleRows.every((r) => selected.has(r.id));
  const someSelected = selected.size > 0 && !allSelected;

  // active filter chips
  const chips: { key: string; label: string; clear: () => void }[] = [];
  if (c.showDismissed) chips.push({ key: "state", label: "State: Open and dismissed", clear: () => setCrit({ showDismissed: false }) });
  else chips.push({ key: "state", label: "State: Open", clear: () => setCrit({ showDismissed: true }) });
  c.severities.forEach((s) => chips.push({ key: `sev-${s}`, label: `Severity: ${SEV_LABEL[s]}`, clear: () => { const n = new Set(c.severities); n.delete(s); setCrit({ severities: n }); } }));
  c.categories.forEach((x) => chips.push({ key: `cat-${x}`, label: `Category: ${CATEGORY_LABEL[x] ?? x}`, clear: () => { const n = new Set(c.categories); n.delete(x); setCrit({ categories: n }); } }));
  c.verdicts.forEach((v) => chips.push({ key: `v-${v}`, label: `Verdict: ${VERDICT_LABEL[v]}`, clear: () => { const n = new Set(c.verdicts); n.delete(v); setCrit({ verdicts: n }); } }));
  if (c.owasp) chips.push({ key: "owasp", label: `OWASP: ${c.owasp}`, clear: () => setCrit({ owasp: "" }) });
  if (c.cwe) chips.push({ key: "cwe", label: `CWE: ${c.cwe}`, clear: () => setCrit({ cwe: "" }) });
  if (c.scanner) chips.push({ key: "scanner", label: `Scanner: ${c.scanner}`, clear: () => setCrit({ scanner: "" }) });
  if (c.path) chips.push({ key: "path", label: `Path: ${c.path}`, clear: () => setCrit({ path: "" }) });
  if (c.minConfidence > 0) chips.push({ key: "conf", label: `Confidence ≥ ${c.minConfidence.toFixed(2)}`, clear: () => setCrit({ minConfidence: 0 }) });
  if (c.evidence !== "all") chips.push({ key: "ev", label: c.evidence === "llm_only" ? "Source: AI-only" : "Source: Scanner-confirmed", clear: () => setCrit({ evidence: "all" }) });
  if (c.since !== "all") chips.push({ key: "since", label: c.since === "new" ? "New since previous run" : "Unchanged", clear: () => setCrit({ since: "all" }) });

  const applyBulk = (note: string) => {
    if (!bulk) return;
    selected.forEach((id) => setDecision(id, bulk, note));
    setSelected(new Set()); setBulk(null);
  };
  const toggleRow = (id: string) => { const n = new Set(selected); if (n.has(id)) n.delete(id); else n.add(id); setSelected(n); };
  const grid = (cls: string) => `fx-grid ${cls}`;
  const tableHeight = Math.min(760, Math.max(320, (typeof window === "undefined" ? 800 : window.innerHeight) - 440));
  const first = (r: FindingRow) => r.owasp[0]?.split(":")[0] ?? "-";

  return (
    <>
      <div class="cc-h">
        <div><h1>Gaps</h1><p>{num(data.counts.open)} open · each one links to its evidence and the controls it fails · {data.baseline ? `${data.baseline.new} new since the previous run · ` : ""}decisions carry across scans</p></div>
        <div class="cc-actions">
          <Dropdown label="Columns">
            <CheckList options={ALL_COLS.map((x) => ({ id: x.id, label: x.label }))} value={cols} onChange={setCols} />
          </Dropdown>
          <button class="btn" onClick={() => download(reportFilename(data, "csv"), findingsCsv(rows, decisions), "text/csv")}>Export this view</button>
        </div>
      </div>

      <div class="fx-tabs" role="tablist" aria-label="Saved views">
        {allViews.map((v) => (
          <button key={v.id} role="tab" class="tab" aria-selected={activeView === v.id} onClick={() => findingsUi.set((p) => ({ ...p, criteria: revive(serialize(v.criteria)), cursor: 0 }))}>
            {v.label}{!v.saved && <span class="n">{counts[v.id]}</span>}
            {v.saved && <span class="n" role="button" aria-label={`Delete view ${v.label}`} onClick={(e) => { e.stopPropagation(); const next = views.filter((x) => x.id !== v.id); setViews(next); writeViews(next); }}>×</span>}
          </button>
        ))}
        <span style="margin-left:auto"><button class="btn ghost sm" onClick={() => setNaming(true)}>Save current view</button></span>
      </div>

      <div class="fx-filters">
        <div class="fx-row">
          <label class="fx-search"><Icon name="search" /><input ref={search} type="search" value={c.text} placeholder="Search title, file, rule or CWE" aria-label="Search findings" onInput={(e) => setCrit({ text: e.currentTarget.value })} /><span class="cc-key">/</span></label>
          <Dropdown label="Severity" active={c.severities.size}><CheckList options={SEVERITIES.map((s) => ({ id: s, label: <Sev level={s} /> }))} value={c.severities} onChange={(severities) => setCrit({ severities })} /></Dropdown>
          <Dropdown label="Category" active={c.categories.size}><CheckList options={Object.entries(CATEGORY_LABEL).map(([id, label]) => ({ id, label }))} value={c.categories} onChange={(categories) => setCrit({ categories })} /></Dropdown>
          <Dropdown label="Verdict" active={c.verdicts.size}><CheckList options={VERDICTS.map((v) => ({ id: v, label: VERDICT_LABEL[v] }))} value={c.verdicts} onChange={(verdicts) => setCrit({ verdicts })} /></Dropdown>
          <Dropdown label="OWASP" active={c.owasp}><PickList options={owaspIds} value={c.owasp} onChange={(owasp) => setCrit({ owasp })} empty="Any category" /></Dropdown>
          <Dropdown label="CWE" active={c.cwe}><PickList options={cweList} value={c.cwe} onChange={(cwe) => setCrit({ cwe })} empty="Any weakness" /></Dropdown>
          <Dropdown label="Scanner" active={c.scanner}><PickList options={scanners} value={c.scanner} onChange={(scanner) => setCrit({ scanner })} empty="Any scanner" /></Dropdown>
          <Dropdown label="File path" active={c.path} wide><input class="cc-input mono" value={c.path} placeholder="api/ or app.py" aria-label="File path contains" onInput={(e) => setCrit({ path: e.currentTarget.value })} /></Dropdown>
          <Dropdown label="Confidence" active={c.minConfidence > 0 ? c.minConfidence.toFixed(2) : ""} wide>
            <label style="font-size:13px;display:block">Minimum model confidence: <b class="mono">{c.minConfidence.toFixed(2)}</b>
              <input type="range" min={0} max={1} step={0.05} value={c.minConfidence} style="width:100%;accent-color:var(--accent)" onInput={(e) => setCrit({ minConfidence: Number(e.currentTarget.value) })} /></label>
          </Dropdown>
          <Dropdown label="New or unchanged" active={c.since === "all" ? "" : 1}>
            <div class="dd-list">{(["all", "new", "unchanged"] as const).map((k) => <label key={k}><input type="radio" checked={c.since === k} onChange={() => setCrit({ since: k })} />{{ all: "Both", new: "New since the previous run", unchanged: "Unchanged" }[k]}</label>)}</div>
          </Dropdown>
          <Dropdown label="Source" active={c.evidence === "all" ? "" : 1}>
            <div class="dd-list">{(["all", "scanner", "llm_only"] as const).map((k) => <label key={k}><input type="radio" checked={c.evidence === k} onChange={() => setCrit({ evidence: k })} />{{ all: "Any source", scanner: "Scanner-confirmed", llm_only: "AI-only, no scanner match" }[k]}</label>)}</div>
          </Dropdown>
        </div>
        <div class="fx-row" style="justify-content:space-between">
          <span class="fx-row" style="margin:0"><span class="cc-note">Active</span>
            {chips.map((x) => <span class="fx-chip" key={x.key}>{x.label}<button aria-label={`Remove filter ${x.label}`} onClick={x.clear}><Icon name="x" size={10} /></button></span>)}
            <button class="btn ghost sm" onClick={() => findingsUi.set((p) => ({ ...p, criteria: emptyCriteria(), cursor: 0 }))}>Clear all</button></span>
          <span class="fx-row" style="margin:0;font-size:13px">
            <label>Group by <select class="cc-select" style="width:auto" value={ui.group} onChange={(e) => findingsUi.set((p) => ({ ...p, group: e.currentTarget.value as typeof ui.group }))}>
              {["none", "file", "category", "owasp", "cwe", "scanner", "severity"].map((g) => <option key={g} value={g}>{g === "none" ? "None" : g[0]?.toUpperCase() + g.slice(1)}</option>)}</select></label>
            <label>Sort <select class="cc-select" style="width:auto" value={ui.sort} onChange={(e) => sortBy(e.currentTarget.value as SortKey)}>
              <option value="risk">Risk</option><option value="severity">Severity</option><option value="verdict">Verdict</option><option value="confidence">Confidence</option><option value="title">Title</option><option value="location">Location</option></select></label>
          </span>
        </div>
      </div>

      {selected.size > 0 && (
        <div class="fx-bulk" role="region" aria-label="Bulk decisions">
          <b>{selected.size} selected</b>
          {(Object.keys(DECISION_LABEL) as DecisionKind[]).map((k) => <button key={k} class="btn sm" onClick={() => setBulk(k)}>Mark {DECISION_LABEL[k].toLowerCase()}</button>)}
          <span class="cc-note" style="flex:1">Each asks for a note. The decision is kept for later scans.</span>
          <button class="btn ghost sm" onClick={() => setSelected(new Set())}>Clear selection</button>
        </div>
      )}

      <div class="fx-table">
        <div class={grid("fx-head")} role="row">
          <span><input type="checkbox" aria-label="Select all visible rows" checked={allSelected} ref={(el) => { if (el) el.indeterminate = someSelected; }} onChange={() => setSelected(allSelected ? new Set() : new Set(visibleRows.map((r) => r.id)))} style="accent-color:var(--accent)" /></span>
          <button onClick={() => sortBy("severity")} aria-label="Sort by severity">Severity{arrow("severity")}</button>
          <button onClick={() => sortBy("title")}>Finding{arrow("title")}</button>
          <button onClick={() => sortBy("verdict")}>AI verdict{arrow("verdict")}</button>
          <span>{cols.has("confidence") ? <button onClick={() => sortBy("confidence")}>Confidence{arrow("confidence")}</button> : ""}</span>
          <span>{cols.has("source") ? "Source" : ""}</span><span>{cols.has("owasp") ? "OWASP" : ""}</span><span>{cols.has("cwe") ? "CWE" : ""}</span><span>{cols.has("since") ? "Since previous" : ""}</span>
        </div>
        {items.length === 0 ? (
          <div class="cc-empty" style="border:1px dashed var(--line-strong);border-radius:8px;margin:16px"><h2>No findings match these filters</h2><p>{chips.length - 1} filter{chips.length - 1 === 1 ? " is" : "s are"} active. {num(data.counts.open)} findings are open in this run.</p><button class="btn" onClick={() => findingsUi.set((p) => ({ ...p, criteria: emptyCriteria(), cursor: 0 }))}>Clear all filters</button></div>
        ) : (
          <VirtualList items={items} rowHeight={ROW} height={tableHeight} selectedIndex={selectedIndex >= 0 ? selectedIndex : ui.cursor} label="Findings"
            render={(item, i, top) => {
              if (item.kind === "group") {
                return <div key={`g-${item.label}`} role="listitem" class={`${grid("fx-item")}`} style={{ top: `${top}px`, fontWeight: 700, background: "var(--sunken)" }}
                  onClick={() => findingsUi.set((p) => { const n = new Set(p.collapsed); if (n.has(item.label)) n.delete(item.label); else n.add(item.label); return { ...p, collapsed: n }; })}>
                  <span /><span style="grid-column: 2 / -1">{item.collapsed ? "▸" : "▾"} {item.label} · {item.count}</span></div>;
              }
              const r = item.row;
              const gone = !r.open || !!decisions[r.id];
              return (
                <div key={r.id} role="listitem" data-row={i} class={`${grid("fx-item")}${selected.has(r.id) ? " sel" : ""}${ui.cursor === i ? " cur" : ""}${gone ? " gone" : ""}`} style={{ top: `${top}px` }}
                  onClick={() => { findingsUi.set((p) => ({ ...p, cursor: i })); navigate("findings", r.id); }}>
                  <span onClick={(e) => e.stopPropagation()}><input type="checkbox" aria-label={`Select ${r.title}`} checked={selected.has(r.id)} onChange={() => toggleRow(r.id)} /></span>
                  <span><Sev level={effectiveSeverity(r)} /></span>
                  <span class="cell"><span class="ttl" title={r.title}>{r.title}</span><span class="pth">{location(r)}</span></span>
                  <span><Verdict v={r.verdict} /></span>
                  <span>{cols.has("confidence") && (r.confidence != null ? <span class="conf"><i><b style={`width:${r.confidence * 100}%`} /></i>{r.confidence.toFixed(2)}</span> : <span class="cc-note">-</span>)}</span>
                  <span class="cell">{cols.has("source") && <><span class="ttl" style="font-weight:500;font-size:12px">{r.llm_only ? "AI-only" : "Scanner-confirmed"}</span><span class="sub">{r.llm_only ? "No scanner match" : r.scanners.join(", ")}</span></>}</span>
                  <span class="mono">{cols.has("owasp") ? first(r) : ""}</span><span class="mono" style="font-size:12px">{cols.has("cwe") ? (r.cwe[0] ?? "-") : ""}</span>
                  <span style={r.status === "new" ? "color:var(--accent);font-weight:600" : "color:var(--text-3)"}>{cols.has("since") ? (r.status === "new" ? "+ New" : r.status === "unchanged" ? "— Unchanged" : "") : ""}</span>
                </div>
              );
            }} />
        )}
        <div class="fx-foot"><span>Rows {rows.length ? 1 : 0} to {Math.min(rows.length, 16)} of {num(rows.length)}. Only visible rows are rendered, {ROW} px each.</span>
          <span><span class="kbd">j</span><span class="kbd">k</span> next, previous <span class="kbd">Enter</span> open <span class="kbd">x</span> select <span class="kbd">Esc</span> close drawer</span></div>
      </div>

      {selectedId && <FindingDrawer key={selectedId} id={selectedId} ids={visibleRows.map((r) => r.id)} />}
      {bulk && <NoteDialog title={`Mark ${selected.size} finding${selected.size === 1 ? "" : "s"} as ${DECISION_LABEL[bulk].toLowerCase()}`} cta={`Mark ${DECISION_LABEL[bulk].toLowerCase()}`} onCancel={() => setBulk(null)} onSave={applyBulk} />}
      {naming && <NameDialog onCancel={() => setNaming(false)} onSave={(label) => { const next = [...views, { id: `v${Date.now()}`, label, criteria: serialize(c) }]; setViews(next); writeViews(next); setNaming(false); }} />}
    </>
  );
}

function NoteDialog({ title, cta, onCancel, onSave }: { title: string; cta: string; onCancel: () => void; onSave: (note: string) => void }) {
  const [note, setNote] = useState("");
  return (
    <>
      <div class="cc-drawer-bg" onClick={onCancel} />
      <div class="dlg" role="dialog" aria-modal="true" aria-label={title}>
        <h2>{title}</h2>
        <p class="cc-note">Say why. The note is saved with the decision; one of 12 characters or more also becomes a team memory that guides future reviews.</p>
        <textarea autoFocus value={note} onInput={(e) => setNote(e.currentTarget.value)} aria-label="Decision note" onKeyDown={(e) => { if (e.key === "Escape") onCancel(); }} />
        <div style="display:flex;gap:8px;justify-content:flex-end"><button class="btn" onClick={onCancel}>Cancel</button><button class="btn primary" disabled={note.trim().length < 3} onClick={() => onSave(note.trim())}>{cta}</button></div>
      </div>
    </>
  );
}

function NameDialog({ onCancel, onSave }: { onCancel: () => void; onSave: (label: string) => void }) {
  const [label, setLabel] = useState("");
  return (
    <>
      <div class="cc-drawer-bg" onClick={onCancel} />
      <div class="dlg" role="dialog" aria-modal="true" aria-label="Save view">
        <h2>Save current view</h2>
        <input class="cc-input" autoFocus value={label} placeholder="For example: Auth findings I own" aria-label="View name" style="margin:8px 0 12px"
          onInput={(e) => setLabel(e.currentTarget.value)} onKeyDown={(e) => { if (e.key === "Enter" && label.trim()) onSave(label.trim()); if (e.key === "Escape") onCancel(); }} />
        <div style="display:flex;gap:8px;justify-content:flex-end"><button class="btn" onClick={onCancel}>Cancel</button><button class="btn primary" disabled={!label.trim()} onClick={() => onSave(label.trim())}>Save view</button></div>
      </div>
    </>
  );
}
