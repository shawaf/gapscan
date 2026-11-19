import { useState } from "preact/hooks";
import { api } from "./api";
import type { ProjectDetail } from "./api";
import { Err, PageHead, Sev, Skeleton } from "./common";
import { Icon } from "./icons";
import { useLoad, when } from "./useApi";
import { navigate } from "../store";
import type { Severity } from "../types";

interface Brief { id: string; title: string; severity: Severity; location: string; verdict: string | null }
interface Head { id: number; finished_at: string | null; score: number | null; grade: string | null; open_findings: number | null; findings: number | null }
interface Cmp { a: Head; b: Head; new: Brief[]; fixed: Brief[]; unchanged: number; series: { id: number; at: string | null; score: number | null; open: number | null }[] }

function Trend({ series }: { series: Cmp["series"] }) {
  const pts = series.filter((s) => s.score != null);
  if (pts.length < 2) return <p class="cc-note">The trend appears after two scored runs.</p>;
  const W = 640, H = 200, L = 36, R = 16, T = 14, B = 34;
  const x = (i: number) => L + (i / (pts.length - 1)) * (W - L - R);
  const y = (v: number) => T + (1 - v / 100) * (H - T - B);
  const maxOpen = Math.max(1, ...pts.map((p) => p.open ?? 0));
  const yo = (v: number) => T + (1 - v / maxOpen) * (H - T - B);
  const line = (f: (p: (typeof pts)[number], i: number) => string) => pts.map(f).join(" ");
  return (
    <figure style="margin:0">
      <svg class="trend" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Risk score by run: ${pts.map((p) => `run ${p.id} ${p.score?.toFixed(0)}`).join(", ")}`}>
        {[0, 25, 50, 75, 100].map((g) => <g key={g}><line x1={L} x2={W - R} y1={y(g)} y2={y(g)} stroke="var(--line)" /><text x={L - 6} y={y(g) + 4} text-anchor="end" font-size="10" fill="var(--text-3)">{g}</text></g>)}
        <polyline points={line((p, i) => `${x(i)},${yo(p.open ?? 0)}`)} fill="none" stroke="var(--text-3)" stroke-width="1.5" stroke-dasharray="4 3" />
        <polyline points={line((p, i) => `${x(i)},${y(p.score ?? 0)}`)} fill="none" stroke="var(--accent)" stroke-width="2.5" />
        {pts.map((p, i) => (
          <g key={p.id}><circle cx={x(i)} cy={y(p.score ?? 0)} r="4" fill="var(--surface)" stroke="var(--accent)" stroke-width="2"><title>{`Run #${p.id}: score ${p.score?.toFixed(0)}, ${p.open ?? "?"} open findings`}</title></circle>
            <text x={x(i)} y={H - 12} text-anchor="middle" font-size="10" fill="var(--text-2)">#{p.id}</text></g>
        ))}
      </svg>
      <figcaption class="cc-note" style="display:flex;gap:16px"><span><b style="color:var(--accent)">━</b> Risk score (0 to 100, lower is better)</span><span><b>╌</b> Open findings (scaled)</span></figcaption>
    </figure>
  );
}

function Delta({ label, v, good }: { label: string; v: string; good?: boolean | null }) {
  return <div><span class="v" style={good == null ? "" : `color:${good ? "var(--ok)" : "var(--sev-high)"}`}>{v}</span><span class="l">{label}</span></div>;
}

export function Compare({ project }: { project: ProjectDetail }) {
  const done = project.scans.filter((s) => s.kind === "scan" && s.status === "done");
  const [a, setA] = useState<string>("");
  const [b, setB] = useState<string>("");
  const res = useLoad<Cmp | null>(() => (done.length >= 2 ? api<Cmp>("GET", `/api/projects/${project.id}/compare?${a ? `a=${a}&` : ""}${b ? `b=${b}` : ""}`) : Promise.resolve(null)), [project.id, a, b, done.length]);
  if (done.length < 2) {
    return (<><PageHead title="Compare" sub="Two runs side by side." />
      <div class="cc-card cc-empty"><Icon name="compare" size={28} /><h2>Comparing needs two finished runs</h2><p>This project has {done.length}. Run another scan and the changes appear here.</p><button class="btn primary" onClick={() => navigate("runs")}>Go to Runs</button></div></>);
  }
  const c = res.data;
  const delta = c && c.a.score != null && c.b.score != null ? c.b.score - c.a.score : null;
  const sel = (value: string, set: (v: string) => void, label: string, fallback: number | undefined) => (
    <label class="cc-field" style="margin:0"><span>{label}</span>
      <select class="cc-select" value={value || String(fallback ?? "")} onChange={(e) => set(e.currentTarget.value)}>
        {done.map((r) => <option key={r.id} value={r.id}>Run #{r.id} · {when(r.finished_at)}{r.score != null ? ` · score ${r.score.toFixed(0)}` : ""}</option>)}
      </select></label>
  );
  return (
    <>
      <PageHead title="Compare" sub="Which findings are new, which were fixed and how the risk score moved between two runs. Finding IDs are stable fingerprints, so a finding is recognized even when the code moves." />
      <div class="selrow" style="margin-bottom:16px">{sel(a, setA, "Baseline run (older)", done[1]?.id)}{sel(b, setB, "Compared run (newer)", done[0]?.id)}</div>
      <Err text={res.error} />
      {!c ? <Skeleton rows={3} /> : (
        <>
          <div class="state3" style="grid-template-columns:repeat(4,minmax(0,1fr))">
            <Delta label="+ New findings" v={String(c.new.length)} good={c.new.length === 0 ? true : null} />
            <Delta label="✓ Fixed or no longer reported" v={String(c.fixed.length)} good={c.fixed.length > 0 ? true : null} />
            <Delta label="= Still open" v={String(c.unchanged)} />
            <Delta label={`Risk score change${c.a.score != null ? ` (from ${c.a.score.toFixed(0)} to ${c.b.score?.toFixed(0)})` : ""}`} v={delta == null ? "-" : `${delta > 0 ? "+" : ""}${delta.toFixed(1)}`} good={delta == null || delta === 0 ? null : delta < 0} />
          </div>
          <section class="cc-card" style="margin-bottom:16px"><h2>Trend over the last runs</h2><Trend series={c.series} /></section>
          <div class="cc-grid g2">
            <section class="cc-card" style="padding:0"><h2 style="padding:16px 16px 0">New in run #{c.b.id} · {c.new.length}</h2>
              <List rows={c.new} empty="Nothing new" link /></section>
            <section class="cc-card" style="padding:0"><h2 style="padding:16px 16px 0">Fixed since run #{c.a.id} · {c.fixed.length}</h2>
              <List rows={c.fixed} empty="Nothing fixed" /></section>
          </div>
        </>
      )}
    </>
  );
}

function List({ rows, empty, link }: { rows: Brief[]; empty: string; link?: boolean }) {
  if (!rows.length) return <div class="cc-empty" style="padding:24px"><h2>{empty}</h2></div>;
  return (
    <div class="tbl-wrap" style="border:0;max-height:420px"><table class="tbl"><tbody>
      {rows.map((r) => (
        <tr key={r.id} class={link ? "click" : ""} onClick={() => link && navigate("findings", r.id)}>
          <td style="width:110px"><Sev level={r.severity} /></td><td><b>{r.title}</b><span class="sub mono" style="overflow-wrap:anywhere">{r.location}</span></td></tr>
      ))}
    </tbody></table></div>
  );
}
