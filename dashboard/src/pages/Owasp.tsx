import { useMemo } from "preact/hooks";
import { EChart, useChartPalette } from "../components/EChart";
import { useData } from "../context";
import { findingsUi } from "./Findings";
import { emptyCriteria } from "../filters";
import { SEV_GLYPH, SEV_LABEL, SEVERITIES } from "../format";
import { navigate } from "../store";

export function Owasp() {
  const { data } = useData();
  const pal = useChartPalette();
  const option = useMemo(() => ({
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } }, legend: { top: 0 },
    grid: { left: 190, right: 20, top: 36, bottom: 24 }, xAxis: { type: "value" },
    yAxis: { type: "category", inverse: true, data: data.owasp.map((o) => `${o.id.slice(0, 3)} ${o.name}`) },
    series: SEVERITIES.map((s) => ({
      name: `${SEV_GLYPH[s]} ${SEV_LABEL[s]}`, type: "bar", stack: "sev", itemStyle: { color: pal.sev[s] },
      data: data.owasp.map((o) => o.by_severity[s] ?? 0),
    })),
  }), [data, pal]);
  const open = (id: string) => { findingsUi.set((p) => ({ ...p, criteria: { ...emptyCriteria(), owasp: id } })); navigate("findings"); };

  return (
    <div>
      <h1>OWASP Top 10:2025</h1>
      <p class="muted">Every finding is mapped through its CWE to the {data.freshness.owasp["OWASP Top 10"] ?? "2025"} categories using OWASP's published CWE lists. Dependencies count under A03 (software supply chain). Findings without a mapped CWE are not forced into a category.</p>
      <div class="card"><EChart option={option} height={380} label="Open findings per OWASP Top 10 category, stacked by severity" /></div>
      <div class="grid cols-2" style={{ marginTop: "14px" }}>
        {data.owasp.map((o) => {
          const total = o.finding_ids.length;
          return (
            <div class="card" key={o.id}>
              <h2>{o.id} {o.name}</h2>
              {o.description && <p class="muted">{o.description}</p>}
              <p>{total ? <button class="btn" onClick={() => open(o.id)}>{total} open finding{total === 1 ? "" : "s"} →</button> : <span class="muted">No open findings mapped here.</span>}</p>
              <p>{o.cheatsheets.map((c) => <span key={c.url}><a href={c.url} target="_blank" rel="noopener noreferrer">{c.title}</a>{" · "}</span>)}</p>
            </div>
          );
        })}
      </div>
      <p class="muted">Category names and requirement text are from OWASP (CC BY-SA 4.0).</p>
    </div>
  );
}
