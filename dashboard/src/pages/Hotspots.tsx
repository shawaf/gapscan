import { useMemo } from "preact/hooks";
import { EChart, useChartPalette } from "../components/EChart";
import { useData } from "../context";
import { findingsUi } from "./Findings";
import { emptyCriteria } from "../filters";
import { navigate } from "../store";
import { num, SEV_LABEL } from "../format";

export function Hotspots() {
  const { data } = useData();
  const spots = data.hotspots;
  const pal = useChartPalette();
  const option = useMemo(() => ({
    tooltip: {
      formatter: (p: { data: { name: string; value: number; risk: number; findings: number; sev: string } }) =>
        `${p.data.name}<br/>${num(p.data.value)} lines · ${p.data.findings} findings · risk ${p.data.risk.toFixed(1)} · worst: ${SEV_LABEL[p.data.sev as keyof typeof SEV_LABEL]}`,
    },
    series: [{
      type: "treemap", roam: false, nodeClick: false, breadcrumb: { show: false }, label: { show: true, formatter: "{b}" },
      // Size = lines of code (at least 1 so files with findings stay visible); color = worst open severity.
      data: spots.filter((h) => h.loc > 0 || h.findings > 0).map((h) => ({
        name: h.file, value: Math.max(h.loc, 1), risk: h.risk, findings: h.findings, sev: h.max_severity,
        itemStyle: { color: h.findings ? pal.sev[h.max_severity] : pal.neutral, borderColor: pal.treemapBorder },
      })),
    }],
  }), [spots, pal]);
  const open = (file: string) => { findingsUi.set((p) => ({ ...p, criteria: { ...emptyCriteria(), path: file } })); navigate("findings"); };

  return (
    <div>
      <h1>Hotspots</h1>
      <p class="muted">Size is lines of code; color is the worst open severity in the file (gray: no open findings). {data.stats.files_scanned} files, {num(data.stats.loc_total)} lines scanned{data.stats.files_skipped ? `, ${data.stats.files_skipped} skipped (too large)` : ""}.</p>
      <div class="card">{spots.length ? <EChart option={option} tall label="Treemap of files by size and worst severity" /> : <div class="empty">No file information (the report was built without access to the source tree).</div>}</div>
      <div class="card" style={{ marginTop: "14px" }}><h2>Riskiest files</h2>
        <table class="t"><thead><tr><th>File</th><th class="num">Lines</th><th class="num">Findings</th><th class="num">Risk points</th></tr></thead>
          <tbody>{spots.filter((h) => h.findings > 0).slice(0, 15).map((h) => (
            <tr key={h.file}><td><a href="#/findings" class="mono" onClick={(e) => { e.preventDefault(); open(h.file); }}>{h.file}</a></td><td class="num">{num(h.loc)}</td><td class="num">{h.findings}</td><td class="num">{h.risk.toFixed(1)}</td></tr>
          ))}</tbody></table></div>
    </div>
  );
}
