import { useMemo } from "preact/hooks";
import { EChart, useChartPalette } from "../components/EChart";
import { useData } from "../context";
import { shortDate } from "../format";

export function Trends() {
  const { data } = useData();
  const b = data.baseline;
  const pal = useChartPalette();
  const option = useMemo(() => b ? {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } }, grid: { left: 60, right: 20, top: 20, bottom: 30 },
    xAxis: { type: "category", data: ["New", "Still open", "Fixed"] }, yAxis: { type: "value" },
    series: [{ type: "bar", data: [{ value: b.new, itemStyle: { color: pal.bad } }, { value: b.unchanged, itemStyle: { color: pal.neutral } }, { value: b.fixed, itemStyle: { color: pal.good } }], label: { show: true, position: "top" } }],
  } : {}, [b, pal]);
  if (!b) {
    return (
      <div><h1>Trends &amp; comparison</h1>
        <div class="card"><p>No baseline was given, so there is nothing to compare against.</p>
          <p>Run <span class="mono">gapscan report current-scan.json --baseline previous-scan.json</span> to see which findings are new, which were fixed and how the risk score moved. Finding IDs are stable across code changes, so unchanged findings match up even when lines move.</p></div></div>
    );
  }
  const delta = b.previous_score != null ? data.score.value - b.previous_score : null;
  return (
    <div>
      <h1>Trends &amp; comparison</h1>
      <p class="muted">Compared with the scan from {shortDate(b.previous_created_at)}.</p>
      <div class="grid cols-3">
        <div class="card kpi"><span class="v">{b.new}</span><span class="l">new findings</span></div>
        <div class="card kpi"><span class="v">{b.fixed}</span><span class="l">fixed or no longer reported</span></div>
        <div class="card kpi"><span class="v">{delta == null ? "-" : `${delta > 0 ? "+" : ""}${delta.toFixed(1)}`}</span><span class="l">risk score change{b.previous_score != null ? ` (from ${b.previous_score.toFixed(0)} to ${data.score.value.toFixed(0)})` : ""}</span></div>
      </div>
      <div class="card" style={{ marginTop: "14px" }}><EChart option={option} label="New, still open and fixed findings" /></div>
      {b.fixed_titles.length > 0 && <div class="card" style={{ marginTop: "14px" }}><h2>Fixed since the previous scan</h2><ul>{b.fixed_titles.map((f) => <li key={f.id}>{f.title} <span class="mono muted">{f.location}</span></li>)}</ul></div>}
    </div>
  );
}
