import { useMemo } from "preact/hooks";
import { PageHead, SevGlyphLabel } from "./common";
import { useData } from "../context";
import { emptyCriteria } from "../filters";
import { num, SEV_LABEL } from "../format";
import { findingsUi } from "../pages/Findings";
import { navigate } from "../store";
import type { Hotspot } from "../types";

interface Rect { x: number; y: number; w: number; h: number; item: Hotspot }

/** Squarified treemap: tiles close to square so labels stay readable. Pure layout, no dependencies. */
export function squarify(items: Hotspot[], w: number, h: number): Rect[] {
  const total = items.reduce((n, i) => n + Math.max(i.loc, 1), 0);
  if (!total || w <= 0 || h <= 0) return [];
  const scale = (w * h) / total;
  const nodes = items.map((item) => ({ item, area: Math.max(item.loc, 1) * scale })).sort((a, b) => b.area - a.area);
  const out: Rect[] = [];
  let x = 0, y = 0, rw = w, rh = h;
  const worst = (row: number[], side: number) => {
    const s = row.reduce((a, b) => a + b, 0);
    const mx = Math.max(...row), mn = Math.min(...row);
    return Math.max((side * side * mx) / (s * s), (s * s) / (side * side * mn));
  };
  let i = 0;
  while (i < nodes.length) {
    const side = Math.min(rw, rh);
    const row: number[] = [];
    let j = i;
    while (j < nodes.length && (row.length === 0 || worst([...row, (nodes[j] as { area: number }).area], side) <= worst(row, side))) { row.push((nodes[j] as { area: number }).area); j++; }
    const sum = row.reduce((a, b) => a + b, 0);
    const thick = sum / side;
    let offset = 0;
    for (let k = 0; k < row.length; k++) {
      const len = (row[k] as number) / thick;
      const item = (nodes[i + k] as { item: Hotspot }).item;
      out.push(rw >= rh ? { x, y: y + offset, w: thick, h: len, item } : { x: x + offset, y, w: len, h: thick, item });
      offset += len;
    }
    if (rw >= rh) { x += thick; rw -= thick; } else { y += thick; rh -= thick; }
    i = j;
  }
  return out;
}

export function HotspotsPage() {
  const { data } = useData();
  const spots = data.hotspots.filter((h) => h.loc > 0 || h.findings > 0).slice(0, 60);
  const W = 1000, H = 360;
  const rects = useMemo(() => squarify(spots, W, H), [spots]);
  const open = (file: string) => { findingsUi.set((p) => ({ ...p, criteria: { ...emptyCriteria(), path: file }, cursor: 0 })); navigate("findings"); };
  return (
    <>
      <PageHead title="Hotspots" sub={`Size is lines of code, color is the worst open severity in the file (white: no open findings). ${data.stats.files_scanned} files, ${num(data.stats.loc_total)} lines scanned${data.stats.files_skipped ? `, ${data.stats.files_skipped} skipped` : ""}.`} />
      <section class="cc-card" style="padding:12px;margin-bottom:16px" aria-label="Treemap of files by size and worst severity">
        {rects.length === 0 ? <div class="cc-empty"><h2>No file information</h2><p>The report was built without access to the source files.</p></div> : (
          <div class="treemap" role="list">
            {rects.map((r) => (
              <div key={r.item.file} role="listitem" style={`position:absolute;left:${(r.x / W) * 100}%;top:${(r.y / H) * 100}%;width:${(r.w / W) * 100}%;height:${(r.h / H) * 100}%`}>
                <button class={`tm ${r.item.findings ? r.item.max_severity : "none"}`} style="position:absolute;inset:0;width:100%;height:100%" onClick={() => open(r.item.file)}
                  title={`${r.item.file}\n${num(r.item.loc)} lines · ${r.item.findings} findings · risk ${r.item.risk.toFixed(1)}${r.item.findings ? ` · worst ${SEV_LABEL[r.item.max_severity]}` : ""}`}
                  aria-label={`${r.item.file}, ${num(r.item.loc)} lines, ${r.item.findings} open findings${r.item.findings ? `, worst ${SEV_LABEL[r.item.max_severity]}` : ""}`}>
                  <b>{r.item.file.split("/").pop()}</b><span>{r.item.findings ? <SevGlyphLabel level={r.item.max_severity} n={r.item.findings} /> : `${num(r.item.loc)} lines`}</span>
                </button>
              </div>
            ))}
          </div>
        )}
      </section>
      <section class="cc-card" style="padding:0"><h2 style="padding:16px 16px 0">Riskiest files</h2>
        <div class="tbl-wrap" style="border:0"><table class="tbl"><thead><tr><th>File</th><th class="num">Lines</th><th class="num">Findings</th><th class="num">Risk points</th></tr></thead>
          <tbody>{data.hotspots.filter((h) => h.findings > 0).slice(0, 15).map((h) => (
            <tr key={h.file} class="click" onClick={() => open(h.file)}><td class="mono" style="font-size:12px">{h.file}</td><td class="num">{num(h.loc)}</td><td class="num">{h.findings}</td><td class="num">{h.risk.toFixed(1)}</td></tr>
          ))}
            {data.hotspots.every((h) => !h.findings) && <tr><td colSpan={4} class="cc-note" style="padding:16px">No file has open findings.</td></tr>}</tbody></table></div></section>
    </>
  );
}
