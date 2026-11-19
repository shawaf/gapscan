import { useState } from "preact/hooks";
import { api } from "./api";
import type { ComplianceCatalog } from "./api";
import { Err, PageHead, Skeleton } from "./common";
import { Icon } from "./icons";
import { num } from "../format";
import { useLoad } from "./useApi";

const WAVE_LABEL: Record<number, string> = { 0: "Available", 1: "Wave 1", 2: "Wave 2", 3: "Wave 3" };

/** Compliance and legal frameworks: a preview of the planned packs. No coverage is computed yet. */
export function CompliancePage() {
  const cat = useLoad(() => api<ComplianceCatalog>("GET", "/api/compliance"), []);
  const [wave, setWave] = useState<number | "all">("all");
  if (!cat.data) return <><PageHead title="Compliance" /><Err text={cat.error} />{!cat.error && <Skeleton rows={5} />}</>;
  const c = cat.data;
  const shown = (g: string) => c.frameworks.filter((f) => f.group === g && (wave === "all" || f.wave === wave));
  return (
    <>
      <PageHead title="Compliance and legal frameworks" sub="Frameworks GapScan will map its evidence to. Each one reaches your findings through ASVS and CWE, so one scan feeds every framework you answer to." />
      <div class="fd-banner warn" role="note" style="margin-top:0"><b><Icon name="info" size={13} /> Preview: only OWASP is built</b>
        <p>The other frameworks are planned, so this page shows no coverage for them yet. When they arrive, GapScan will report technical evidence for the controls that software can show. It will never say a project is compliant or certified, and it is not legal advice.</p></div>
      <div class="state3">
        <div><span class="v">{num(c.counts.available)}</span><span class="l"><Icon name="check" size={14} /> available now</span></div>
        <div><span class="v">{num(c.counts.planned)}</span><span class="l"><Icon name="clock" size={14} /> planned</span></div>
        <div><span class="v">{num(c.counts.wave_1)}</span><span class="l"><Icon name="play" size={14} /> in the first wave</span></div>
      </div>
      <div class="cc-chips" role="group" aria-label="Wave filter" style="margin:0 0 12px">
        <button class="cc-chip" aria-pressed={wave === "all"} onClick={() => setWave("all")}>All</button>
        {[0, 1, 2, 3].map((w) => <button key={w} class="cc-chip" aria-pressed={wave === w} onClick={() => setWave(w)}>{WAVE_LABEL[w]}</button>)}
      </div>
      {c.groups.map((g) => {
        const rows = shown(g.id);
        if (!rows.length) return null;
        return (
          <section key={g.id} class="cc-card" style="padding:0;margin-bottom:16px" aria-label={g.name}>
            <h2 style="margin:0;padding:16px 16px 8px">{g.name}</h2>
            <div class="tbl-wrap" style="border:0;border-top:1px solid var(--line);border-radius:0 0 8px 8px">
              <table class="tbl"><thead><tr><th>Framework</th><th>Region</th><th>What scans can show</th><th>Status</th></tr></thead>
                <tbody>
                  {rows.map((f) => (
                    <tr key={f.id}>
                      <td><b>{f.name}</b>{f.text === "restricted" && <span class="sub">Copyrighted text: control IDs and our own summaries only</span>}</td>
                      <td>{f.region}</td>
                      <td>{f.evidence}</td>
                      <td><span class={`badge2 ${f.status === "available" ? "ok" : ""}`}>{WAVE_LABEL[f.wave]}</span></td>
                    </tr>
                  ))}
                </tbody></table></div>
          </section>
        );
      })}
      <p class="cc-note" style="margin-top:12px">{c.note}</p>
    </>
  );
}
