import { useData } from "../context";
import { pct, shortDate } from "../format";
import { Overview } from "./Overview";

/** The printable executive summary (the PDF export renders this page): overview, top risks and
 *  the OWASP summary on one clean layout. */
export function Executive() {
  const { data } = useData();
  return (
    <div>
      <div class="toolbar no-print" style={{ marginBottom: "10px" }}>
        <button class="btn primary" onClick={() => window.print()}>Print / save as PDF</button>
        <a class="btn" href="#/overview">Back to the interactive report</a>
      </div>
      <Overview />
      <div class="card" style={{ marginTop: "14px" }}>
        <h2>OWASP Top 10:2025 summary</h2>
        <table class="t"><thead><tr><th>Category</th><th class="num">Open findings</th><th class="num">Critical</th><th class="num">High</th></tr></thead>
          <tbody>{data.owasp.map((o) => <tr key={o.id}><td>{o.id} {o.name}</td><td class="num">{o.finding_ids.length}</td><td class="num">{o.by_severity.critical ?? 0}</td><td class="num">{o.by_severity.high ?? 0}</td></tr>)}</tbody></table>
        <p class="muted">Category names and text: OWASP Foundation, CC BY-SA 4.0.</p>
      </div>
      {data.asvs && (
        <div class="card" style={{ marginTop: "14px" }}>
          <h2>Standards coverage</h2>
          <p>ASVS {data.freshness.owasp["OWASP ASVS"]} level {data.asvs.level}: {data.asvs.evidence_of_failure} requirements with evidence of failure; {pct(data.asvs.manual_pct, 1)} of requirements need manual review. {data.asvs.note}</p>
        </div>
      )}
      <div class="card warn" style={{ marginTop: "14px" }}>
        <h2>Limitations</h2><ul>{data.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
        <p class="muted">Scan of {shortDate(data.meta.scan_created_at)} · GapScan {data.meta.gapscan_version} · model {data.freshness.model || "none"}</p>
      </div>
    </div>
  );
}
