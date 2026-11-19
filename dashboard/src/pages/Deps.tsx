import { useMemo, useState } from "preact/hooks";
import { SeverityBadge, VerdictBadge, Tags } from "../components/Badges";
import { useData } from "../context";
import { navigate } from "../store";
import { pct } from "../format";
import type { VerdictKey } from "../types";

const REACH: Record<string, string> = {
  imported: "Imported by project code", not_imported_directly: "Not imported directly (may be transitive)", unknown: "Not checked",
};

export function Deps() {
  const { data } = useData();
  const d = data.dependencies;
  const [q, setQ] = useState("");
  const [onlyVuln, setOnlyVuln] = useState(false);
  const sbom = useMemo(() => d.sbom.filter((r) => (!onlyVuln || r.vulnerable) && (!q || `${r.name} ${r.license} ${r.ecosystem}`.toLowerCase().includes(q.toLowerCase()))), [d.sbom, q, onlyVuln]);

  return (
    <div>
      <h1>Dependencies &amp; supply chain</h1>
      <h2>Vulnerable packages ({d.packages.length})</h2>
      <div class="card">
        {d.packages.length === 0 ? <div class="empty">No open vulnerable packages.</div> : (
          <table class="t"><thead><tr><th>Package</th><th>Worst severity</th><th>Advisories</th><th>Exploit signals</th><th>Fixed in</th><th>Reachability</th><th>Review</th></tr></thead>
            <tbody>{d.packages.map((p) => (
              <tr key={`${p.package}@${p.version}`}>
                <td><b>{p.package}</b> {p.version}<br /><span class="muted">{p.ecosystem ?? ""}</span></td>
                <td><SeverityBadge severity={p.max_severity} /></td>
                <td>{p.finding_ids.length} finding{p.finding_ids.length === 1 ? "" : "s"}<br /><Tags items={p.cves.slice(0, 3)} />{p.cves.length > 3 && <span class="muted">+{p.cves.length - 3}</span>}
                  <br /><a href={`#/findings/${encodeURIComponent(p.finding_ids[0] ?? "")}`} onClick={(e) => { e.preventDefault(); navigate("findings", p.finding_ids[0] ?? null); }}>open first</a></td>
                <td>{p.kev && <span class="tag kev">CISA KEV</span>}{p.epss != null ? `EPSS ${pct(p.epss * 100, 1)}` : <span class="muted">EPSS n/a</span>}</td>
                <td>{p.fixed_version ?? <span class="muted">unknown</span>}</td>
                <td>{REACH[p.reachability] ?? p.reachability}</td>
                <td><VerdictBadge verdict={p.verdict as VerdictKey} /></td>
              </tr>
            ))}</tbody></table>
        )}
        <p class="muted">Reachability is an estimate from the model's checks and never clears a finding: an installed vulnerable package stays open until it is upgraded or a reviewer decides.</p>
      </div>

      <h2 style={{ marginTop: "18px" }}>Upgrade plan</h2>
      <div class="card">
        {d.upgrade_plan.length === 0 ? <div class="empty">No upgrades with a known fixed version.</div> : (
          <table class="t"><thead><tr><th>#</th><th>Upgrade</th><th class="num">Findings resolved</th><th class="num">Risk removed (points)</th></tr></thead>
            <tbody>{d.upgrade_plan.map((s, i) => (
              <tr key={s.package}><td>{i + 1}</td><td><b>{s.package}</b> {s.from_version} → <b>{s.to_version}</b> {s.kev && <span class="tag kev">KEV</span>}</td><td class="num">{s.resolves}</td><td class="num">{s.risk_points.toFixed(1)}</td></tr>
            ))}</tbody></table>
        )}
        <p class="muted">One upgrade per package, ordered by the risk it removes (CISA KEV first). “Fixed in” is the lowest version that fixes every advisory when all of them have a known fix.</p>
      </div>

      <h2 style={{ marginTop: "18px" }}>Software bill of materials (CycloneDX)</h2>
      <div class="card">
        {!d.sbom_available ? <div class="empty">No SBOM was generated for this scan (Trivy was unavailable).</div> : (
          <>
            <div class="filters"><label>Filter<input type="search" value={q} onInput={(e) => setQ((e.currentTarget as HTMLInputElement).value)} /></label>
              <button class="chip" aria-pressed={onlyVuln} onClick={() => setOnlyVuln(!onlyVuln)}>Only vulnerable</button><span class="muted">{sbom.length} of {d.sbom.length} components</span></div>
            <div style={{ maxHeight: "420px", overflow: "auto" }}>
              <table class="t"><thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>License</th><th>Relation</th><th>Vulnerable</th></tr></thead>
                <tbody>{sbom.map((r) => (
                  <tr key={`${r.name}@${r.version}`}><td>{r.name}</td><td>{r.version}</td><td>{r.ecosystem}</td><td>{r.license || <span class="muted">not recorded</span>}</td>
                    <td>{r.direct == null ? "-" : r.direct ? "direct" : "transitive"}</td><td>{r.vulnerable ? "yes" : "no"}</td></tr>
                ))}</tbody></table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
