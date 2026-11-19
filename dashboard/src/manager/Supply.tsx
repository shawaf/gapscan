import { useMemo, useState } from "preact/hooks";
import { PageHead, ScannerNotice, Sev, Verdict } from "./common";
import { Icon } from "./icons";
import { useData } from "../context";
import { effectiveSeverity, location, pct } from "../format";
import { navigate } from "../store";
import type { FindingRow, VerdictKey } from "../types";

const REACH: Record<string, string> = { imported: "Imported by project code", not_imported_directly: "Not imported directly (may be transitive)", unknown: "Not checked" };

export function DepsPage() {
  const { data } = useData();
  const d = data.dependencies;
  const [tab, setTab] = useState<"packages" | "plan" | "sbom">("packages");
  const [q, setQ] = useState("");
  const [onlyVuln, setOnlyVuln] = useState(false);
  const sbom = useMemo(() => d.sbom.filter((r) => (!onlyVuln || r.vulnerable) && (!q || `${r.name} ${r.license} ${r.ecosystem}`.toLowerCase().includes(q.toLowerCase()))), [d.sbom, q, onlyVuln]);
  const kev = d.packages.filter((p) => p.kev).length;
  return (
    <>
      <PageHead title="Dependencies" sub={`${d.packages.length} vulnerable packages${kev ? `, ${kev} on the CISA KEV list` : ""} · ${d.upgrade_plan.length} upgrades would fix known advisories · ${d.sbom.length} components in the SBOM`} />
      <ScannerNotice scanners={data.scanners} names={["osv", "trivy"]} what="Dependency findings and the SBOM" />
      <div class="tabs2" role="tablist" aria-label="Dependency views">
        {([["packages", "Vulnerable packages", d.packages.length], ["plan", "Upgrade plan", d.upgrade_plan.length], ["sbom", "SBOM", d.sbom.length]] as const).map(([id, label, n]) => (
          <button key={id} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}>{label}<span class="n">{n}</span></button>
        ))}
      </div>
      {tab === "packages" && (
        <section class="cc-card" style="padding:0">
          {d.packages.length === 0 ? <div class="cc-empty"><Icon name="deps" size={24} /><h2>No open vulnerable packages</h2><p>Nothing installed matches a known advisory in the local database.</p></div> : (
            <div class="tbl-wrap" style="border:0"><table class="tbl"><thead><tr><th>Package</th><th>Worst severity</th><th>Advisories</th><th>Exploit signals</th><th>Fixed in</th><th>Reachability</th><th>Review</th></tr></thead>
              <tbody>{d.packages.map((p) => (
                <tr key={`${p.package}@${p.version}`} class="click" onClick={() => p.finding_ids[0] && navigate("findings", p.finding_ids[0])}>
                  <td><b>{p.package}</b> <span class="mono">{p.version}</span><span class="sub">{p.ecosystem ?? ""}</span></td>
                  <td><Sev level={p.max_severity} /></td>
                  <td>{p.finding_ids.length} finding{p.finding_ids.length === 1 ? "" : "s"}<span class="sub mono">{p.cves.slice(0, 3).join(", ")}{p.cves.length > 3 ? ` +${p.cves.length - 3}` : ""}</span></td>
                  <td>{p.kev && <span class="chip2 bad">CISA KEV</span>} <span class="mono" style="font-size:12px">{p.epss != null ? `EPSS ${pct(p.epss * 100, 1)}` : "EPSS n/a"}</span></td>
                  <td class="mono">{p.fixed_version ?? <span class="cc-note">unknown</span>}</td>
                  <td style="max-width:200px">{REACH[p.reachability] ?? p.reachability}</td>
                  <td><Verdict v={p.verdict as VerdictKey} /></td>
                </tr>
              ))}</tbody></table></div>
          )}
          <p class="cc-note" style="padding:12px 16px">Reachability is an estimate from the model's checks and never clears a finding: an installed vulnerable package stays open until it is upgraded or a reviewer decides.</p>
        </section>
      )}
      {tab === "plan" && (
        <section class="cc-card" style="padding:0">
          {d.upgrade_plan.length === 0 ? <div class="cc-empty"><h2>No upgrades with a known fixed version</h2></div> : (
            <div class="tbl-wrap" style="border:0"><table class="tbl"><thead><tr><th>#</th><th>Upgrade</th><th class="num">Findings resolved</th><th class="num">Risk removed (points)</th></tr></thead>
              <tbody>{d.upgrade_plan.map((s, i) => (
                <tr key={s.package}><td class="mono">{i + 1}</td><td><b>{s.package}</b> <span class="mono">{s.from_version} → <b>{s.to_version}</b></span> {s.kev && <span class="chip2 bad">KEV</span>}</td><td class="num">{s.resolves}</td><td class="num">{s.risk_points.toFixed(1)}</td></tr>
              ))}</tbody></table></div>
          )}
          <p class="cc-note" style="padding:12px 16px">One upgrade per package, ordered by the risk it removes (CISA KEV first). “Fixed in” is the lowest version that fixes every advisory when all of them have a known fix.</p>
        </section>
      )}
      {tab === "sbom" && (
        <section class="cc-card" style="padding:0">
          {!d.sbom_available ? <div class="cc-empty"><h2>No SBOM for this run</h2><p>Trivy was unavailable, so no CycloneDX bill of materials was produced.</p></div> : (
            <>
              <div style="display:flex;gap:10px;align-items:center;padding:12px 16px;flex-wrap:wrap"><input class="cc-input" style="max-width:280px" type="search" value={q} placeholder="Filter components" aria-label="Filter components" onInput={(e) => setQ(e.currentTarget.value)} />
                <button class="cc-chip" aria-pressed={onlyVuln} onClick={() => setOnlyVuln(!onlyVuln)}>Only vulnerable</button><span class="cc-note">{sbom.length} of {d.sbom.length} components</span></div>
              <div class="tbl-wrap" style="border:0;border-top:1px solid var(--line);max-height:520px"><table class="tbl"><thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>License</th><th>Relation</th><th>Vulnerable</th></tr></thead>
                <tbody>{sbom.map((r) => (
                  <tr key={`${r.name}@${r.version}`}><td>{r.name}</td><td class="mono">{r.version}</td><td>{r.ecosystem}</td><td>{r.license || <span class="cc-note">not recorded</span>}</td>
                    <td>{r.direct == null ? "-" : r.direct ? "direct" : "transitive"}</td><td>{r.vulnerable ? <span class="badge2 bad">yes</span> : <span class="cc-note">no</span>}</td></tr>
                ))}</tbody></table></div>
            </>
          )}
        </section>
      )}
    </>
  );
}

function FindingTable({ rows, empty }: { rows: FindingRow[]; empty: string }) {
  if (!rows.length) return <div class="cc-empty" style="padding:28px"><h2>{empty}</h2></div>;
  return (
    <div class="tbl-wrap" style="border:0"><table class="tbl"><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Review</th><th>Reported by</th></tr></thead>
      <tbody>{rows.map((r) => (
        <tr key={r.id} class="click" onClick={() => navigate("findings", r.id)}>
          <td><Sev level={effectiveSeverity(r)} /></td><td><b>{r.title}</b><span class="sub mono">{r.rule_id}</span></td>
          <td class="mono" style="font-size:12px;min-width:160px;overflow-wrap:anywhere">{location(r)}</td><td><Verdict v={r.verdict} /></td><td>{r.scanners.join(", ")}</td></tr>
      ))}</tbody></table></div>
  );
}

export function SecretsPage() {
  const { data } = useData();
  const open = data.findings.filter((f) => f.open);
  const secrets = open.filter((f) => f.category === "secret");
  const config = open.filter((f) => f.category === "config");
  return (
    <>
      <PageHead title="Secrets and Config" sub="Locations only, never values. Possible secrets and infrastructure or configuration issues from Gitleaks, Semgrep, Checkov and Trivy." />
      <div class="fd-banner grey" role="note" style="margin-top:0"><b><Icon name="lock" size={13} /> Secret values are never stored or shown</b><p>Only the place, the rule and the review appear here. Rotate any real secret, even after removing it from the code.</p></div>
      <ScannerNotice scanners={data.scanners} names={["gitleaks"]} what="Secret findings" />
      <section class="cc-card" style="padding:0;margin-bottom:16px"><h2 style="padding:16px 16px 0">Possible secrets · {secrets.length}</h2><FindingTable rows={secrets} empty="No secrets found" /></section>
      <ScannerNotice scanners={data.scanners} names={["checkov", "trivy"]} what="Configuration findings" />
      <section class="cc-card" style="padding:0"><h2 style="padding:16px 16px 0">Infrastructure and configuration issues · {config.length}</h2><FindingTable rows={config} empty="No configuration issues found (Dockerfile, Terraform, Kubernetes)" />
        <p class="cc-note" style="padding:0 16px 14px">CIS benchmark references are not extracted yet.</p></section>
    </>
  );
}
