import { useState } from "preact/hooks";
import { api } from "./api";
import type { ComplianceCatalog, Project, Service } from "./api";
import { ConfirmDialog, Grade, PageHead, Skeleton } from "./common";
import { Icon } from "./icons";
import type { IconName } from "./icons";
import { useLoad } from "./useApi";
import { useData } from "../context";
import { num } from "../format";
import { navigate } from "../store";
import { DomainArt } from "./DomainArt";

// The gap model (ARCHITECTURE 1): target − evidence = gap. A domain is a family of targets
// and the scanners that produce evidence for them. This catalog only
// names targets, every number shown next to one is computed in Python and read from the report.

/** How far GapScan is with a target: a coverage view, mapped on gaps only, or not built. */
export type TargetState = "coverage" | "mapped" | "gate" | "planned";
export interface Target { id: string; name: string; edition: string; state: TargetState; note: string; page?: string; region?: string; wave?: number; restricted?: boolean }
export interface Domain { id: string; label: string; icon: IconName; ready: boolean; text: string; source: string; targets: Target[]; evidence?: string[] }

export const STATE_LABEL: Record<TargetState, string> = { coverage: "Coverage view", mapped: "Mapped on gaps", gate: "Pass or fail gate", planned: "Planned" };
const STATE_CLASS: Record<TargetState, string> = { coverage: "ok", mapped: "warn", gate: "ok", planned: "" };

export const DOMAINS: Domain[] = [
  {
    id: "security", label: "Application security", icon: "lock", ready: true, source: "Built today",
    text: "Weaknesses in code, dependencies, secrets, infrastructure as code and container images, measured against OWASP standards.",
    evidence: ["Code rules and data flow", "Dependencies, SBOM and malicious packages", "Secrets", "Infrastructure as code", "Container images"],
    targets: [
      { id: "asvs", name: "OWASP ASVS", edition: "5.0", state: "coverage", page: "asvs", note: "Every requirement at the chosen level: evidence of failure, no finding, or manual review." },
      { id: "top10", name: "OWASP Top 10:2025", edition: "", state: "coverage", page: "owasp", note: "Open gaps per category, mapped through CWE." },
      { id: "api", name: "OWASP API Security Top 10", edition: "2023", state: "mapped", note: "Gaps in API code carry the category; a coverage view is not built yet." },
      { id: "masvs", name: "OWASP MASVS", edition: "2.1", state: "mapped", note: "Android, iOS and Flutter gaps carry the control; a coverage view is not built yet." },
      { id: "llm", name: "OWASP GenAI LLM Top 10", edition: "2026", state: "planned", note: "In the knowledge base today; a scan category for LLM applications is planned." },
      { id: "policy", name: "Your own policy", edition: "gapscan.policy.toml", state: "gate", note: "Rules that fail or warn a run, for example in CI." },
    ],
  },
];

const GROUP_ICON: Record<string, IconName> = { standards: "doc", industry: "hotspots", eu: "law", privacy: "person", mena: "globe" };

/** The planned domains, one per group of the compliance catalog served by the engine (/api/compliance). */
export function catalogDomains(cat: ComplianceCatalog): Domain[] {
  return cat.groups.map((g) => ({
    id: g.id, label: g.label, icon: GROUP_ICON[g.id] ?? "compliance", ready: false, text: g.text,
    source: `Planned · ${g.planned} frameworks${g.wave_1 ? `, ${g.wave_1} in the first wave` : ""}`,
    targets: cat.frameworks.filter((f) => f.group === g.id && f.status === "planned").map((f) => ({
      id: f.id, name: f.name, edition: "", state: "planned" as const, note: f.evidence, region: f.region, wave: f.wave, restricted: f.text === "restricted",
    })),
  }));
}

/** Application security first, then the planned domains once the catalog has loaded. */
export const allDomains = (cat: ComplianceCatalog | null): Domain[] => [...DOMAINS, ...(cat ? catalogDomains(cat) : [])];

function TargetRow({ t, onOpen }: { t: Target; onOpen?: () => void }) {
  return (
    <tr class={onOpen ? "click" : ""} onClick={onOpen}>
      <td><b>{t.name}</b>{t.edition && <span class="cc-note"> · {t.edition}</span>}<span class="sub">{t.note}</span></td>
      <td style="white-space:nowrap;text-align:right"><span class={`badge2 ${STATE_CLASS[t.state]}`}>{STATE_LABEL[t.state]}</span></td>
    </tr>
  );
}

/** False when the server has no compliance catalog (GapScan Open ships without it): the planned
 * compliance domains and their links are then not shown. Set by App from GET /api/compliance. */
let complianceAvailable = true;
export const setComplianceAvailable = (v: boolean): void => { complianceAvailable = v; };
export const isComplianceAvailable = (): boolean => complianceAvailable;

const SHOWN = 5;

/** The features home for one project: which features (domains) it is scanned for, each
 *  opening into its own pages. Application security is enabled today; the rest are planned. */
export function ProjectFeatures({ project, domains }: { project: Project; domains: Domain[] }) {
  const done = project.latest_done;
  const services = useLoad(() => api<Service[]>("GET", `/api/projects/${project.id}/services`), [project.id]);
  const enabled = new Set((services.data ?? []).filter((s) => s.enabled).map((s) => s.domain));
  const [confirm, setConfirm] = useState<{ d: Domain; enable: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const apply = async () => {
    if (!confirm) return;
    setBusy(true);
    try { await api("PUT", `/api/projects/${project.id}/services/${confirm.d.id}`, { enabled: confirm.enable }); }
    finally { setBusy(false); setConfirm(null); services.reload(); }
  };
  return (
    <>
      <div class="cc-h"><div><h1>{project.name}</h1>
        <p class="mono cc-note" style="margin:3px 0 0">{project.path}</p>
        <p style="margin-top:8px">The features this project is measured against.{complianceAvailable ? " Turn a feature on or off for this project. Application security is built; the compliance and legal domains are planned and will map the same evidence to each framework's controls." : ""}</p></div></div>
      <div class="dom-grid">
        {domains.map((d) => {
          const on = enabled.has(d.id);
          return (
            <section key={d.id} class={`cc-card dom${on ? "" : " planned"}`} aria-labelledby={`feat-${d.id}`}>
              <DomainArt id={d.id} />
              <div style="display:flex;justify-content:space-between;gap:8px;align-items:center">
                <h2 id={`feat-${d.id}`} class="big" style="display:flex;gap:8px;align-items:center;margin:0"><Icon name={d.icon} size={18} />{d.label}</h2>
                <span class={`badge2 ${on ? "ok" : ""}`}>{on ? "Enabled" : d.ready ? "Off" : "Planned"}</span>
              </div>
              <p style="margin:8px 0 4px;font-size:13px">{d.text}</p>
              {on && d.ready
                ? <p class="cc-note" style="margin:0 0 8px;display:flex;align-items:center;gap:8px">{done
                    ? <>Latest scan: <Grade g={done.grade} n={done.score} /> · {done.open_findings} open gaps of {done.findings}</>
                    : "Not scanned yet — open it to run the first scan."}</p>
                : on
                  ? <p class="cc-note" style="margin:0 0 8px">Enabled for this project. {d.source} · no scan engine yet, so this only records intent for now.</p>
                  : <p class="cc-note" style="margin:0 0 8px">{d.ready ? "Not enabled for this project." : `${d.source} · not available to scan yet.`}</p>}
              <ul class="dom-targets">{d.targets.slice(0, d.ready ? undefined : SHOWN).map((t) => <li key={t.id}><span>{t.name}{t.edition && !t.edition.includes(".toml") ? ` ${t.edition}` : ""}</span><span class={`dot ${t.state}`} title={STATE_LABEL[t.state]} aria-label={STATE_LABEL[t.state]} /></li>)}
                {!d.ready && d.targets.length > SHOWN && <li class="cc-note"><span>and {d.targets.length - SHOWN} more</span></li>}</ul>
              <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
                {on && d.ready && <button class="btn primary" onClick={() => navigate("overview")} aria-label={`Open ${d.label}`}>Open</button>}
                {!on && <button class="btn primary" onClick={() => setConfirm({ d, enable: true })} aria-label={`Enable ${d.label}`}><Icon name="plus" size={13} /> Enable</button>}
                {on && d.id !== "security" && <button class="btn" onClick={() => setConfirm({ d, enable: false })} aria-label={`Disable ${d.label}`}>Disable</button>}
                {!d.ready && <button class="btn" onClick={() => navigate(d.id)} aria-label={`See what is planned for ${d.label}`}>See what is planned</button>}
              </div>
            </section>
          );
        })}
      </div>
      {confirm && (
        <ConfirmDialog
          title={confirm.enable ? `Enable ${confirm.d.label}?` : `Disable ${confirm.d.label}?`}
          confirm={busy ? "Working…" : confirm.enable ? "Enable" : "Disable"}
          danger={!confirm.enable}
          onCancel={() => setConfirm(null)}
          onConfirm={() => void apply()}>
          {confirm.enable
            ? (confirm.d.ready
                ? <>Turn on <b>{confirm.d.label}</b> for <b>{project.name}</b>. New scans will measure this project against its targets ({confirm.d.targets.slice(0, 2).map((t) => t.name).join(", ")}…).</>
                : <>Turn on <b>{confirm.d.label}</b> for <b>{project.name}</b>. This feature is planned — there is no scan engine for it yet, so enabling it only records that this project will use it.</>)
            : <>Turn off <b>{confirm.d.label}</b> for <b>{project.name}</b>. Its history is kept; it stops being part of this project's scans until you enable it again.</>}
        </ConfirmDialog>
      )}
    </>
  );
}

/** A domain that has no engine yet: list its frameworks and say plainly that nothing is measured today. */
export function PlannedDomain({ domain }: { domain: Domain }) {
  return (
    <>
      <div class="cc-h"><div><h1>{domain.label}</h1><p>{domain.text}</p></div></div>
      <div class="fd-banner grey" role="status" style="margin:0 0 16px"><b><Icon name="info" size={13} /> Planned ({domain.source})</b>
        <p>Nothing is measured against these frameworks yet. They will map the evidence that security scans already collect, so projects scanned today will not need to be scanned differently. GapScan will report technical evidence for the controls software can show; it will never say a project is compliant or certified, and it is not legal advice.</p>
        <span style="display:flex;gap:8px"><button class="btn sm primary" onClick={() => navigate("overview")}>Go to Application security</button><button class="btn sm" onClick={() => navigate("features")}>All features</button></span></div>
      <section class="cc-card" style="padding:0" aria-label="Frameworks"><div class="tbl-wrap" style="border:0"><table class="tbl">
        <thead><tr><th>Framework</th><th>Region</th><th>What scans can show</th><th style="text-align:right">Build wave</th></tr></thead>
        <tbody>{domain.targets.map((t) => (
          <tr key={t.id}>
            <td><b>{t.name}</b>{t.restricted && <span class="sub">Copyrighted text: control IDs and our own summaries only</span>}</td>
            <td>{t.region}</td>
            <td style="font-size:13px">{t.note}</td>
            <td style="white-space:nowrap;text-align:right"><span class="badge2">Wave {t.wave}</span></td>
          </tr>
        ))}</tbody></table></div></section>
      <p class="cc-note" style="margin-top:12px">Editions are pinned from each publisher when its pack is built. Wave 1 comes first; wave 3 follows customer demand.</p>
    </>
  );
}

/** Per project: every security target, how far GapScan measures it, and the numbers the report has for it. */
export function ProjectTargetsPage() {
  const { data } = useData();
  const sec = DOMAINS[0] as Domain;
  const a = data.asvs;
  const top10Open = data.owasp.reduce((n, o) => n + o.finding_ids.length, 0);
  const top10Hit = data.owasp.filter((o) => o.finding_ids.length > 0).length;
  const result: Record<string, string> = {
    asvs: a ? `Level ${a.level}: ${num(a.evidence_of_failure)} failing · ${num(a.no_issue_found_by_tools)} no finding · ${num(a.manual_review_required)} manual, of ${num(a.total)}` : "Not computed for this run",
    top10: `${top10Hit} of ${data.owasp.length} categories have open gaps · ${num(top10Open)} gaps mapped`,
  };
  return (
    <>
      <PageHead title="Targets" sub="The standards this project is measured against. A gap is a control from one of them that the evidence shows is not met; one gap can fail controls in several targets." />
      <section class="cc-card" style="padding:0;margin-bottom:16px"><div class="tbl-wrap" style="border:0"><table class="tbl">
        <thead><tr><th>Target</th><th>This run</th><th style="text-align:right">State</th></tr></thead>
        <tbody>{sec.targets.map((t) => (
          <tr key={t.id} class={t.page ? "click" : ""} onClick={t.page ? () => navigate(t.page as string) : undefined}>
            <td><b>{t.name}</b>{t.edition && <span class="cc-note"> · {t.edition}</span>}<span class="sub">{t.note}</span></td>
            <td style="font-size:13px">{result[t.id] ?? <span class="cc-note">{t.state === "gate" ? "Applied when a policy file exists" : "No view yet"}</span>}</td>
            <td style="white-space:nowrap;text-align:right"><span class={`badge2 ${STATE_CLASS[t.state]}`}>{STATE_LABEL[t.state]}</span></td>
          </tr>
        ))}</tbody></table></div></section>
      {complianceAvailable && <p class="cc-note">Compliance frameworks and legal regulations will map the same evidence once their packs exist. <a href="#" onClick={(e) => { e.preventDefault(); navigate("compliance"); }}>See the planned frameworks</a> · <a href="#" onClick={(e) => { e.preventDefault(); navigate("features"); }}>See all features</a></p>}
    </>
  );
}
