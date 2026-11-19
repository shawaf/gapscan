import type { ComplianceCatalog, Project } from "./api";
import { PageHead, Skeleton } from "./common";
import { Icon } from "./icons";
import type { IconName } from "./icons";
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
    source: `ROADMAP 5.2 · ${g.planned} frameworks${g.wave_1 ? `, ${g.wave_1} in the first wave` : ""}`,
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

/** The gap model in one line, so the start page says what GapScan does before asking anything. */
function GapModel() {
  const step = (icon: IconName, title: string, text: string) => (
    <div style="flex:1;min-width:150px"><b style="display:flex;gap:6px;align-items:center"><Icon name={icon} size={14} />{title}</b><p class="cc-note" style="margin:2px 0 0">{text}</p></div>
  );
  const op = (s: string) => <span aria-hidden="true" style="font-size:20px;color:var(--text-3);align-self:center">{s}</span>;
  return (
    <div class="cc-card" style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px" role="note" aria-label="How GapScan measures">
      {step("asvs", "Target", "A versioned standard or your own policy")}{op("−")}
      {step("findings", "Evidence", "What scanners, data flow and reachability show")}{op("=")}
      {step("warn", "Gap", "A control the evidence shows is not met")}{op("→")}
      {step("check", "Proof of fix", "A rescan confirms the gap is closed")}
    </div>
  );
}

/** Start page: choose what to measure the software against, then go to that domain's projects. */
const SHOWN = 5;

export function TargetsPage({ projects, domains, loading }: { projects: Project[] | null; domains: Domain[]; loading: boolean }) {
  const count = (projects ?? []).filter((p) => !p.archived).length;
  return (
    <>
      <div class="cc-h"><div><h1>What do you want to close gaps against?</h1>
        <p>Choose a domain to see its projects and dashboards. Application security is built. The compliance and legal domains are planned: they will map the same evidence to each framework's controls.</p></div></div>
      <GapModel />
      <div class="dom-grid">
        {domains.map((d) => {
          const go = () => navigate(d.id, null, null);
          return (
            <section key={d.id} class={`cc-card dom${d.ready ? "" : " planned"}`} aria-labelledby={`dom-${d.id}`}>
              <DomainArt id={d.id} />
              <div style="display:flex;justify-content:space-between;gap:8px;align-items:center">
                <h2 id={`dom-${d.id}`} class="big" style="display:flex;gap:8px;align-items:center;margin:0"><Icon name={d.icon} size={18} />{d.label}</h2>
                <span class={`badge2 ${d.ready ? "ok" : ""}`}>{d.ready ? `${count} project${count === 1 ? "" : "s"}` : "Planned"}</span>
              </div>
              <p style="margin:8px 0 4px;font-size:13px">{d.text}</p>
              <p class="cc-note" style="margin:0 0 8px">{d.source}</p>
              <ul class="dom-targets">{d.targets.slice(0, d.ready ? undefined : SHOWN).map((t) => <li key={t.id}><span>{t.name}{t.edition && !t.edition.includes(".toml") ? ` ${t.edition}` : ""}</span><span class={`dot ${t.state}`} title={STATE_LABEL[t.state]} aria-label={STATE_LABEL[t.state]} /></li>)}
                {!d.ready && d.targets.length > SHOWN && <li class="cc-note"><span>and {d.targets.length - SHOWN} more</span></li>}</ul>
              <button class={`btn ${d.ready ? "primary" : ""}`} style="margin-top:12px" onClick={go}
                aria-label={d.ready ? `Open ${d.label}, ${count} project${count === 1 ? "" : "s"}` : `Open ${d.label}, planned`}>
                {d.ready ? "Open projects" : "See what is planned"}</button>
            </section>
          );
        })}
        {loading && <section class="cc-card"><Skeleton rows={4} /></section>}
      </div>
      <p class="cc-note" style="margin-top:12px;display:flex;gap:14px;flex-wrap:wrap">{(Object.keys(STATE_LABEL) as TargetState[]).map((s) => <span key={s}><span class={`dot ${s}`} /> {STATE_LABEL[s]}</span>)}</p>
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
        <span style="display:flex;gap:8px"><button class="btn sm primary" onClick={() => navigate("security", null, null)}>Go to Application security</button><button class="btn sm" onClick={() => navigate("home", null, null)}>All domains</button></span></div>
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
      <p class="cc-note">Compliance frameworks and legal regulations will map the same evidence once their packs exist. <a href="#" onClick={(e) => { e.preventDefault(); navigate("compliance"); }}>See the planned frameworks</a> · <a href="#/" onClick={(e) => { e.preventDefault(); navigate("home", null, null); }}>See all domains</a></p>
    </>
  );
}
