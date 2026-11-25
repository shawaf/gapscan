import { useEffect, useMemo, useState } from "preact/hooks";
import { Logo } from "../components/Logo";
import type { ComponentChildren } from "preact";
import { ACTIVE, api, connection } from "./api";
import type { ComplianceCatalog, Doctor, Models, Project, ProjectDetail, QueueRun, ScannerAvail, WorkspaceLink } from "./api";
import { ConnectionBanner, Err, Skeleton, percent, stepLabel } from "./common";
import { Compare } from "./Compare";
import { CompliancePage } from "./Compliance";
import { FindingsExplorer } from "./Findings";
import { HotspotsPage } from "./Hotspots";
import { Home } from "./Home";
import { Icon, Spinner } from "./icons";
import { ALL_NAV, MAIN_NAV, SYSTEM_NAV } from "./nav";
import { Overview } from "./Overview";
import { AsvsPage, OwaspPage } from "./Standards";
import { DepsPage, SecretsPage } from "./Supply";
import { RunDrawer, Runs } from "./Runs";
import { HealthPage } from "./Health";
import { SetupPage } from "./Setup";
import { WelcomePage } from "./Welcome";
import { PlannedDomain, ProjectTargetsPage, TargetsPage, allDomains, isComplianceAvailable, setComplianceAvailable } from "./Targets";
import type { Domain } from "./Targets";
import { SettingsPage } from "./Settings";
import { fetchProject, fetchReport, latestDone, useLoad } from "./useApi";
import { DataContext } from "../context";
import { applyTheme, cycleTheme, initDecisions, initRouter, navigate, routeStore, setServerBase, setTheme, setUi, themeStore, toggleUi, uiStore, useStore, UI_ORDER, UI_LABEL } from "../store";
import type { Theme, Ui } from "../store";
import type { ReportData } from "../types";

const RESULT_PAGES: Record<string, () => preact.JSX.Element> = {
  findings: FindingsExplorer, targets: ProjectTargetsPage, owasp: OwaspPage, asvs: AsvsPage, deps: DepsPage, secrets: SecretsPage, hotspots: HotspotsPage,
};

export function App() {
  const route = useStore(routeStore);
  const theme = useStore(themeStore);
  const ui = useStore(uiStore);
  const projects = useLoad(() => api<Project[]>("GET", "/api/projects"), [], (ps) => ps.some((p) => p.active), 2000);
  const queue = useLoad(() => api<QueueRun[]>("GET", "/api/queue"), [], () => true, 2000);
  const health = useLoad(() => api<Doctor>("GET", "/api/doctor"), []);
  const setup = useLoad(() => api<{ welcome: "done" | "skipped" | null }>("GET", "/api/setup"), []);
  const models = useLoad(() => api<Models>("GET", "/api/models"), [], () => true, 30000);
  const catalog = useLoad(() => api<ComplianceCatalog>("GET", "/api/compliance"), []);
  // Polled slowly so the sidebar stops saying "no remote requests" once a workspace is connected.
  const workspace = useLoad(() => api<WorkspaceLink>("GET", "/api/workspace"), [], () => true, 30000);
  const domains = useMemo(() => allDomains(catalog.data), [catalog.data]);
  // GapScan Open has no compliance catalog: the endpoint says `available: false` and the page is hidden.
  const hasCatalog = catalog.loading || (!!catalog.data && catalog.data.available !== false);
  setComplianceAvailable(hasCatalog);
  const mainNav = hasCatalog ? MAIN_NAV : MAIN_NAV.filter((n) => n.id !== "compliance");
  const domainOf = (id: string): Domain | undefined => domains.find((d) => d.id === id);
  const conn = useStore(connection);
  const [menu, setMenu] = useState(false);
  const [palette, setPalette] = useState(false);
  const [pillRun, setPillRun] = useState<number | null>(null);

  const pid = route.project;
  const project = useLoad<ProjectDetail | null>(() => (pid ? fetchProject(pid) : Promise.resolve(null)), [pid],
    (p) => !!p && p.scans.some((s) => ACTIVE.includes(s.status)), 1500);
  const run = latestDone(project.data);
  const report = useLoad<ReportData | null>(() => (run ? fetchReport(run.id) : Promise.resolve(null)), [run?.id]);

  useEffect(() => { applyTheme(themeStore.get()); initRouter(); if (!window.location.hash) navigate("home", null, null); }, []);
  useEffect(() => { setServerBase(pid ? `/api/projects/${pid}` : null); }, [pid]);
  useEffect(() => { if (report.data) initDecisions(report.data); }, [report.data]);

  // First launch: a person with no projects who has not seen the welcome page yet starts there.
  useEffect(() => {
    if (setup.data?.welcome === null && projects.data?.length === 0 && (page === "home" || !pid) && page !== "welcome" && page !== "setup" && page !== "health" && page !== "settings") navigate("welcome", null, null);
  }, [setup.data?.welcome, projects.data?.length]);

  const reloadAll = () => { projects.reload(); queue.reload(); project.reload(); };
  const live = queue.data?.find((q) => q.status === "running") ?? null;  // a scan or a benchmark
  const current = projects.data?.find((p) => String(p.id) === pid) ?? null;
  const page = route.page;
  const warn = health.data ? health.data.summary.warn + health.data.summary.problem : 0;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      const typing = el.tagName === "INPUT" || el.tagName === "SELECT" || el.tagName === "TEXTAREA";
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((v) => !v); return; }
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      const n = Number(e.key);
      const target = mainNav.find((m) => m.key === n);
      if (pid && target) navigate(target.id);
      if (e.key === "t") cycleTheme();
      if (e.key === "u") toggleUi();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pid]);

  useEffect(() => {
    const label = ALL_NAV.find((n) => n.id === page)?.label ?? domainOf(page)?.label ?? "Domains";
    document.title = `GapScan · ${current ? `${current.name} · ` : ""}${label}`;
  }, [page, current?.name]);

  const ctx = useMemo(() => (report.data ? { data: report.data, byId: new Map(report.data.findings.map((f) => [f.id, f])) } : null), [report.data]);
  const counts: Record<string, string> = {};
  if (report.data) { counts.findings = String(report.data.counts.open); counts.deps = String(report.data.dependencies.packages.length); }

  const needsReport = page in RESULT_PAGES || page === "overview";
  const domain = pid ? undefined : domainOf(page);
  let body: ComponentChildren;
  if (page === "settings") body = <SettingsPage project={current ? { id: current.id, name: current.name } : null} />;
  else if (page === "health") body = <HealthPage />;
  else if (page === "setup") body = <SetupPage />;
  else if (page === "welcome") body = <WelcomePage />;
  else if (page === "compliance" && pid && hasCatalog) body = <CompliancePage />;
  else if (!pid && page === "security") body = <Home projects={projects.data} error={projects.error} reload={reloadAll} />;
  else if (!pid && domain) body = <PlannedDomain domain={domain} />;
  else if (!pid || page === "home") body = <TargetsPage projects={projects.data} domains={domains} loading={catalog.loading} />;
  else if (!project.data) body = <><Err text={project.error} />{!project.error && <Skeleton rows={5} />}</>;
  else if (page === "runs") body = <Runs project={project.data} queue={queue.data ?? []} reload={reloadAll} />;
  else if (page === "compare") body = <Compare project={project.data} />;
  else if (needsReport && !ctx) {
    body = report.loading || (run && !report.error) ? <Skeleton rows={6} /> : run ? (
      <div class="cc-card cc-empty"><Icon name="overview" size={28} /><h2>These results could not be loaded</h2><p>{report.error}</p><button class="btn" onClick={report.reload}>Try again</button></div>
    ) : <FirstUse project={project.data} onStarted={reloadAll} />;
  } else if (page === "overview" && ctx) body = <DataContext.Provider value={ctx}><Overview project={project.data} run={run} reload={reloadAll} /></DataContext.Provider>;
  else if (page in RESULT_PAGES && ctx) {
    const View = RESULT_PAGES[page] as () => preact.JSX.Element;
    body = <DataContext.Provider value={ctx}><View /></DataContext.Provider>;
  } else body = <p class="cc-note">Unknown page.</p>;

  const navLink = (n: (typeof ALL_NAV)[number]) => (
    <a key={n.id} href={pid ? `#/p/${pid}/${n.id}` : `#/${n.id}`} aria-current={page === n.id ? "page" : undefined}
      onClick={(e) => { e.preventDefault(); navigate(n.id, null, n.id === "settings" || n.id === "health" ? pid : pid); }}>
      <Icon name={n.icon as never} /><span class="grow">{n.label}</span>
      {n.id === "health" && warn > 0 ? <span class="cc-warnct"><Icon name="warn" size={12} />{warn}</span>
        : counts[n.id] ? <span class="cc-key" title="Open items">{counts[n.id]}</span> : n.key ? <span class="cc-key" title={`Shortcut: ${n.key}`}>{n.key}</span> : null}
    </a>
  );

  return (
    <div class="cc">
      <nav class="cc-side" aria-label="Main">
        <a class="cc-brand" href="#/" onClick={(e) => { e.preventDefault(); navigate("home", null, null); }}><Logo size={18} /><span class="wordmark">GapScan</span></a>
        <div class="cc-switch">
          <button aria-haspopup="listbox" aria-expanded={menu} onClick={() => setMenu(!menu)}>
            <span>{current ? <><span class="nm">{current.name}</span><span class="pth">{current.path}</span></> : <span class="nm">Choose a project</span>}</span><Icon name="chevron" />
          </button>
          {menu && (
            <div class="cc-menu" role="listbox" aria-label="Projects">
              {projects.data?.filter((p) => !p.archived || String(p.id) === pid).map((p) => <button key={p.id} role="option" aria-selected={String(p.id) === pid} onClick={() => { setMenu(false); navigate(page === "home" ? "overview" : page, null, String(p.id)); }}><b>{p.name}</b><span class="cc-note mono" style="display:block">{p.path}</span></button>)}
              <button onClick={() => { setMenu(false); navigate("security", null, null); }}>All security projects and add a project…</button>
            </div>
          )}
        </div>
        {pid ? <div class="cc-nav"><span class="cc-group">Application security</span>{mainNav.map((n, i) => (n.group && n.group !== mainNav[i - 1]?.group ? [<span key={`g-${n.group}`} class="cc-group sub">{n.group}</span>, navLink(n)] : navLink(n)))}</div> : (
          <div class="cc-nav">
            <a href="#/" aria-current={page === "home" ? "page" : undefined} onClick={(e) => { e.preventDefault(); navigate("home", null, null); }}><Icon name="overview" /><span class="grow">All domains</span></a>
            <span class="cc-group">Domains</span>
            {domains.map((d) => <a key={d.id} href={`#/${d.id}`} aria-current={page === d.id ? "page" : undefined} onClick={(e) => { e.preventDefault(); navigate(d.id, null, null); }}><Icon name={d.icon} /><span class="grow">{d.label}</span>{!d.ready && <span class="cc-key">Planned</span>}</a>)}
          </div>
        )}
        <div class="cc-sep" />
        <div class="cc-nav">{SYSTEM_NAV.map(navLink)}</div>
        <div class="cc-offline"><Icon name="lock" /><span><b>Local mode</b> · {workspace.data?.connected
          ? <>scans stay offline. Runs go to {hostOf(workspace.data.url)} only when you press Send.</>
          : "offline, no remote requests."}<br />Served from {window.location.host}</span></div>
      </nav>
      <div class="cc-main">
        <header class="cc-top">
          <div class="cc-crumb">{current ? <><a href="#/security" onClick={(e) => { e.preventDefault(); navigate("security", null, null); }}>Application security</a> / {current.name} / <b>{ALL_NAV.find((n) => n.id === page)?.label ?? "Overview"}</b></>
            : domain ? <><a href="#/" onClick={(e) => { e.preventDefault(); navigate("home", null, null); }}>Domains</a> / <b>{domain.label}</b></> : <b>{ALL_NAV.find((n) => n.id === page)?.label ?? "Domains"}</b>}</div>
          <button class="cc-search" onClick={() => setPalette(true)} aria-label="Search or run a command (Ctrl K)"><Icon name="search" /><span>Search or run a command</span><span class="cc-key">Ctrl K</span></button>
          {live && live.kind === "benchmark" && (
            <a class="cc-pill" href="#/health" onClick={(e) => { e.preventDefault(); navigate("health"); }} aria-label="Model benchmark in progress, open System Health">
              <Spinner /><b>Benchmark</b><span>{live.options.model} · {live.progress_done} of {live.progress_total} cases</span><span class="mini"><i style={`width:${live.progress_total ? (100 * live.progress_done) / live.progress_total : 0}%`} /></span>
            </a>
          )}
          {live && live.kind !== "benchmark" && (
            <a class="cc-pill" href={`#/p/${live.project_id}/runs/${live.id}`} onClick={(e) => { e.preventDefault(); setPillRun(live.id); }} aria-label={`Run ${live.id} in progress, open details`}>
              <Spinner /><b>Run #{live.id}</b><span>{stepLabel(live)} · {percent(live)}%</span><span class="mini"><i style={`width:${percent(live)}%`} /></span>
            </a>
          )}
          {pid && <button class="btn primary" onClick={() => navigate("runs")}><Icon name="plus" size={14} /> New scan</button>}
          <div class="cc-seg" role="radiogroup" aria-label="Look" title="Shortcut: u">
            {UI_ORDER.map((u: Ui) => (
              <button key={u} role="radio" aria-checked={ui === u} onClick={() => setUi(u)}>{UI_LABEL[u]}</button>
            ))}
          </div>
          <div class="cc-seg icons" role="radiogroup" aria-label="Theme" title="Shortcut: t">
            {(["light", "dark", "system"] as Theme[]).map((t) => {
              const label = t === "light" ? "Light" : t === "dark" ? "Dark" : "System";
              return <button key={t} role="radio" aria-checked={theme === t} aria-label={`${label} theme`} title={`${label} theme`} onClick={() => setTheme(t)}><Icon name={t === "light" ? "sun" : t === "dark" ? "moon" : "monitor"} size={15} /></button>;
            })}
          </div>
        </header>
        <main class={`cc-body${!pid && (page === "home" || domain) ? " wide" : ""}`} id="main">
          {!conn.ok && <ConnectionBanner lastOk={conn.lastOk} onRetry={() => { reloadAll(); queue.reload(); }} />}
          {project.data?.archived && (
            <div class="fd-banner grey" role="status" style="margin:0 0 16px"><b><Icon name="lock" size={13} /> This project is archived</b>
              <p>Its history and decisions are kept, but runs are blocked.</p>
              <button class="btn sm" onClick={async () => { await api("PUT", `/api/projects/${project.data?.id}`, { archived: false }); reloadAll(); }}>Restore project</button></div>
          )}
          {models.data?.error && (page === "overview" || page === "runs") && project.data && (
            <div class="fd-banner bad" role="status" style="margin:0 0 16px"><b><Icon name="x" size={13} /> The local model server is not answering</b>
              <p>AI review is off until it is back. Scans still run with scanners only, and verdicts from earlier runs stay visible with their run number.</p>
              <span style="display:flex;gap:8px"><button class="btn sm primary" onClick={() => navigate("setup")}>Set up the AI engine</button><button class="btn sm" onClick={() => navigate("health")}>Open System Health</button>
                <button class="btn sm" onClick={async () => { await api("POST", `/api/projects/${project.data?.id}/scans`, { triage: false }); reloadAll(); navigate("runs"); }}>Run scanners only</button></span></div>
          )}
          {body}
        </main>
      </div>
      {palette && <Palette onClose={() => setPalette(false)} pid={pid} projects={projects.data ?? []} domains={domains} />}
      {pillRun != null && project.data && live && <RunDrawer id={pillRun} project={project.data} onClose={() => setPillRun(null)} reload={reloadAll} />}
    </div>
  );
}

/** Before the first scan: say what is ready and offer the two ways to start. */
function FirstUse({ project, onStarted }: { project: ProjectDetail; onStarted: () => void }) {
  const scanners = useLoad(() => api<ScannerAvail[]>("GET", "/api/scanners"), []);
  const models = useLoad(() => api<Models>("GET", "/api/models"), []);
  const ready = scanners.data?.filter((s) => s.available).length ?? 0;
  const profile = models.data?.profiles.find((p) => p.selected);
  const start = async (triage: boolean) => { await api("POST", `/api/projects/${project.id}/scans`, { triage }); onStarted(); navigate("runs"); };
  return (
    <div class="cc-card cc-empty" style="border-style:dashed;text-align:left;max-width:640px">
      <h2>No scans yet for {project.name}</h2>
      <p>Run a scan to measure this project against its target standards (OWASP ASVS and Top 10) and see its gaps here. {scanners.data ? `${ready} of ${scanners.data.length} scanners` : "Scanners"}{profile ? ` and the ${profile.name} model (${profile.installed ? "installed" : "not installed"}) are ready.` : " are being checked."}</p>
      <div style="display:flex;gap:8px;margin-top:10px"><button class="btn primary" onClick={() => start(true)} disabled={!ready}>Run scan + AI review</button><button class="btn" onClick={() => start(false)} disabled={!ready}>Scanners only</button></div>
    </div>
  );
}

function Palette({ onClose, pid, projects, domains }: { onClose: () => void; pid: string | null; projects: Project[]; domains: Domain[] }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const commands = useMemo(() => [
    ...(pid ? ALL_NAV.filter((n) => isComplianceAvailable() || n.id !== "compliance").map((n) => ({ label: `Go to ${n.label}`, hint: n.key ? String(n.key) : "", run: () => navigate(n.id) })) : []),
    ...(pid ? [{ label: "Start a new scan", hint: "", run: () => navigate("runs") }] : []),
    { label: "Switch theme", hint: "t", run: cycleTheme },
    { label: "Switch look (GapScan / Midnight / soft / glassy)", hint: "u", run: toggleUi },
    { label: "All domains", hint: "", run: () => navigate("home", null, null) },
    ...domains.map((d) => ({ label: `Go to ${d.label}${d.ready ? " projects" : " (planned)"}`, hint: "", run: () => navigate(d.id, null, null) })),
    ...projects.map((p) => ({ label: `Open project ${p.name}`, hint: "", run: () => navigate("overview", null, String(p.id)) })),
  ], [pid, projects, domains]);
  const shown = commands.filter((c) => c.label.toLowerCase().includes(q.toLowerCase())).slice(0, 10);
  const go = (i: number) => { const c = shown[i]; if (c) { onClose(); c.run(); } };
  return (
    <>
      <div class="cc-drawer-bg" onClick={onClose} />
      <div class="cc-cmd" role="dialog" aria-modal="true" aria-label="Command palette">
        <input autoFocus value={q} placeholder="Search pages, projects and actions" aria-label="Search commands"
          onInput={(e) => { setQ(e.currentTarget.value); setSel(0); }}
          onKeyDown={(e) => {
            if (e.key === "Escape") onClose();
            if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, shown.length - 1)); }
            if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
            if (e.key === "Enter") go(sel);
          }} />
        <ul role="listbox">{shown.map((c, i) => <li key={c.label} role="option" aria-selected={i === sel} onClick={() => go(i)}><span>{c.label}</span><span class="cc-key">{c.hint}</span></li>)}
          {shown.length === 0 && <li class="cc-note">Nothing matches.</li>}</ul>
      </div>
    </>
  );
}

function hostOf(url: string): string {
  try { return new URL(url).host; } catch { return url; }
}
