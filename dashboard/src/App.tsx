import { useEffect, useMemo, useState } from "preact/hooks";
import { DataContext } from "./context";
import { Logo } from "./components/Logo";
import { loadData } from "./data";
import { download, reportFilename } from "./download";
import { Icon } from "./manager/icons";
import { applyTheme, cycleTheme, setTheme, toggleUi, uiStore, UI_LABEL, decisionStore, initDecisions, initRouter, navigate, routeStore, themeStore, useStore } from "./store";
import type { Theme } from "./store";
import type { ReportData } from "./types";
import { Asvs } from "./pages/Asvs";
import { Coverage } from "./pages/Coverage";
import { Deps } from "./pages/Deps";
import { Details } from "./pages/Details";
import { Executive } from "./pages/Executive";
import { Findings } from "./pages/Findings";
import { Hotspots } from "./pages/Hotspots";
import { Images } from "./pages/Images";
import { Infrastructure } from "./pages/Infrastructure";
import { Overview } from "./pages/Overview";
import { Owasp } from "./pages/Owasp";
import { SecretsConfig } from "./pages/SecretsConfig";
import { Trends } from "./pages/Trends";

const PAGES = [
  { id: "overview", label: "Overview", view: Overview },
  { id: "owasp", label: "OWASP Top 10", view: Owasp },
  { id: "findings", label: "Findings", view: Findings },
  { id: "asvs", label: "ASVS coverage", view: Asvs },
  { id: "coverage", label: "Coverage", view: Coverage },
  { id: "deps", label: "Dependencies", view: Deps },
  { id: "iac", label: "Infrastructure", view: Infrastructure },
  { id: "images", label: "Container images", view: Images },
  { id: "secrets", label: "Secrets", view: SecretsConfig },
  { id: "hotspots", label: "Hotspots", view: Hotspots },
  { id: "trends", label: "Trends", view: Trends },
  { id: "details", label: "Scan details", view: Details },
] as const;

export function App() {
  const [data, setData] = useState<ReportData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const route = useStore(routeStore);
  const theme = useStore(themeStore);
  const ui = useStore(uiStore);
  const decisions = useStore(decisionStore);

  useEffect(() => {
    applyTheme(themeStore.get());
    initRouter();
    loadData().then((d) => { initDecisions(d); setData(d); }).catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  useEffect(() => {
    if (data) document.title = `GapScan report · ${data.meta.project}`;
  }, [data]);

  // global shortcuts: 1-9 pages, t theme, u UI edition
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.tagName === "INPUT" || el.tagName === "SELECT" || el.tagName === "TEXTAREA" || e.metaKey || e.ctrlKey || e.altKey) return;
      const n = Number(e.key);
      if (n >= 1 && n <= PAGES.length) navigate((PAGES[n - 1] as (typeof PAGES)[number]).id);
      if (e.key === "t") cycleTheme();
      if (e.key === "u") toggleUi();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const ctx = useMemo(() => (data ? { data, byId: new Map(data.findings.map((f) => [f.id, f])) } : null), [data]);
  if (error) return <div class="main"><h1>Cannot open this report</h1><p class="card bad">{error}</p></div>;
  if (!data || !ctx) return <div class="main" role="status">Loading report…</div>;

  // "executive" is a printable page reached from the toolbar and used by the PDF export.
  const page = PAGES.find((p) => p.id === route.page) ?? (route.page === "executive" ? { id: "executive", label: "Executive summary", view: Executive } : PAGES[0]);
  const View = page.view;
  const openCount = data.counts.open - Object.keys(decisions).filter((id) => ctx.byId.get(id)?.open).length;
  const iacCount = (data.infrastructure ?? []).reduce((n, g) => n + g.files.reduce((m, f) => m + f.findings, 0), 0);
  const counts: Record<string, string> = {
    findings: String(openCount), deps: String(data.dependencies.packages.length),
    ...(iacCount ? { iac: String(iacCount) } : {}), ...((data.images ?? []).length ? { images: String((data.images ?? []).length) } : {}),
  };

  return (
    <DataContext.Provider value={ctx}>
      <div class="app">
        <aside class="sidebar">
          <div class="brand"><Logo size={18} /><span><span class="wordmark">GapScan</span><small>{data.meta.project}</small></span></div>
          <nav class="nav" aria-label="Report pages">
            {PAGES.map((p, i) => (
              <a key={p.id} href={`#/${p.id}`} aria-current={page.id === p.id ? "page" : undefined} title={`Shortcut: ${i + 1}`}>
                <span>{p.label}</span>{counts[p.id] && <span class="count">{counts[p.id]}</span>}
              </a>
            ))}
          </nav>
        </aside>
        <main class="main" id="main">
          <div class="topbar no-print">
            <span class="muted">Risk <b class={`grade-${data.score.grade}`}>{data.score.grade} ({data.score.value.toFixed(0)})</b> · {openCount} open findings</span>
            <div class="toolbar">
              <button class="btn" onClick={toggleUi} aria-label={`Look: ${ui}. Press to change the look`} title="Shortcut: u">Look: {UI_LABEL[ui]}</button>
              <div class="seg" role="radiogroup" aria-label="Theme" title="Shortcut: t">
                {(["light", "dark", "system"] as Theme[]).map((t) => {
                  const label = t === "light" ? "Light" : t === "dark" ? "Dark" : "System";
                  return <button key={t} role="radio" aria-checked={theme === t} aria-label={`${label} theme`} title={`${label} theme`} onClick={() => setTheme(t)}><Icon name={t === "light" ? "sun" : t === "dark" ? "moon" : "monitor"} size={15} /></button>;
                })}
              </div>
              <button class="btn" onClick={() => download(reportFilename(data, "json"), JSON.stringify(data, null, 2), "application/json")}>Export JSON</button>
              <button class="btn" onClick={() => navigate("executive")}>Executive summary (PDF)</button>
            </div>
          </div>
          <View />
        </main>
      </div>
    </DataContext.Provider>
  );
}
