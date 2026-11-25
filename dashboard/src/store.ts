import { useEffect, useState } from "preact/hooks";
import type { Decision, DecisionKind, ReportData } from "./types";

/** A tiny observable store: components subscribe through `useStore`. */
export class Store<T> {
  private listeners = new Set<() => void>();
  constructor(private value: T) {}
  get(): T { return this.value; }
  set(next: T | ((prev: T) => T)): void {
    this.value = typeof next === "function" ? (next as (p: T) => T)(this.value) : next;
    this.listeners.forEach((l) => l());
  }
  subscribe(fn: () => void): () => void { this.listeners.add(fn); return () => this.listeners.delete(fn); }
}

export function useStore<T>(store: Store<T>): T {
  const [, force] = useState(0);
  useEffect(() => store.subscribe(() => force((n) => n + 1)), [store]);
  return store.get();
}

// ---- persisted, per-viewer conveniences (every storage access is guarded: private mode etc.) ----
function readLS(key: string): string | null { try { return localStorage.getItem(key); } catch { return null; } }
function writeLS(key: string, value: string): void { try { localStorage.setItem(key, value); } catch { /* ignore */ } }

// Theme and look are per-viewer conveniences that can be set globally or per project. When a project
// is active, its own choice wins and is what a change saves; with no project the global default is used.
let activeProject: string | null = null;
function scopedKey(base: string): string { return activeProject ? `${base}.${activeProject}` : base; }
function resolveScoped(base: string, pid: string | null): string | null {
  return (pid ? readLS(`${base}.${pid}`) : null) ?? readLS(base);
}

export type Theme = "system" | "light" | "dark";
export const themeStore = new Store<Theme>((readLS("gapscan.theme") as Theme | null) ?? "system");
export function applyTheme(t: Theme): void {
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
}
export function setTheme(t: Theme): void {
  themeStore.set(t);
  writeLS(scopedKey("gapscan.theme"), t);
  applyTheme(t);
}
export function cycleTheme(): void {
  setTheme({ system: "light", light: "dark", dark: "system" }[themeStore.get()] as Theme);
}

// ---- UI edition: "midnight" (dark-only control room, the default), "gapscan" (the GapScan design
// system, light and dark), "soft" (rounded, pastel) or "glassy" (translucent, frosted). All four
// stylesheets ship inlined; the look cycles midnight → gapscan → soft → glassy. A saved look that no
// longer exists (such as the retired "classic") falls back to the default.
// Saved globally or per active project, like the theme. ----
export type Ui = "gapscan" | "midnight" | "soft" | "glassy";
export const DEFAULT_UI: Ui = "midnight";
export const UI_ORDER: Ui[] = ["midnight", "gapscan", "soft", "glassy"];
export const UI_LABEL: Record<Ui, string> = { gapscan: "GapScan", midnight: "Midnight", soft: "Soft", glassy: "Glassy" };
const validUi = (v: string | null): Ui => (v && UI_ORDER.includes(v as Ui) ? (v as Ui) : DEFAULT_UI);
export const uiStore = new Store<Ui>(validUi(readLS("gapscan.ui")));
export function setUi(ui: Ui): void {
  uiStore.set(ui);
  writeLS(scopedKey("gapscan.ui"), ui);
}
export function toggleUi(): void {
  setUi(UI_ORDER[(UI_ORDER.indexOf(uiStore.get()) + 1) % UI_ORDER.length] ?? DEFAULT_UI);
}

/** Switch the project whose theme/look apply now. A project's own choice wins over the global one;
 *  this only reads and applies (it never persists), so it is safe to call on every project change. */
export function setActiveProject(pid: string | null): void {
  activeProject = pid;
  const theme = (resolveScoped("gapscan.theme", pid) as Theme | null) ?? "system";
  themeStore.set(theme);
  applyTheme(theme);
  uiStore.set(validUi(resolveScoped("gapscan.ui", pid)));  // uiStore change re-applies the stylesheet
}

// ---- reviewer decisions: kept per report in localStorage, exported as gapscan-decisions.json ----
export const decisionStore = new Store<Record<string, Decision>>({});
let decisionKey = "gapscan.decisions";
/** Server mode: GapScan's management server embeds a meta tag; decisions then live in its
 *  database (shared across reviewers and reports) instead of this browser's localStorage. */
let serverBaseOverride: string | null | undefined;
/** The Control Center sets this to `/api/projects/<id>` for the project it shows. */
export function setServerBase(base: string | null): void { serverBaseOverride = base; }
function serverBase(): string | null {
  if (serverBaseOverride !== undefined) return serverBaseOverride;
  if (typeof document === "undefined") return null;
  return document.querySelector('meta[name="gapscan-server"]')?.getAttribute("content") ?? null;
}
function sendDecision(id: string, decision: DecisionKind | null, note: string): void {
  const base = serverBase();
  if (!base) return;
  const url = `${base}/decisions/${encodeURIComponent(id)}`;
  const init: RequestInit = decision === null
    ? { method: "DELETE", headers: { "Content-Type": "application/json" } }
    : { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision, note }) };
  fetch(url, init).catch(() => { /* offline: the in-page state still shows the decision */ });
}
export function initDecisions(data: ReportData): void {
  const base = serverBase();
  if (base) {
    decisionStore.set({});
    fetch(`${base}/decisions`).then((r) => r.json()).then((rows: { finding_id: string; decision: DecisionKind; note: string; date: string }[]) => {
      const saved: Record<string, Decision> = {};
      for (const r of rows) saved[r.finding_id] = { finding_id: r.finding_id, decision: r.decision, note: r.note, by: "", date: r.date };
      decisionStore.set(saved);
    }).catch(() => { /* keep empty */ });
    return;
  }
  decisionKey = `gapscan.decisions.${data.meta.project}.${data.meta.scan_created_at}`;
  const saved: Record<string, Decision> = {};
  try { Object.assign(saved, JSON.parse(readLS(decisionKey) ?? "{}")); } catch { /* ignore bad data */ }
  for (const f of data.findings) {
    if (f.decision && !saved[f.id]) saved[f.id] = { finding_id: f.id, decision: f.decision, note: "from decisions file", by: "", date: "" };
  }
  decisionStore.set(saved);
}
export function setDecision(id: string, decision: DecisionKind | null, note = ""): void {
  decisionStore.set((prev) => {
    const next = { ...prev };
    if (decision === null) delete next[id];
    else next[id] = { finding_id: id, decision, note, by: "", date: new Date().toISOString().slice(0, 10) };
    if (!serverBase()) writeLS(decisionKey, JSON.stringify(next));
    return next;
  });
  sendDecision(id, decision, note);
}
export function exportDecisions(): string {
  return JSON.stringify({ version: 1, decisions: Object.values(decisionStore.get()) }, null, 2);
}

// ---- hash router ----
// Report file:      #/findings/<id>
// Control Center:   #/p/<project>/findings/<id>   (and #/ for the project list)
export interface Route { page: string; id: string | null; project: string | null }
export const routeStore = new Store<Route>(parseHash(typeof location === "undefined" ? "" : window.location.hash));
export function parseHash(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter((x, i) => i < 3 || x).map(decodeURIComponent);
  let project: string | null = null;
  if (parts[0] === "p" && parts[1]) { project = parts[1]; parts.splice(0, 2); }
  const [page = "", id = null] = parts;
  return { page: page || (project ? "features" : "home"), id: id || null, project };
}
export function navigate(page: string, id: string | null = null, project: string | null = routeStore.get().project): void {
  const base = project ? `/p/${encodeURIComponent(project)}` : "";
  window.location.hash = `${base}/${page}${id ? `/${encodeURIComponent(id)}` : ""}`;
}
export function initRouter(): void {
  window.addEventListener("hashchange", () => routeStore.set(parseHash(window.location.hash)));
}
