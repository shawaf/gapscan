import { useCallback, useEffect, useRef, useState } from "preact/hooks";
import { api } from "./api";
import type { ProjectDetail, Scan } from "./api";
import type { ReportData } from "../types";

/** Load once and on demand; poll while `poll(data)` is true (and the tab is visible). */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[], poll?: (d: T) => boolean, every = 1500) {
  // Data is tagged with the deps it was loaded for, so a page that changes its inputs (another project, another run)
  // never shows the previous inputs' data while the new load is in flight.
  const key = JSON.stringify(deps);
  const [loaded, setLoaded] = useState<{ key: string; data: T } | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const timer = useRef<number | undefined>(undefined);
  const run = useCallback(() => {
    window.clearTimeout(timer.current);
    load().then((d) => {
      setLoaded({ key, data: d }); setError(""); setLoading(false);
      if (poll?.(d)) timer.current = window.setTimeout(run, document.hidden ? 5000 : every);
    }).catch((e: unknown) => { setError(e instanceof Error ? e.message : String(e)); setLoading(false); });
  }, deps);
  useEffect(() => { setError(""); setLoading(true); run(); return () => window.clearTimeout(timer.current); }, [run]);
  const data = loaded && loaded.key === key ? loaded.data : null;
  return { data, error, loading, reload: run };
}

export const fetchProject = (id: string) => api<ProjectDetail>("GET", `/api/projects/${id}`);
export const fetchScan = (id: number | string) => api<Scan>("GET", `/api/scans/${id}`);
export const fetchReport = (scanId: number) => api<ReportData>("GET", `/api/scans/${scanId}/report.json`);

export const latestDone = (p: ProjectDetail | null): Scan | null =>
  p?.scans.find((s) => s.kind === "scan" && s.status === "done") ?? null;

export function duration(a: string | null, b: string | null): string {
  if (!a) return "-";
  const secs = Math.max(0, Math.round(((b ? Date.parse(b) : Date.now()) - Date.parse(a)) / 1000));
  const m = Math.floor(secs / 60), s = secs % 60;
  return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : m ? `${m}m ${String(s).padStart(2, "0")}s` : `${s}s`;
}
export const clock = (secs: number): string => `${String(Math.floor(secs / 60)).padStart(2, "0")}:${String(secs % 60).padStart(2, "0")}`;
export function when(iso: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  const same = d.toDateString() === new Date().toDateString();
  const t = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  return same ? `Today ${t}` : `${d.toLocaleDateString("en-US", { month: "short", day: "numeric" })}, ${t}`;
}
