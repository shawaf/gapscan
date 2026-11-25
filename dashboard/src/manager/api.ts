/** Thin client for the management server. The browser adds Origin and the session cookie. */
export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

import { Store } from "../store";

/** Whether the server answered the last request, and when it last did (drives the "live updates paused" banner). */
export const connection = new Store<{ ok: boolean; lastOk: number }>({ ok: true, lastOk: Date.now() });

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    connection.set((c) => (c.ok ? { ...c, ok: false } : c));
    throw new ApiError(0, "The server is not answering");
  }
  if (!connection.get().ok || Date.now() - connection.get().lastOk > 5000) connection.set({ ok: true, lastOk: Date.now() });
  else connection.get().lastOk = Date.now();
  let data: unknown = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) throw new ApiError(res.status, (data as { error?: string } | null)?.error ?? `request failed (${res.status})`);
  return data as T;
}

export interface ScanBrief { id: number; status: string; score: number | null; grade: string | null; open_findings: number | null; findings: number | null; finished_at: string | null }
export interface Project {
  id: number; name: string; path: string; created_at: string; archived: boolean;
  latest: ScanBrief | null; latest_done: ScanBrief | null; history: { id: number; score: number | null; at: string | null }[]; active: boolean;
}
export interface RunOptions {
  triage?: boolean; limit?: number; rebuild?: boolean; scanners?: string[]; profile?: string;
  max_tool_calls?: number; asvs_level?: number; baseline?: number; model?: string;
  deep_dive?: boolean; deep_dive_limit?: number; base?: string;
}
/** What is checked out in a project's folder, and the refs a diff-aware run can use as its base.
 * Read from git only: GapScan never fetches, checks out or pulls. */
export interface GitRefs { git: boolean; branch: string; commit: string; dirty: boolean; refs: string[] }
/** The branch/commit checked out in a folder (GET /api/git-head). All-empty for a non-repo. */
export interface GitHead { git: boolean; branch: string; commit: string; dirty: boolean }
/** One directory's sub-folders, for the in-browser folder picker (GET /api/fs). Directories only. */
export interface FsListing {
  path: string; name: string; parent: string | null; home: string; truncated: boolean;
  entries: { name: string; git: boolean }[]; head: GitHead;
}
export interface Plan {
  folder: string; exists: boolean; files: number; scannable: number; by_language: Record<string, number>; bytes: number; truncated: boolean;
  scanners: { name: string; will_run: boolean; version: string; why: string }[];
  ai: { enabled: boolean; profile: string; model: string; limit: number; tool_calls: number; installed: boolean | null; error: string };
  ignore: { file: boolean; paths: number; rules: number }; estimate_seconds: number | null; changes: string;
}
export interface Benchmark {
  id: number; model: string; status: string; phase: string; progress_done: number; progress_total: number; error: string; finished_at: string | null;
  summary: { accuracy?: number; true_positives_kept?: number; false_positives_removed?: number; first_try_valid_json?: number; median_seconds?: number; cases?: number; failed?: number };
}
export interface RunStats {
  plan?: Plan;
  raw?: number; merged?: number; scanners?: { name: string; status: string; findings: number; seconds: number }[];
  verdicts?: Record<string, number>; tokens?: number; seconds_per_finding?: number; seconds_left?: number; failed_at?: string;
  deep_dive?: { investigations: number; total: number; covers: number; failed: number; dropped: number };
}
export interface QueueRun {
  id: number; project_id: number; kind?: string; project: string; status: string; phase: string; options: RunOptions;
  progress_done: number; progress_total: number; created_at: string; started_at: string | null; stats: RunStats; position: number;
}
export interface ScannerAvail { name: string; description: string; available: boolean; version: string; default: boolean }
export interface Scan {
  id: number; project_id: number; kind: string; status: string; phase: string; options: RunOptions; stats: RunStats;
  created_at: string; started_at: string | null; finished_at: string | null; error: string;
  progress_done: number; progress_total: number; findings: number | null; open_findings: number | null;
  score: number | null; grade: string | null; model: string | null; log: string; started_by?: string; has_report?: boolean; exports?: string[];
  branch?: string; commit_sha?: string;
}
export interface ProjectDetail extends Project { scans: Scan[] }
/** One feature (domain) a project has turned on, from GET /api/projects/{id}/services. */
export interface Service { domain: string; enabled: boolean; label: string }
export interface Profile { name: string; model: string; note: string; installed: boolean; selected: boolean; size_gb: number | null }
export interface Models { profiles: Profile[]; installed: { name: string }[]; error: string; endpoint: string }
export interface Settings { profile: string; triage_limit: number; use_tools: boolean; max_tool_calls: number; asvs_level: number; default_preset: "full" | "scanners"; deep_dive: boolean; deep_dive_limit: number; scanners: string[] }
export interface Check { name: string; status: "ok" | "warn" | "problem"; component: string; group: string; version: string; detail: string; fix: string }
export interface Doctor { checked_at: string; summary: { ok: number; warn: number; problem: number }; items: Check[] }
export interface Freshness { name: string; value: string; age_days: number | null; used: number | null; stale: boolean }
export interface DataInfo { version: string; data_dir: string; bundle: Record<string, unknown> | null; max_age_days: number; freshness: Freshness[] }
export interface Task { id: string; kind: string; status: string; log: string[]; progress?: { done: number; total: number }; result: { snapshots?: Record<string, string>; warnings?: string[] } | null }

export const ACTIVE = ["queued", "running"];

export interface Memory { id: string; text: string; kind: string; rule: string; path: string; cwe: string; source: string; created: string; enabled: boolean }

export interface Hw { os: string; arch: string; ram_gb: number; disk_free_gb: number; gpu: string; gpu_name: string; vram_gb: number; usable_gb: number }
export interface PackInfo { id: string; filename: string; size: number; version: string; platform: string; alias: string; note: string }
export interface Tier { id: string; profile: string; alias: string; size: number; note: string; needs_gb: number; fits: boolean; installed: boolean; running: boolean; linked: boolean; ollama: boolean }
export interface SetupStatus {
  hardware: Hw; platform: string; runtime: { pack: PackInfo | null; installed: boolean }; embedding: { pack: PackInfo | null; installed: boolean };
  scanners: { name: string; via: "bundled" | "managed" | "path" | "missing"; path: string }[]; scanner_plan: { missing: string[]; packs: string[]; python: boolean; size: number; unavailable: string[] };
  tiers: Tier[]; recommended: string | null; selected: string | null; welcome: "done" | "skipped" | null; plan: PlanStep[]; running: boolean; active: string | null; hosts: string[]; manifest_created: string; task: string | null;
}
export interface PlanStep { step: string; pack?: string; label: string; size: number | null; done: boolean; optional: boolean; note?: string }

export interface ComplianceFramework { id: string; name: string; group: string; region: string; wave: 0 | 1 | 2 | 3; status: "available" | "planned"; text: "open" | "restricted"; evidence: string }
export interface ComplianceGroup { id: string; label: string; name: string; text: string; planned: number; wave_1: number }
export interface ComplianceCatalog { available?: boolean; note: string; groups: ComplianceGroup[]; frameworks: ComplianceFramework[]; counts: { available: number; planned: number; wave_1: number; wave_2: number; wave_3: number } }

/** The team workspace this install sends signed "local run" reports to (never carries the token). */
export interface WorkspaceLink {
  url: string; connected: boolean;
  identity: { name: string; role: string; workspace_id: string } | null | "";
  key: { public_key: string; fingerprint: string } | null;
  projects: Record<string, string>;
}
export interface WorkspaceProject { id: string; name: string; team_id: string }
export interface SendResult { scan_id: string; source: string; install: string; owner: string; new: number; reopened: number; resolved: number; unchanged: number }
