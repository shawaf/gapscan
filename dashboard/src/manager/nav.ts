export interface NavItem { id: string; label: string; icon: string; key?: number; group?: string }

// Grouped by the gap model (ROADMAP 1.2): the gaps themselves, the targets they are measured
// against, and the evidence behind them. Route ids stay as they were; a gap is a finding in the engine.
export const MAIN_NAV: NavItem[] = [
  { id: "overview", label: "Overview", icon: "overview", key: 1, group: "Gaps" },
  { id: "runs", label: "Runs", icon: "runs", key: 2, group: "Gaps" },
  { id: "findings", label: "Gaps", icon: "findings", key: 3, group: "Gaps" },
  { id: "targets", label: "All targets", icon: "asvs", key: 4, group: "Targets" },
  { id: "asvs", label: "ASVS coverage", icon: "asvs", key: 5, group: "Targets" },
  { id: "owasp", label: "OWASP Top 10", icon: "owasp", key: 6, group: "Targets" },
  { id: "compliance", label: "Compliance frameworks", icon: "compliance", group: "Targets" },
  { id: "deps", label: "Dependencies", icon: "deps", key: 7, group: "Evidence" },
  { id: "secrets", label: "Secrets and Config", icon: "secrets", key: 8, group: "Evidence" },
  { id: "hotspots", label: "Hotspots", icon: "hotspots", key: 9, group: "Evidence" },
  { id: "compare", label: "Compare", icon: "compare", group: "Evidence" },
];
export const SYSTEM_NAV: NavItem[] = [
  { id: "settings", label: "Settings", icon: "settings" },
  { id: "setup", label: "Setup", icon: "setup" },
  { id: "health", label: "System Health", icon: "health" },
];
export const ALL_NAV = [...MAIN_NAV, ...SYSTEM_NAV];
