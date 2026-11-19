import type { ReportData } from "./types";

export const SCHEMA_VERSION = 1;

export function parseEmbedded(text: string): ReportData {
  const data = JSON.parse(text) as ReportData;
  if (data.meta?.report_schema_version !== SCHEMA_VERSION) {
    throw new Error(`Unsupported report schema version ${String(data.meta?.report_schema_version)}`);
  }
  return data;
}

/** Report data embedded by `gapscan report` (a JSON <script> element); in `vite dev` a fixture. */
export async function loadData(): Promise<ReportData> {
  const el = document.getElementById("gapscan-data");
  if (el?.textContent) return parseEmbedded(el.textContent);
  if (import.meta.env.DEV) {
    const mod = await import("../fixtures/report.json");
    return mod.default as unknown as ReportData;
  }
  throw new Error("No report data embedded in this page.");
}
