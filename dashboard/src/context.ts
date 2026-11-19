import { createContext } from "preact";
import { useContext } from "preact/hooks";
import type { FindingRow, ReportData } from "./types";

export interface Ctx { data: ReportData; byId: Map<string, FindingRow> }
export const DataContext = createContext<Ctx | null>(null);
export function useData(): Ctx {
  const c = useContext(DataContext);
  if (!c) throw new Error("report data not loaded");
  return c;
}
