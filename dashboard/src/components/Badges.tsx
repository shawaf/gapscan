import { SEV_GLYPH, SEV_LABEL, VERDICT_LABEL } from "../format";
import type { Severity, VerdictKey } from "../types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span class={`badge sev-${severity}`} title={SEV_LABEL[severity]}>
      <span aria-hidden="true">{SEV_GLYPH[severity]}</span>
      {SEV_LABEL[severity]}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: VerdictKey }) {
  return <span class={`badge v-${verdict}`}>{VERDICT_LABEL[verdict]}</span>;
}

export function Tags({ items, kev = false }: { items: string[]; kev?: boolean }) {
  return (
    <span>
      {kev && <span class="tag kev">CISA KEV</span>}
      {items.map((t) => <span class="tag" key={t}>{t}</span>)}
    </span>
  );
}

/** Model-written text is always labeled so readers know it is not scanner evidence. */
export function AiText({ label = "AI-generated", model, children }: { label?: string; model?: string; children: preact.ComponentChildren }) {
  return (
    <div class="ai">
      <div class="ai-label">{label}{model ? ` · ${model}` : ""}</div>
      {children}
    </div>
  );
}

export function Meter({ value, max = 100, label }: { value: number; max?: number; label: string }) {
  return (
    <div class="bar" role="meter" aria-valuenow={value} aria-valuemin={0} aria-valuemax={max} aria-label={label}>
      <span style={{ width: `${Math.max(0, Math.min(100, (value / max) * 100))}%` }} />
    </div>
  );
}
