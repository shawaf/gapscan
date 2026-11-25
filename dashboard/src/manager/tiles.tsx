import type { ComponentChildren } from "preact";
import { Icon } from "./icons";
import type { IconName } from "./icons";
import { SEV_LABEL } from "../format";
import type { Severity } from "../types";

/** Two letters for a project, as on its sidebar tile: "payments-api" is PA. */
export function initials(name: string): string {
  const words = name.replace(/([a-z])([A-Z])/g, "$1 $2").split(/[^A-Za-z0-9]+/).filter(Boolean);
  return ((words[0]?.[0] ?? "?") + (words[1]?.[0] ?? words[0]?.[1] ?? "")).toUpperCase();
}
export function Monogram({ name }: { name: string }) { return <div class="mx-mono" aria-hidden="true">{initials(name)}</div>; }

/** The last runs as small bars, the latest one highlighted. */
export function Spark({ values, label }: { values: number[]; label: string }) {
  if (values.length < 2) return <div class="mx-spark" />;
  const max = Math.max(...values, 1);
  return <div class="mx-spark" role="img" aria-label={`${label}, last ${values.length} runs: ${values.map((v) => Math.round(v)).join(", ")}`}>{values.map((v, i) => <i key={i} style={`height:${Math.max(3, (v / max) * 24)}px`} />)}</div>;
}

export function StatTile({ icon, dot, label, value, unit, note, children }: { icon?: IconName; dot?: string; label: string; value: ComponentChildren; unit?: string; note?: ComponentChildren; children?: ComponentChildren }) {
  return (
    <section class="cc-card mx-tile" aria-label={label}>
      <p class="mx-ct">{icon ? <Icon name={icon} /> : dot ? <span class="mx-dot" style={`background:${dot}`} /> : null}{label}</p>
      <div class="mx-big">{value}{unit && <span>{unit}</span>}</div>
      {children}
      {note && <div class="mx-meta">{note}</div>}
    </section>
  );
}

export function SevTag({ level }: { level: Severity }) { return <span class={`mx-sev sev2 ${level}`}>{SEV_LABEL[level]}</span>; }

/** A run log with quiet timestamps. */
export function LogLines({ text, tail }: { text: string; tail?: number }) {
  const lines = text.trimEnd().split("\n");
  return (
    <div class="mx-log" role="log">{(tail ? lines.slice(-tail) : lines).map((l, i) => {
      const m = /^(\[?\d{2}:\d{2}:\d{2}\]?|\d{4}-\d{2}-\d{2}T\S+)\s+(.*)$/.exec(l);
      return <div key={i}>{m ? <><span class="ts">{m[1]}</span>  {m[2]}</> : l}</div>;
    })}</div>
  );
}
