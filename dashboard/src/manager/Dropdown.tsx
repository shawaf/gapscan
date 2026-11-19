import { useEffect, useRef, useState } from "preact/hooks";
import type { ComponentChildren } from "preact";
import { Icon } from "./icons";

/** A filter button that opens a small panel; closes on outside click or Escape. */
export function Dropdown({ label, active, children, wide }: { label: string; active?: number | string; children: ComponentChildren; wide?: boolean }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { e.stopPropagation(); setOpen(false); } };
    document.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey, true);
    return () => { document.removeEventListener("mousedown", onDown); window.removeEventListener("keydown", onKey, true); };
  }, [open]);
  const on = active !== undefined && active !== 0 && active !== "";
  return (
    <div class="dd" ref={ref}>
      <button type="button" class={`dd-btn${on ? " on" : ""}`} aria-haspopup="true" aria-expanded={open} onClick={() => setOpen(!open)}>
        {label}{on ? <b class="dd-n">{active}</b> : null}<Icon name="down" size={12} />
      </button>
      {open && <div class={`dd-panel${wide ? " wide" : ""}`} role="group" aria-label={`${label} filter`}>{children}</div>}
    </div>
  );
}

export function CheckList<T extends string>({ options, value, onChange }: { options: { id: T; label: ComponentChildren }[]; value: Set<T>; onChange: (next: Set<T>) => void }) {
  return (
    <div class="dd-list">
      {options.map((o) => (
        <label key={o.id}><input type="checkbox" checked={value.has(o.id)} onChange={() => { const n = new Set(value); if (n.has(o.id)) n.delete(o.id); else n.add(o.id); onChange(n); }} />{o.label}</label>
      ))}
    </div>
  );
}

export function PickList({ options, value, onChange, empty }: { options: string[]; value: string; onChange: (v: string) => void; empty: string }) {
  return (
    <div class="dd-list">
      <label><input type="radio" checked={value === ""} onChange={() => onChange("")} />{empty}</label>
      {options.map((o) => <label key={o}><input type="radio" checked={value === o} onChange={() => onChange(o)} /><span class="mono" style="font-size:12px">{o}</span></label>)}
    </div>
  );
}
