import type { JSX } from "preact";

// Inline SVG on a 16 px grid, 1.5 px stroke, round caps, drawn in the text color. An icon never stands
// alone: it always has a label or an accessible name beside it.
const PATHS: Record<string, string> = {
  overview: "M2 11a6 6 0 0 1 12 0M8 11l3-4",
  runs: "M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12zM6.5 5.5l4 2.5-4 2.5z",
  findings: "M5 4h9M5 8h9M5 12h9M2 4h.01M2 8h.01M2 12h.01",
  owasp: "M2.5 2.5h4v4h-4zM9.5 2.5h4v4h-4zM2.5 9.5h4v4h-4zM9.5 9.5h4v4h-4z",
  asvs: "M2 4l1.5 1.5L6 3M2 9l1.5 1.5L6 8M8 4.5h6M8 9.5h6M2 13.5h12",
  compliance: "M8 1.8l5 2v4c0 3.2-2.2 5.4-5 6.4-2.8-1-5-3.2-5-6.4v-4zM5.8 8l1.6 1.6L10.4 6.4",
  law: "M8 2v12M4.5 14h7M3 4.5h10M3 4.5L1.5 9a1.5 1.5 0 0 0 3 0zM13 4.5L11.5 9a1.5 1.5 0 0 0 3 0z",
  person: "M8 7.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zM3 14c.4-2.8 2.4-4.5 5-4.5s4.6 1.7 5 4.5",
  globe: "M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12zM2 8h12M8 2c1.7 1.8 2.5 3.8 2.5 6S9.7 12.2 8 14M8 2C6.3 3.8 5.5 5.8 5.5 8s.8 4.2 2.5 6",
  deps: "M8 1.8l5.5 3v6.4L8 14.2l-5.5-3V4.8zM2.5 4.8L8 7.8l5.5-3M8 7.8v6.4",
  folder: "M2 4.5a1 1 0 011-1h3l1.5 1.5H13a1 1 0 011 1v6a1 1 0 01-1 1H3a1 1 0 01-1-1z",
  home: "M2.5 7L8 2.5 13.5 7M4 6v7h8V6",
  secrets: "M6 8.5a3 3 0 1 1 0-.01M8.5 8.5H14M12 8.5v2.5M10 8.5v1.5",
  hotspots: "M2.5 2.5h11v11h-11zM2.5 8h11M8 2.5v11",
  compare: "M5 3v10M5 13l-2.5-2.5M5 13l2.5-2.5M11 13V3M11 3L8.5 5.5M11 3l2.5 2.5",
  settings: "M2 4.5h7M12 4.5h2M2 11.5h2M7 11.5h7M10.5 3v3M5.5 10v3",
  health: "M1.5 8h3l2-4.5 3 9 2-4.5h3",
  setup: "M8 2v8M4.5 7L8 10.5 11.5 7M3 13.5h10",
  lock: "M4 7.5h8v6H4zM5.5 7.5V5.5a2.5 2.5 0 0 1 5 0v2",
  search: "M7 12a5 5 0 1 1 0-10 5 5 0 0 1 0 10zM11 11l3.2 3.2",
  plus: "M8 3v10M3 8h10",
  chevron: "M5 6.5l3-3 3 3M5 9.5l3 3 3-3",
  down: "M4.5 6.5L8 10l3.5-3.5",
  check: "M3 8.5l3.2 3L13 4.5",
  x: "M4 4l8 8M12 4l-8 8",
  info: "M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12zM8 7.2V11M8 5h.01",
  warn: "M8 2.2L14.5 13.5h-13zM8 6.5v3M8 11.5h.01",
  play: "M5 3.5l8 4.5-8 4.5z",
  stop: "M4 4h8v8H4z",
  external: "M9 3h4v4M13 3L7.5 8.5M12 9.5V13H3V4h3.5",
  doc: "M4 1.8h5.5L13 5.3V14.2H4zM9.5 1.8V5.5H13",
  clock: "M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12zM8 4.8V8l2.2 1.4",
  trash: "M3 4.5h10M6.5 4.5V2.8h3v1.7M4.5 4.5l.6 8.7h5.8l.6-8.7",
  pause: "M5 3.5v9M11 3.5v9",
  sun: "M8 10.8a2.8 2.8 0 1 0 0-5.6 2.8 2.8 0 0 0 0 5.6zM8 1.5v1.3M8 13.2v1.3M1.5 8h1.3M13.2 8h1.3M3.4 3.4l.9.9M11.7 11.7l.9.9M3.4 12.6l.9-.9M11.7 4.3l.9-.9",
  moon: "M13.5 9.6A5.8 5.8 0 0 1 6.4 2.5 5.8 5.8 0 1 0 13.5 9.6z",
  monitor: "M2 3h12v8H2zM6 14h4M8 11v3",
  help: "M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12zM6.2 6.3a1.9 1.9 0 1 1 2.6 1.8c-.5.3-.8.7-.8 1.3M8 11.6h.01",
};

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 16, label }: { name: IconName; size?: number; label?: string }): JSX.Element {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"
      stroke-linecap="round" stroke-linejoin="round" aria-hidden={label ? undefined : "true"} role={label ? "img" : undefined} aria-label={label}>
      <path d={PATHS[name]} />
    </svg>
  );
}

/** Filled 12 px severity shapes (a distinct shape per level). */
export function SevGlyph({ level }: { level: string }): JSX.Element {
  const shapes: Record<string, string> = {
    critical: "M6 0.8L11.2 6 6 11.2 0.8 6z", high: "M6 1L11.5 10.8H0.5z", medium: "M1.5 1.5h9v9h-9z",
  };
  if (shapes[level]) return <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor" aria-hidden="true"><path d={shapes[level]} /></svg>;
  if (level === "info") return <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="6" cy="6" r="4" /></svg>;
  return <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor" aria-hidden="true"><circle cx="6" cy="6" r="5" /></svg>;
}

export function Spinner({ size = 14 }: { size?: number }): JSX.Element {
  return (
    <svg class="spin" width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
      <path d="M8 2a6 6 0 1 0 6 6" />
    </svg>
  );
}
