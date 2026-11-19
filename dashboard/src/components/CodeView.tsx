import hljs from "highlight.js/lib/core";
import python from "highlight.js/lib/languages/python";
import javascript from "highlight.js/lib/languages/javascript";
import typescript from "highlight.js/lib/languages/typescript";
import java from "highlight.js/lib/languages/java";
import kotlin from "highlight.js/lib/languages/kotlin";
import go from "highlight.js/lib/languages/go";
import swift from "highlight.js/lib/languages/swift";
import dart from "highlight.js/lib/languages/dart";
import yaml from "highlight.js/lib/languages/yaml";
import json from "highlight.js/lib/languages/json";
import bash from "highlight.js/lib/languages/bash";
import xml from "highlight.js/lib/languages/xml";
import dockerfile from "highlight.js/lib/languages/dockerfile";

// Only the languages GapScan scans are bundled, keeping the single HTML file small.
const LANGS = { python, javascript, typescript, java, kotlin, go, swift, dart, yaml, json, bash, xml, dockerfile };
for (const [name, def] of Object.entries(LANGS)) hljs.registerLanguage(name, def);

export function highlightLine(text: string, language: string | null): string {
  if (!language || !hljs.getLanguage(language)) return escapeHtml(text);
  try { return hljs.highlight(text, { language, ignoreIllegals: true }).value; } catch { return escapeHtml(text); }
}

export function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** Source lines with the flagged ones marked. highlight.js escapes the code it renders, so the
 *  HTML below only ever contains its own <span> tokens around escaped text. */
export function CodeView({ lines, language }: { lines: [number, string, boolean][]; language: string | null }) {
  if (!lines.length) return <div class="muted">No source context available for this finding.</div>;
  return (
    <pre class="code" tabIndex={0} aria-label="Source code; flagged lines are highlighted">
      {lines.map(([n, text, flagged], i) => (
        <div class={`cl${flagged ? " flag" : ""}`} key={`${n}-${i}`}>
          <span class="ln">{n || ""}</span>
          <span class="tx" dangerouslySetInnerHTML={{ __html: highlightLine(text, language) || "&nbsp;" }} />
          {flagged && <span class="sr-only"> (flagged line)</span>}
        </div>
      ))}
    </pre>
  );
}
