import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { Plugin } from "vite";

// Libraries inlined into the single-file pages. Their licenses (MIT, Apache-2.0, BSD-3-Clause, 0BSD)
// require the copyright and license text to travel with every copy, and each report HTML file is a
// copy. The texts are read from each package's own files at build time, never typed by hand.
const PACKAGES = ["preact", "echarts", "zrender", "highlight.js", "tslib"];
const LICENSE_FILE = /^(licen[cs]e|notice|copying)(\.(md|txt))?$/i;

function packageNotices(root: string, name: string): string {
  const dir = join(root, "node_modules", name);
  if (!existsSync(dir)) return "";
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf-8")) as { version: string; license?: string };
  const parts = [`=== ${name} ${pkg.version} (${pkg.license ?? "see below"}) ===`];
  for (const f of readdirSync(dir).filter((f) => LICENSE_FILE.test(f)).sort()) {
    parts.push(`--- ${f} ---`, readFileSync(join(dir, f), "utf-8").trim());
  }
  const extra = join(dir, "licenses"); // e.g. echarts' licenses of code it bundles itself
  if (existsSync(extra)) {
    for (const f of readdirSync(extra).sort()) parts.push(`--- licenses/${f} ---`, readFileSync(join(extra, f), "utf-8").trim());
  }
  return parts.join("\n\n");
}

export function thirdPartyNotices(root: string): string {
  const body = PACKAGES.map((p) => packageNotices(root, p)).filter(Boolean).join("\n\n");
  // Some license files use Windows line endings; normalize so the built templates are stable in git.
  return `Third-party software inlined in this file\n\n${body}\n`.replace(/\r\n?/g, "\n");
}

/** Embeds the notices in the page as a non-executing text block (also safe if a text contains "</"). */
export function noticesPlugin(root: string): Plugin {
  return {
    name: "gapscan-third-party-notices",
    transformIndexHtml(html) {
      const text = thirdPartyNotices(root).replace(/<\//g, "<\\/");
      return html.replace("</body>", `<script type="text/plain" id="third-party-notices">\n${text}</script>\n</body>`);
    },
  };
}
