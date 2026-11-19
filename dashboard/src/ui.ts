import classicCss from "./styles-classic.css?inline";
import softCss from "./styles-soft.css?inline";
import glassCss from "./styles-glass.css?inline";
import gapscanCss from "./styles-gapscan.css?inline";
import { uiStore, type Ui } from "./store";

const CSS: Record<Ui, string> = { gapscan: gapscanCss, soft: softCss, classic: classicCss, glassy: glassCss };

/** Swap the active stylesheet; `data-ui` on <html> lets charts follow the switch. */
export function applyUi(ui: Ui): void {
  let el = document.getElementById("gapscan-ui") as HTMLStyleElement | null;
  if (!el) {
    el = document.createElement("style");
    el.id = "gapscan-ui";
    // First in <head>, so page-specific sheets (the Control Center's) still override the base.
    document.head.prepend(el);
  }
  el.textContent = CSS[ui];
  document.documentElement.setAttribute("data-ui", ui);
}

export function initUi(): void {
  applyUi(uiStore.get());
  uiStore.subscribe(() => applyUi(uiStore.get()));
}
