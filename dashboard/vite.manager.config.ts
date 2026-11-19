import { defineConfig } from "vite";
import preact from "@preact/preset-vite";
import { viteSingleFile } from "vite-plugin-singlefile";
import { noticesPlugin } from "./third-party-notices";

// The management UI also ships as ONE offline html file (no CDN, no web fonts). It is served by
// `gapscan serve` from the loopback interface and talks only to that same origin.
export default defineConfig({
  plugins: [preact(), viteSingleFile(), noticesPlugin(__dirname)],
  build: {
    target: "es2022", cssCodeSplit: false, assetsInlineLimit: 100000000, outDir: "dist-manager",
    rollupOptions: { input: "manager.html" },
  },
});
