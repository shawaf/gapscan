import { defineConfig } from "vitest/config";
import preact from "@preact/preset-vite";
import { viteSingleFile } from "vite-plugin-singlefile";
import { noticesPlugin } from "./third-party-notices";

// The dashboard ships as ONE html file: all JS and CSS inlined, no network requests, no CDNs,
// no web fonts (system font stack). Python injects the report JSON at the data placeholder.
export default defineConfig({
  plugins: [preact(), viteSingleFile(), noticesPlugin(__dirname)],
  build: { target: "es2022", cssCodeSplit: false, assetsInlineLimit: 100000000, chunkSizeWarningLimit: 4000 },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
});
