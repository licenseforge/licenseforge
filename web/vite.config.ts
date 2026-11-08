import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { configDefaults, defineConfig } from "vitest/config";

// The Go server serves dist/ (web/embed.go). In development, run the server
// on :8080 and `npm run dev`; Vite proxies the server's routes.
const server = "http://localhost:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } },
  // No inline scripts or styles, so the strict CSP holds.
  build: { assetsInlineLimit: 0, modulePreload: { polyfill: false } },
  server: { proxy: { "/auth": server, "/api": server } },
  // jsdom: window.location for same-origin URLs, DOM for the dialog tests.
  // A zone off UTC, so code that must format in UTC is tested as such.
  // e2e/ holds the Playwright browser tests (npm run e2e, ADR-0041).
  test: { environment: "jsdom", env: { TZ: "America/Los_Angeles" }, exclude: [...configDefaults.exclude, "e2e/**"] },
});
