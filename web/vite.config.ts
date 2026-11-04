import path from "node:path";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The Go server serves dist/ (web/embed.go). In development, run the server
// on :8080 and `npm run dev`; Vite proxies the server's routes.
const server = "http://localhost:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } },
  // No inline scripts or styles, so the strict CSP holds.
  build: { assetsInlineLimit: 0, modulePreload: { polyfill: false } },
  server: { proxy: { "/auth": server, "/api": server } },
  test: { environment: "jsdom" }, // window.location for same-origin URLs, DOM for the dialog test
});
