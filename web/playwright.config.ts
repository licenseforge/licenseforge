import { readFileSync } from "node:fs";
import { defineConfig } from "@playwright/test";

// Browser smoke tests (ADR-0041) against the environment e2e/env/up.sh
// deploys; local only, not part of `npm test` or CI.
function e2eEnv(): Record<string, string> {
  const path = process.env.E2E_ENV_FILE ?? "../e2e/env/.state/env";
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new Error(`no e2e environment: run e2e/env/up.sh first (read ${path})`);
  }
  return Object.fromEntries(text.split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
}
const env = { ...e2eEnv(), ...Object.fromEntries(Object.entries(process.env).filter(([k]) => k.startsWith("E2E_"))) } as Record<string, string>;
// The nip.io names carry the minikube IP: map them there, so no DNS is
// needed (resolvers with DNS-rebinding protection drop such answers).
const ip = /\.(\d+\.\d+\.\d+\.\d+)\.nip\.io/.exec(env.E2E_BASE_URL ?? "")?.[1];

export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: env.E2E_BASE_URL,
    // The environment's certificates come from its own local CA; this
    // browser profile is throwaway and only talks to that environment.
    ignoreHTTPSErrors: true,
    launchOptions: ip ? { args: [`--host-resolver-rules=MAP *.nip.io ${ip}`] } : {},
    trace: "retain-on-failure",
  },
  metadata: { inviteTokenFile: env.E2E_INVITE_TOKEN_FILE, tenant: env.E2E_TENANT },
});
