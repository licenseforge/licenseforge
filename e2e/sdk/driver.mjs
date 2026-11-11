// One step of a customer's app built on the TypeScript SDK, for the SDK
// journeys (sdk_test.go): node e2e/sdk/driver.mjs <step>.
//   online:  activate | refresh | deactivate | current (the saved lease alone, no request)
//            | run (the background loop until it stops, 30 s at most; forgot: the lease is gone;
//              with LF_RUN_MS, stopped after that long, then the lease it holds)
//   offline: offline-request | offline-install (LF_FILE) | offline-current | offline-deactivate
// Configured as a vendor would, from LF_* variables (sdk_test.go sets them);
// the lease, the offline state and the clock guard are kept in files between
// steps. Prints one JSON line: the claims, or the request or receipt text
// (text), or the error's code (and HTTP status online), with any warnings the
// online client recorded (a store that failed, a stored lease that didn't
// verify). With LF_K8S_STORE (configmap or secret), the lease is kept in
// that Kubernetes object (LF_K8S_NAME) through the API at LF_K8S_HOST,
// LF_K8S_PORT (CA file LF_K8S_CA, namespace LF_K8S_NAMESPACE, token
// LF_K8S_TOKEN) instead of a file. Needs sdk/ts built.
import { readFileSync } from "node:fs";
import {
  Client, ClockError, compute, FileClockStore, FileLeaseStore, Guard, KubernetesConfigMapStore, KubernetesSecretStore, LicenseError, OfflineClient, OfflineError, OnlineError, parseKeySet,
} from "../../sdk/ts/dist/src/index.js";

const env = (k) => process.env[k] ?? "";
const op = process.argv[2];
const fingerprint = await compute(env("LF_TENANT_ID"), env("LF_PRODUCT"), { override: () => env("LF_MACHINE") });
const keys = parseKeySet(new TextEncoder().encode(env("LF_KEYS")));
const claimsOf = ({ claims, status }) => {
  const e = claims.entitlements;
  return { iat: claims.issuedAt.toISOString(), lid: claims.licenseId, tenant: claims.tenant, product: claims.product, plan: claims.plan, status, sso: e.hasFeature("sso"), nope: e.hasFeature("nope"), seats: e.limit("seats") };
};

function leaseStore() {
  const kind = env("LF_K8S_STORE");
  if (!kind) return new FileLeaseStore(env("LF_STORE"));
  const api = { host: env("LF_K8S_HOST"), port: Number(env("LF_K8S_PORT")), ca: readFileSync(env("LF_K8S_CA")), namespace: env("LF_K8S_NAMESPACE"), token: () => env("LF_K8S_TOKEN") };
  const opts = { name: env("LF_K8S_NAME"), api };
  if (kind === "secret") return new KubernetesSecretStore(opts);
  if (kind === "configmap") return new KubernetesConfigMapStore(opts);
  throw new Error(`LF_K8S_STORE ${kind}: configmap or secret`);
}

let out;
if (op.startsWith("offline-")) {
  const client = new OfflineClient({
    tenantId: env("LF_TENANT_ID"),
    product: env("LF_PRODUCT"),
    licenseKey: env("LF_LICENSE_KEY"),
    keys,
    fingerprint,
    hostname: env("LF_MACHINE"),
    appVersion: "1.0.0",
    store: new FileClockStore(env("LF_STORE") + ".offline"),
    clock: new Guard(new FileClockStore(env("LF_STORE") + ".clock"), env("LF_LICENSE_KEY")),
  });
  try {
    if (op === "offline-request") out = { ok: true, text: client.request() };
    else if (op === "offline-install") out = { ok: true, ...claimsOf(client.install(env("LF_FILE"))) };
    else if (op === "offline-current") out = { ok: true, ...claimsOf(client.current()) };
    else if (op === "offline-deactivate") out = { ok: true, text: client.deactivate() };
    else throw new Error(`unknown step ${op}`);
  } catch (e) {
    if (!(e instanceof OfflineError || e instanceof LicenseError || e instanceof ClockError)) throw e;
    out = { ok: false, code: e.code, detail: e.message };
  }
  out.warnings = [];
} else {
  const client = await Client.create({
    baseURL: env("LF_BASE_URL"),
    tenantId: env("LF_TENANT_ID"),
    product: env("LF_PRODUCT"),
    licenseKey: env("LF_LICENSE_KEY"),
    keys,
    fingerprint,
    hostname: env("LF_MACHINE"),
    appVersion: "1.0.0",
    store: leaseStore(),
    maxAttempts: 1,
  });
  try {
    if (op === "activate") await client.activate();
    else if (op === "refresh") await client.refresh();
    else if (op === "deactivate") await client.deactivate();
    else if (op === "run") {
      const forMs = Number(env("LF_RUN_MS") || 0);
      const stop = AbortSignal.timeout(forMs || 30_000);
      try {
        await client.run(stop); // only ever rejects
      } catch (e) {
        if (!(forMs && stop.aborted)) throw e;
      }
    }
    else if (op !== "current") throw new Error(`unknown step ${op}`);
    out = { ok: true, ...(op === "deactivate" ? {} : claimsOf(client.current())) };
  } catch (e) {
    if (!(e instanceof OnlineError)) throw e;
    out = { ok: false, code: e.code, http: e.status, detail: `${e.message}${e.cause ? `: ${e.cause}` : ""}` };
    if (op === "run") {
      try {
        client.current();
        out.forgot = false;
      } catch (x) {
        out.forgot = x instanceof OnlineError && x.code === "no_lease";
      }
    }
  }
  out.warnings = client.takeWarnings().map(String);
}
console.log(JSON.stringify(out));
