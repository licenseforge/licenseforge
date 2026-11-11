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
// LF_K8S_TOKEN, or LF_K8S_TOKEN_FILE read at every request, as a projected
// token is) instead of a file. LF_CA: the server's private CA (PEM file),
// given to the client's ca option. run also prints the codes of the errors
// it reported and went on from (errors); with LF_READY, the file it creates
// once the client has loaded the stored lease. Without LF_MACHINE the SDK
// finds the fingerprint itself (in a pod: the cluster's), and without
// LF_K8S_HOST a Kubernetes store uses the pod's service account; online
// steps print the fingerprint's binding. Needs sdk/ts built.
import { readFileSync, writeFileSync } from "node:fs";
import {
  Client, ClockError, compute, FileClockStore, FileLeaseStore, Guard, KubernetesConfigMapStore, KubernetesSecretStore, LicenseError, OfflineClient, OfflineError, OnlineError, parseKeySet,
} from "../../sdk/ts/dist/src/index.js";

const env = (k) => process.env[k] ?? "";
const op = process.argv[2];
const fingerprint = await compute(env("LF_TENANT_ID"), env("LF_PRODUCT"), env("LF_MACHINE") ? { override: () => env("LF_MACHINE") } : {});
const keys = parseKeySet(new TextEncoder().encode(env("LF_KEYS")));
const claimsOf = ({ claims, status }) => {
  const e = claims.entitlements;
  return { iat: claims.issuedAt.toISOString(), lid: claims.licenseId, tenant: claims.tenant, product: claims.product, plan: claims.plan, status, sso: e.hasFeature("sso"), nope: e.hasFeature("nope"), seats: e.limit("seats") };
};

function leaseStore() {
  const kind = env("LF_K8S_STORE");
  if (!kind) return new FileLeaseStore(env("LF_STORE"));
  const api = !env("LF_K8S_HOST") ? undefined : { host: env("LF_K8S_HOST"), port: Number(env("LF_K8S_PORT")), ca: readFileSync(env("LF_K8S_CA")), namespace: env("LF_K8S_NAMESPACE"), token: () => (env("LF_K8S_TOKEN_FILE") ? readFileSync(env("LF_K8S_TOKEN_FILE"), "utf8").trim() : env("LF_K8S_TOKEN")) };
  const opts = { name: env("LF_K8S_NAME"), ...(api && { api }) };
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
    ...(env("LF_CA") && { ca: readFileSync(env("LF_CA")) }),
  });
  if (env("LF_READY")) writeFileSync(env("LF_READY"), "");
  const errors = [];
  try {
    if (op === "activate") await client.activate();
    else if (op === "refresh") await client.refresh();
    else if (op === "deactivate") await client.deactivate();
    else if (op === "run") {
      const forMs = Number(env("LF_RUN_MS") || 0);
      const stop = AbortSignal.timeout(forMs || 30_000);
      try {
        await client.run(stop, (e) => errors.push(e instanceof OnlineError ? e.code : String(e))); // only ever rejects
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
  if (op === "run") out.errors = errors;
  out.binding = fingerprint.binding;
  out.warnings = client.takeWarnings().map(String);
}
console.log(JSON.stringify(out));
