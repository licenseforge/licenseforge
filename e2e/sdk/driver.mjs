// One step of a customer's app built on the TypeScript SDK, for the SDK
// journeys (sdk_test.go): node e2e/sdk/driver.mjs <step>.
//   online:  activate | refresh | deactivate | current (the saved lease alone, no request)
//   offline: offline-request | offline-install (LF_FILE) | offline-current | offline-deactivate
// Configured as a vendor would, from LF_* variables (sdk_test.go sets them);
// the lease, the offline state and the clock guard are kept in files between
// steps. Prints one JSON line: the claims, or the request or receipt text
// (text), or the error's code (and HTTP status online), with any warnings the
// online client recorded (a store that failed, a stored lease that didn't
// verify). Needs sdk/ts built.
import { Client, compute, FileClockStore, FileLeaseStore, Guard, LicenseError, OfflineClient, OfflineError, OnlineError, parseKeySet } from "../../sdk/ts/dist/src/index.js";

const env = (k) => process.env[k] ?? "";
const op = process.argv[2];
const fingerprint = await compute(env("LF_TENANT_ID"), env("LF_PRODUCT"), { override: () => env("LF_MACHINE") });
const keys = parseKeySet(new TextEncoder().encode(env("LF_KEYS")));
const claimsOf = ({ claims, status }) => {
  const e = claims.entitlements;
  return { lid: claims.licenseId, tenant: claims.tenant, product: claims.product, plan: claims.plan, status, sso: e.hasFeature("sso"), nope: e.hasFeature("nope"), seats: e.limit("seats") };
};

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
    if (!(e instanceof OfflineError || e instanceof LicenseError)) throw e;
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
    store: new FileLeaseStore(env("LF_STORE")),
    maxAttempts: 1,
  });
  try {
    if (op === "activate") await client.activate();
    else if (op === "refresh") await client.refresh();
    else if (op === "deactivate") await client.deactivate();
    else if (op !== "current") throw new Error(`unknown step ${op}`);
    out = { ok: true, ...(op === "deactivate" ? {} : claimsOf(client.current())) };
  } catch (e) {
    if (!(e instanceof OnlineError)) throw e;
    out = { ok: false, code: e.code, http: e.status, detail: `${e.message}${e.cause ? `: ${e.cause}` : ""}` };
  }
  out.warnings = client.takeWarnings().map(String);
}
console.log(JSON.stringify(out));
