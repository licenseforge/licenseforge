// One step of a customer's app built on the TypeScript SDK, for the SDK
// journeys (sdk_test.go): node e2e/sdk/driver.mjs activate|refresh|deactivate|current
// (current: the saved lease alone, no request).
// Configured as a vendor would, from LF_* variables (sdk_test.go sets them);
// the lease is kept in a file between steps. Prints one JSON line: the
// verified lease's claims, or the error code. Needs sdk/ts built (npm run build).
import { Client, compute, FileLeaseStore, OnlineError, parseKeySet } from "../../sdk/ts/dist/src/index.js";

const env = (k) => process.env[k] ?? "";
const op = process.argv[2];
try {
  const fingerprint = await compute(env("LF_TENANT_ID"), env("LF_PRODUCT"), { override: () => env("LF_MACHINE") });
  const client = await Client.create({
    baseURL: env("LF_BASE_URL"),
    tenantId: env("LF_TENANT_ID"),
    product: env("LF_PRODUCT"),
    licenseKey: env("LF_LICENSE_KEY"),
    keys: parseKeySet(new TextEncoder().encode(env("LF_KEYS"))),
    fingerprint,
    hostname: env("LF_MACHINE"),
    appVersion: "1.0.0",
    store: new FileLeaseStore(env("LF_STORE")),
    maxAttempts: 1,
  });
  if (op === "activate") await client.activate();
  else if (op === "refresh") await client.refresh();
  else if (op === "deactivate") {
    await client.deactivate();
    console.log(JSON.stringify({ ok: true }));
    process.exit(0);
  } else if (op !== "current") throw new Error(`unknown step ${op}`);
  const { claims, status } = client.current();
  const e = claims.entitlements;
  console.log(JSON.stringify({ ok: true, lid: claims.licenseId, tenant: claims.tenant, product: claims.product, plan: claims.plan, status, sso: e.hasFeature("sso"), seats: e.limit("seats") }));
} catch (e) {
  if (!(e instanceof OnlineError)) throw e;
  console.log(JSON.stringify({ ok: false, code: e.code, detail: `${e.message}${e.cause ? `: ${e.cause}` : ""}` }));
}
