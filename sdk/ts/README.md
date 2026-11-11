# LicenseForge SDK for Node.js

Verifies LicenseForge license files (`lf1`, [spec](../../spec/license-format.md)) in a Node.js service, offline: the envelope, the Ed25519 signature against keys built into your app, the claims and the claim checks. Server-side only, Node 22 or later, with no runtime dependencies (ADR-0010).

Status: alpha. `npm install @licenseforge/sdk@next` once `0.1.0-alpha.1` is out; releases carry npm provenance ([verifying releases](../../docs/verifying-releases.md#typescript-sdk-npm)). It passes the shared conformance vectors (`spec/vectors/lf1.json`, `lf1-claims.json`, `fingerprint.json`, `offline.json`).

```ts
import { readFileSync } from "node:fs";
import { open, parseKeySet, LicenseError } from "@licenseforge/sdk";

// Your tenant's trusted key set, as the dashboard shows it (Settings →
// Signing keys → JSON), shipped with your build.
const keys = parseKeySet(readFileSync(new URL("./licenseforge-keys.json", import.meta.url)));

try {
  const { claims, status } = open(licenseText, keys, { now: new Date(), product: "acme-db", fingerprint });
  if (status === "grace") warn(`License expired ${claims.expires?.toISOString()}: renew it.`);
  if (!claims.entitlements.allows("nodes", nodes.length + 1)) refuse("node limit reached");
} catch (e) {
  if (e instanceof LicenseError) refuse(e.code); // malformed, bad_signature, expired, …
  else throw e;
}
```

- `parseKeySet(json)` reads the trusted key set under the spec's rules (exact fields, canonical base64url). A malformed set is `invalid_key_set`; an unknown alg, a duplicate kid or a weak key loads and surfaces in `verify`.
- `verify(license, keys)` checks the envelope and the signature, and returns the payload and key ID.
- `parseClaims(payload)` applies the strict encoding rules. `check(claims, options)` runs the claim checks in the spec's order.
- `open` does all three. `LicenseError.code` is the spec's class.
- `Entitlements`: `hasFeature(key)`, `limit(key)` (`UNLIMITED` is -1, absent is 0) and `allows(key, total)`.
- `compute(tenant, product, options)` / `forLicense(claims, options)` give this machine's fingerprint (ADR-0017), for a bound license's `fingerprint` check option. The sources, first match wins:
  1. your `override` function;
  2. `LICENSEFORGE_FINGERPRINT`, only if you set `allowEnvOverride`;
  3. Kubernetes, the `kube-system` namespace UID (the pod's service account needs `get` on that namespace);
  4. the OS machine ID: `/etc/machine-id` (refused on tmpfs, and in containers unless the host's file is mounted in), `MachineGuid` or `IOPlatformUUID`.

  A `FingerprintError` says why there is none: `no_fingerprint`, `transient` (retry), `invalid` or `failed`. On Windows the ID is read with `%SystemRoot%\System32\reg.exe`; whoever controls the app's environment controls that path (as with `NODE_OPTIONS`).
- Offline activation (ADR-0043): `new OfflineClient({ tenantId, product, licenseKey, keys, fingerprint, store: new FileClockStore(statePath), clock: new Guard(new FileClockStore(clockPath), licenseKey) })` runs a license on an air-gapped machine, as the Go SDK's `offline` package:
  - `request()` writes the activation request to carry to the vendor (it contains the license key);
  - `install(file)` verifies the vendor's answer and installs it, refusing a file this machine returned (`returned`), an older file of the installed license (`older_file`) and another license's while one is installed (`other_license`);
  - `current()` before each license check: the installed file's claims and status;
  - `deactivate()` deletes the file, remembers it, and returns the deactivation receipt for the vendor, once that is saved.

  Give `store` a `FileClockStore` of its own, never the clock guard's (`foreign_state`), and a clock guard: no server time comes in offline. A file whose iat is ahead of the machine's clock raises the guard to it, within the guard's tolerance (`clock_not_saved` if the guard can't be saved). FileClockStore has no cross-process lock: two processes changing the state at once can lose a change, as deleting it would (ADR-0014).

  The formats underneath:
  - `encodeRequest(request)` writes the `lfreq1` request an air-gapped machine hands over; `parseRequest` reads one.
  - `encodeReceipt` and `parseReceipt` do the same for the `lfrcpt1` deactivation receipt, and `fileSHA256(file)` is the receipt's hash of the deleted file.
  - `offlineSHA256` identifies a request or receipt, ignoring changed line endings.
  - All refuse unknown fields; the encoders check their own output.
- Clock guard (ADR-0018): `new Guard(store, licenseKey).now()` gives the time to check licenses with. It never moves backwards and refuses a clock turned back beyond the tolerance (`ClockError` `rollback`). `observe` and `reset` raise or set the mark from verified times. Use `FileClockStore` for offline licenses; `MemoryClockStore` resets on restart.
- Online client (ADR-0034): `await Client.create(config)`, then:
  - `activate()` once per machine, with one idempotency key across retries;
  - `refresh()` to renew the lease;
  - `current()` before each license check;
  - `run(signal, onError)` in the background, which refreshes from `refresh_after` on;
  - `deactivate()` to free the seat.

  Store the lease with `store`:
  - `FileLeaseStore(path)`;
  - `KubernetesConfigMapStore({ name })`, so every replica of a cluster-bound app shares one lease. RBAC: get and update on that ConfigMap by name; create it beforehand;
  - `KubernetesSecretStore({ name })`, the same on a Secret.

  Every lease is verified (signature, product, tenant, this machine, binding) before it is used or stored. Older leases are refused as replays. The client checks with max(local, server time) and never trusts the HTTP Date header. `OnlineError.code` carries the API's stable codes.

  A server behind a private CA: start Node with `NODE_EXTRA_CA_CERTS=/path/ca.pem`. The client uses Node's `fetch`, which then trusts that CA as well as Node's bundled CAs (for a CA installed in the operating system instead, see Node's `--use-system-ca` option).

Development: `npm ci && npm test`.
