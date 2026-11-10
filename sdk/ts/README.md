# LicenseForge SDK for Node.js

Verifies LicenseForge license files (`lf1`, [spec](../../spec/license-format.md)) in a Node.js service, offline: the envelope, the Ed25519 signature against keys built into your app, the claims and the claim checks. Server-side only, Node 22 or later, with no runtime dependencies (ADR-0010).

Status: in progress, not published yet. It passes the shared conformance vectors (`spec/vectors/lf1.json`, `lf1-claims.json`). Next: fingerprints, offline requests and receipts, and the online client.

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

Development: `npm ci && npm test`.
