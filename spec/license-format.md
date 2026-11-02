# License File Format (v1 draft)

*Status: draft · Date: *

Decision context: [ADR-0004 Signed license files with Ed25519](../docs/adr/0004-signed-license-files-with-ed25519.md).

## Envelope
```
-----BEGIN LICENSEFORGE LICENSE-----
lf1.<kid>.<base64url(payload_json)>.<base64url(signature)>
-----END LICENSEFORGE LICENSE-----
```
- Signed message = the exact ASCII bytes `lf1.<kid>.<base64url(payload_json)>`. Version and kid are covered by the signature; no JSON canonicalization needed.
- `kid` sits **outside** the payload so the SDK picks the key *before* parsing any untrusted JSON.
- **Algorithm is bound to the key, never read from the file.** The SDK's trusted key set is a list of `{kid, alg, public_key}`; `alg` comes from that list. v1 supports `ed25519`; `ecdsa-p256` and `ml-dsa-65` (post-quantum, FIPS 204) can be added later by issuing new keys, without a format change and without JWT-style `alg` confusion. ([ADR-0021 Certification readiness](../docs/adr/0021-certification-readiness.md))
- PEM-ish armor so it survives email, copy-paste, ConfigMaps.

### Encoding rules
- `base64url` = RFC 4648 §5 URL-safe alphabet, **no padding**, canonical only (non-canonical trailing bits are rejected; prevents malleability).
- `kid`: 1–128 chars from `[A-Za-z0-9_:-]` (no `.`).
- Ed25519 signatures are exactly 64 bytes.
- Armor is optional for machine-to-machine transport (online leases may be sent bare). If present, everything between the BEGIN/END lines is joined after removing whitespace, so wrapped lines and CRLF are fine.
- Maximum encoded size: 64 KiB; larger input is rejected before parsing.
- Error classes (shared by all SDKs and the conformance vectors): `malformed`, `unknown_key`, `unsupported_alg`, `bad_signature`.

### Conformance vectors
`spec/vectors/lf1.json` in the main repo: fixed test keys, encoded licenses and the expected result for each. Every SDK must pass all of them ([ADR-0010 Official SDKs Go, Java, TypeScript](../docs/adr/0010-official-sdks-go-java-typescript.md)).

## Payload
```json
{
  "v": 1,
  "lid": "lic_01J...",
  "tenant": "tnt_8f2c",
  "product": "acme-db",
  "plan": "enterprise-yearly",
  "customer": { "id": "cus_01J..." },
  "iat": "2026-11-02T10:00:00Z",
  "nbf": "2026-11-02T10:00:00Z",
  "exp": "2026-12-02T10:00:00Z",
  "grace": "P7D",
  "max_offline": "P3D",
  "refresh_after": "2026-11-05T10:00:00Z",
  "updates_until": "2027-11-02T00:00:00Z",
  "bind": { "type": "machine", "fp": "sha256:..." },
  "entitlements": { "features": ["sso"], "limits": { "nodes": 10 } }
}
```

| Field | Notes |
|---|---|
| `exp` | Online: short lease (e.g. 7d), refreshed silently. Offline: whatever the vendor sells (30/90/365d). |
| `grace` | After `exp`, app keeps running in warning mode for this long, then blocks. Vendor decides what "block" means. |
| `max_offline` | Online leases: how long the app may run without a successful refresh. ([ADR-0013 License data model hardening](../docs/adr/0013-license-data-model-hardening.md)) |
| `refresh_after` | SDK shouldn't refresh before this (load shaping). |
| `updates_until` | v0.2. Builds dated after this aren't covered (maintenance/perpetual fallback). |
| `bind` | `machine` (fingerprint), `cluster` (k8s kube-system namespace UID), or `none` (site license). |
| `customer` | ID only by default; vendor may opt in to include a display name. Keeps personal data out of files copied to customer machines (GDPR data minimisation). |

## SDK verify algorithm
1. Parse armor, split on `.` into 4 parts; first must be `lf1`.
2. Look up `{alg, public_key}` by `kid` in the trusted key set embedded in the vendor's build. Unknown kid → invalid.
3. Verify signature over `lf1.<kid>.<payload_b64>` with that key's `alg`. Fail → invalid. Only now decode the payload JSON.
4. Check `v == 1`, `product` matches, `bind` matches local fingerprint.
5. Time: `iat` in the future → invalid (clock tamper); `now < nbf` → invalid; `now > exp + grace` → expired; `now > exp` → grace (warn).
6. If set, `updates_until` < app build date → invalid for this build.
7. Anti-rollback: persist max(`now`, last_seen); if clock goes backwards beyond tolerance → invalid.

That's the whole SDK core. Any language with Ed25519 (libsodium covers C/C++) can implement it in ~100 lines.
