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
- **Whitespace** means exactly SP, HT, CR, LF (`0x20 0x09 0x0D 0x0A`). It is ignored anywhere (around and inside the token, armored or bare), so wrapped lines, CRLF and trailing newlines are fine. Any other character (NBSP, U+2028, …) is not whitespace and makes the license `malformed`.
- A single leading UTF-8 BOM (`EF BB BF`) is ignored.
- Armor is optional (online leases may be sent bare). If the input starts with the BEGIN marker it must end with the END marker; markers may be on the same line as the token.
- Maximum size: 64 KiB (65,536 **bytes** of the raw UTF-8 input, not characters); larger input is `malformed` before any parsing.
- The payload part must be non-empty.
- Ed25519 verification must be strict: non-canonical `S` (S ≥ L) is rejected (`bad_signature`).
- Error classes (shared by all SDKs and the conformance vectors): `malformed`, `unknown_key`, `unsupported_alg`, `bad_signature`. A trusted key set with duplicate `kid`s or a key of the wrong length is a configuration error, `invalid_key_set`, reported when that key is used.
- A trusted key with an unknown `alg` is not a configuration error: it surfaces as `unsupported_alg` when a license uses that `kid`.

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
Steps run in this order; the first failing step decides the error class.
1. Input larger than 64 KiB → `malformed`.
2. Drop one leading BOM; trim whitespace at both ends. If it starts with the BEGIN marker, it must end with the END marker (else `malformed`); keep what is between. Remove all whitespace.
3. Split on `.`: exactly 4 parts, first is `lf1`, `kid` matches its pattern, payload part non-empty, payload and signature parts are canonical base64url → else `malformed`.
4. Look up `kid` in the trusted key set embedded in the vendor's build → `unknown_key` if absent; `invalid_key_set` if the `kid` appears more than once.
5. Key's `alg` not supported → `unsupported_alg`.
6. Key length wrong for `alg` → `invalid_key_set`. Signature length wrong for `alg` → `malformed`. Verify the signature over the ASCII bytes `lf1.<kid>.<payload_b64>` → `bad_signature` on failure.
7. Only now parse the payload JSON.
8. Check `v == 1`, `product` matches, `bind` matches local fingerprint.
9. Time: `iat` in the future → invalid (clock tamper); `now < nbf` → invalid; `now > exp + grace` → expired; `now > exp` → grace (warn).
10. If set, `updates_until` < app build date → invalid for this build.
11. Anti-rollback: persist max(`now`, last_seen); if clock goes backwards beyond tolerance → invalid.

That's the whole SDK core. Any language with Ed25519 (libsodium covers C/C++) can implement it in ~100 lines.
