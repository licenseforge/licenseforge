# ADR-0026 Signing key lifecycle

*Status: accepted · Date: 2026-11-02*

## Context
Each tenant signs its licenses and leases with its own Ed25519 keys ([ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md), [ADR-0009 Multi-tenancy](0009-multi-tenancy.md)). Vendors embed the trusted public keys (`kid`, `alg`, key) in their builds ([License File Format](../../spec/license-format.md)). So a new key is only useful once vendor builds trust it: if the server switched to a new key at once, every deployed build would reject the next lease refresh, an outage for all of the vendor's customers. Architecture Overview fixes the custody model for v0.1 (private keys AES-GCM-encrypted with the master keyring, behind a `Signer` interface); the lifecycle wasn't decided.

## Decision
- **kid = key row ID** `sk_<26 base32>`: globally unique, valid under the spec's kid pattern, so keys of different tenants never collide in a vendor's trusted set.
- **Algorithm**: `ed25519` only in v0.1 ([ADR-0024 HIPAA, NIST and FedRAMP readiness from day 1](0024-hipaa-nist-and-fedramp-readiness-from-day-1.md)); the column exists so ECDSA P-256 / ML-DSA keys can be added later.
- **States**: `pending` → `active` → `retired`.
  - `pending`: generated, public key shown so vendors can add it to their trusted set and ship builds. Never signs.
  - `active`: signs everything new. **At most one per tenant** (partial unique index), exactly one in normal operation (none after a compromise until a pending key is promoted); at most one `pending`.
  - `retired`: never signs again. **The private key is erased from the live table** (ciphertext set to NULL); the public key stays for listing and so vendors can verify old files. This is not full destruction: the old ciphertext survives in dead tuples, WAL archives and backups, and decrypts with the master keyring. It is gone for good only after a master-key rotation (old key removed from the keyring) and backup expiry. Real destruction comes with KMS/HSM custody (v0.4), where the key is destroyed in the KMS.
- **First key ever** of a tenant is created `active` (no build trusts anything yet). A tenant that has had keys but none is active (e.g. after a compromise) gets a `pending` key like any rotation: activating a key no build trusts would break every deployed build.
- **Rotation** = create `pending`, vendor ships builds trusting it, then **promote**: in one transaction the old `active` becomes `retired` and the `pending` one `active`. The dashboard warns that builds not trusting the new kid will reject new leases. **Discard** retires a pending key that never signed (rotation abandoned, or the pending key leaked).
- **Transitions** (never back from retired, never active → pending) are enforced by the signing service, like other rules that need the old row; the database enforces the states themselves (CHECKs, one active and one pending key per tenant, no DELETE, immutable kid/alg/public key/tenant). The platform pool may only read keys and rewrap private keys after a master-key rotation.
- **Compromise**: same steps without waiting; old builds then fail closed on refresh, which is the safe failure. Offline files signed with the old key stay valid in builds that still trust it: documented, not fixable server-side.
- **Private key** = the 32-byte Ed25519 seed, encrypted with the keyring ([ADR-0025 License key storage and encryption at rest](0025-license-key-storage-and-encryption-at-rest.md)) bound to purpose `signing_key`, tenant and kid, so a ciphertext copied to another row or tenant doesn't decrypt.
- **`Signer`**: `Sign(ctx, tenant, kid, msg)` and `Public(ctx, tenant, kid)`. Sign refuses keys that aren't `active` and messages that aren't `lf1.<kid>.…` for that kid (no general signing oracle, domain-separated from anything else). Callers read the active kid first, build the message, then sign. Sign holds a share lock on the key while signing, so a concurrent promote waits and a retired key never signs after its retirement commits; if a rotation committed first, Sign fails and the caller retries. KMS/HSM signers (v0.4) implement the same interface.
- No DELETE on signing keys; key operations (create, promote, discard) are audit-logged ([ADR-0021 Certification readiness](0021-certification-readiness.md); wired when the audit log lands, ADR-0027).

## Consequences
- Rotation needs vendor cooperation (ship builds that trust the pending key). That is inherent to embedded trust anchors; the pending state makes it a planned step, not an outage.
- Retired keys are never reactivated: a mistaken promote can't be rolled back, only rotated forward.
