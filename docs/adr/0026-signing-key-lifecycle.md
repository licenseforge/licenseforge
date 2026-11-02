# ADR-0026 Signing key lifecycle

*Status: proposed · Date: 2026-11-02*

> [!WARNING]
> **Proposed (drafted overnight 2026-11-02, implemented in the signing-keys PR). Needs maintainer acceptance before merge.**

## Context
Each tenant signs its licenses and leases with its own Ed25519 keys ([ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md), [ADR-0009 Multi-tenancy](0009-multi-tenancy.md)). Vendors embed the trusted public keys (`kid`, `alg`, key) in their builds ([License File Format](../../spec/license-format.md)). So a new key is only useful once vendor builds trust it: if the server switched to a new key at once, every deployed build would reject the next lease refresh, an outage for all of the vendor's customers. Architecture Overview fixes the custody model for v0.1 (private keys AES-GCM-encrypted with the master keyring, behind a `Signer` interface); the lifecycle wasn't decided.

## Decision
- **kid = key row ID** `sk_<26 base32>`: globally unique, valid under the spec's kid pattern, so keys of different tenants never collide in a vendor's trusted set.
- **Algorithm**: `ed25519` only in v0.1 ([ADR-0024 HIPAA, NIST and FedRAMP readiness from day 1](0024-hipaa-nist-and-fedramp-readiness-from-day-1.md)); the column exists so ECDSA P-256 / ML-DSA keys can be added later.
- **States**: `pending` → `active` → `retired`.
  - `pending`: generated, public key shown so vendors can add it to their trusted set and ship builds. Never signs.
  - `active`: signs everything new. **Exactly one per tenant** (partial unique index); at most one `pending`.
  - `retired`: never signs again. **The private key is destroyed** (ciphertext set to NULL, NIST SP 800-57 destruction); the public key stays for listing and so vendors can verify old files.
- **First key** of a tenant is created `active` (no build trusts anything yet).
- **Rotation** = create `pending`, vendor ships builds trusting it, then **promote**: in one transaction the old `active` becomes `retired` and the `pending` one `active`. The dashboard warns that builds not trusting the new kid will reject new leases.
- **Compromise**: same steps without waiting; old builds then fail closed on refresh, which is the safe failure. Offline files signed with the old key stay valid in builds that still trust it: documented, not fixable server-side.
- **Private key** = the 32-byte Ed25519 seed, encrypted with the keyring ([ADR-0025 License key storage and encryption at rest](0025-license-key-storage-and-encryption-at-rest.md)) bound to purpose `signing_key`, tenant and kid, so a ciphertext copied to another row or tenant doesn't decrypt.
- **`Signer`**: `Sign(ctx, tenant, kid, msg)` and `Public(ctx, tenant, kid)`. Sign refuses keys that aren't `active`. Callers read the active kid first, build `lf1.<kid>.<payload>`, then sign; a rotation in between makes Sign fail and the caller retries. KMS/HSM signers (v0.4) implement the same interface.
- No DELETE on signing keys; key operations (create, promote, retire) are audit-logged ([ADR-0021 Certification readiness](0021-certification-readiness.md)).

## Consequences
- Rotation needs vendor cooperation (ship builds that trust the pending key). That is inherent to embedded trust anchors; the pending state makes it a planned step, not an outage.
- Retired private keys can't be recovered: a mistaken promote can't be rolled back, only rotated forward.
