# ADR-0025 License key storage and encryption at rest

*Status: accepted · Date: 2026-11-02*

## Context
A license key is a credential: whoever holds it can activate. Enterprise audits (SOC 2, ISO 27001, [ADR-0021 Certification readiness](0021-certification-readiness.md)) expect secrets to be encrypted at rest and access to them audited. Vendors also need to look up a customer's key and resend it, so hash-only storage (like API tokens) hurts adoption. Activation must find a license by key quickly without decrypting every row.

## Decision
- **Format**: `LF-` + 128 random bits as 26 uppercase base32 characters in groups (`LF-ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ`). Input is normalised (case, dashes, spaces) before use.
- **Keyring**: one or more 32-byte master keys with IDs, from `LICENSEFORGE_MASTER_KEYS` (a Kubernetes Secret / secret manager, [ADR-0011 Secret manager integrations](0011-secret-manager-integrations.md)). The first key is active for new encryption; all keys decrypt, so rotation needs no downtime. KMS/HSM custody later replaces the env source behind the same interface ([ADR-0021 Certification readiness](0021-certification-readiness.md)).
- **Encryption**: AES-256-GCM via Go's FIPS-approved random-nonce GCM, with a per-purpose subkey derived by HKDF-SHA256 from the master key. Additional authenticated data binds each ciphertext to its row (purpose, tenant, row ID), so ciphertexts can't be swapped between rows or tenants. Stored as `v1.<key id>.<base64url>`.
- **Lookup**: HMAC-SHA256 of the normalised key under an HKDF-derived lookup subkey, stored in an indexed column. Activation computes the HMAC under each keyring key and queries for any of them, so lookups keep working during rotation.
- **Reveal**: the dashboard may show a key again to roles with the permission ([ADR-0019 Authorization model](0019-authorization-model.md)); every reveal is audit-logged. Keys can be rotated without reissuing the license.

## Consequences
- The database alone (backup, replica, SQL access) never exposes license keys.
- Losing all master keys makes stored keys unrecoverable; licenses still verify (signatures don't depend on them) but keys can't be re-shown, only rotated. Operators must back up the master key Secret.
- Rotation of the master key re-encrypts lazily; an explicit re-encrypt job comes later.

## Alternatives considered
- **Hash only** (like API tokens): strongest, but vendors can't resend keys; support burden.
- **Plaintext with DB/disk encryption only**: fails "encrypted at rest" for anyone with SQL access.
- **Database-side pgcrypto**: keys would travel to and live in the database session.
