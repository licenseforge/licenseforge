# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Added
- Repository setup, Apache-2.0 license, community files, CI.
- Architecture Decision Records 0001–0028 and the `lf1` license file format draft.
- Minimal server with `/healthz` and `/readyz`.
- `Merge gate` check: fails while a PR has the `do-not-merge` label.
- Server data layer foundation (`internal/store`): ent with PostgreSQL, prefixed IDs, versioned migrations with a built-in runner (checksums, per-file transactions, advisory lock), a three-login role model (owner, tenant pool, platform pool) with forced row-level security and release-blocking isolation tests, and `deploy/database-setup.sql`; tenants and products tables.
- `internal/secrets` (ADR-0025): keyring of master keys from `LICENSEFORGE_MASTER_KEYS` (generate one with `openssl rand -base64 32`), AES-256-GCM encryption bound to its row, HMAC lookup hashes that survive key rotation.
- `internal/licensekey`: license keys `LF-` + 128 random bits in grouped base32, normalised input with one canonical spelling.
- Audit log: one hash-chained, append-only chain per tenant, written in the action's transaction and serialized per tenant; `Verify` detects changed, removed or reordered entries (ADR-0027).
- Per-tenant Ed25519 signing keys with a pending → active → retired lifecycle; private keys encrypted with the master keyring and erased from the live table on retirement; `Signer` interface with a local implementation (ADR-0026).
- License invariants: term licenses always have an expiry, site licenses start at issue with no activation limit, limits are fraction-free integers with key-format names.
- Customers, licenses and activations tables (ADR-0013): plan snapshot (incl. binding policy) and resolved entitlements checked like the license format, encrypted key with per-tenant lookup hash, status and expiry invariants (expiry derived), activations bound as the license requires, one active activation per machine, never deleted, same-tenant keys and forced RLS; plans gain a binding policy.
- Catalog tables (ADR-0015): features, plans (calendar-month or second terms) and plan features; keys, slugs and types immutable and rows archived, never deleted, enforced by column-level grants; database-enforced formats and ranges; same-tenant/same-product/type composite keys; schema-vs-migration and same-tenant structural guard tests.
- Go SDK module `licenseforge.io/licenseforge/sdk/go` with `licensefile`: sign and verify `lf1` licenses (Ed25519, key ID in the envelope, algorithm bound to the trusted key).
- `lf1` conformance vectors in `spec/vectors/lf1.json`.
- `licensefile.ParseClaims`, `Claims.Check` and `Open`: parse and check lf1 claims (version, product, binding, clock skew, not-before, max offline, expiry with grace, updates_until) in the order defined by the spec.
- Claim conformance vectors in `spec/vectors/lf1-claims.json` (98 cases); fingerprint derivation vectors in `spec/vectors/fingerprint.json`.
- `Entitlements.HasFeature`, `Limit` and `Allows` (ADR-0015): unknown keys are never an error; an absent limit behaves as 0; `Allows` takes the resulting total and rejects negative values.
- Go SDK `clock` package: clock rollback protection (ADR-0018): HMAC-authenticated high-water mark, `Now`/`Observe`/`Reset`, 24h default tolerance (0 = strict), rollback check that always runs (also on read-only storage), and a `FileStore` with OS file locks that is atomic and safe across processes.
- CI runs tests in FIPS 140-3 mode (`GOFIPS140=certified`).
- Go SDK `fingerprint` package: default machine/cluster fingerprints (vendor override, opt-in `LICENSEFORGE_FINGERPRINT`, Kubernetes kube-system UID with retries, Linux machine-id with tmpfs and container safeguards, Windows MachineGuid, macOS IOPlatformUUID), hashed per tenant and product.

### Changed
- PostgreSQL 17 or newer is required (ADR-0028); `store.Open` and `store.Migrate` refuse older versions.
