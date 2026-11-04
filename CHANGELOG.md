# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Added
- Repository setup, Apache-2.0 license, community files, CI.
- Architecture Decision Records 0001–0030 and the `lf1` license file format draft.
- Helm chart `deploy/helm/licenseforge` (ADR-0005): Pod Security restricted, migrations as a pre-install/pre-upgrade Job with its own Secret (serving pods never get the owner login), startup and drain-aware probes, PodDisruptionBudget, NetworkPolicies for the server and the migration Job, optional HPA; values checked at render; linted (strict) and rendered in CI.
- Container image (distroless, non-root; FIPS variant with `--build-arg GOFIPS140=certified`) and `compose.yaml` for development: PostgreSQL with `deploy/database-setup.sql`, `migrate`, then the server.
- A fourth database login, `licenseforge_login` (group `licenseforge_identity`, ADR-0029), for the login path: `LICENSEFORGE_IDENTITY_DATABASE_URL`, the `identity-database-url` Helm Secret key and a line in `deploy/database-setup.sql`. `store.Open` takes `store.Logins` and refuses any pool's login in another pool.
- Server with `/healthz` (liveness) and `/readyz` (fails while the database is unreachable); `licenseforge migrate` applies migrations as the schema owner. Configured by `LICENSEFORGE_DATABASE_URL`, `LICENSEFORGE_PLATFORM_DATABASE_URL`, `LICENSEFORGE_OWNER_DATABASE_URL` (migrate only) and `LICENSEFORGE_MASTER_KEYS`; the server refuses to start without them, with unsafe database logins, or with the owner login in its environment. On SIGTERM it fails readiness and drains for `LICENSEFORGE_DRAIN` (default 5s) before closing.
- `Merge gate` check: fails while a PR has the `do-not-merge` label.
- Server data layer foundation (`internal/store`): ent with PostgreSQL, prefixed IDs, versioned migrations with a built-in runner (checksums, per-file transactions, advisory lock), a three-login role model (owner, tenant pool, platform pool) with forced row-level security and release-blocking isolation tests, and `deploy/database-setup.sql`; tenants and products tables.
- `internal/secrets` (ADR-0025): keyring of master keys from `LICENSEFORGE_MASTER_KEYS` (generate one with `openssl rand -base64 32`), AES-256-GCM encryption bound to its row, HMAC lookup hashes that survive key rotation.
- `internal/licensekey`: license keys `LF-` + 128 random bits in grouped base32, normalised input with one canonical spelling.
- `internal/authz` (ADR-0019): built-in roles owner/admin/manager/support/viewer and the token-only sdk role, mapped to fixed permissions; `Require` per handler, explicit product scope (zero scope denies), `Products` for list filters, `CanAssign` for member and token changes; scoped principals can't manage access; only owners grant, change or remove owner; tenant settings are owner-only.
- `internal/apitoken`: API tokens `lf_live_` + 256 random bits + CRC-32 checksum (secret-scanner friendly), offline format check, SHA-256 lookup hash and a display prefix.
- Audit log: one hash-chained, append-only chain per tenant, written in the action's transaction and serialized per tenant; `Verify` detects changed, removed or reordered entries (ADR-0027).
- Per-tenant Ed25519 signing keys with a pending → active → retired lifecycle; private keys encrypted with the master keyring and erased from the live table on retirement; `Signer` interface with a local implementation (ADR-0026).
- License invariants: term licenses always have an expiry, site licenses start at issue with no activation limit, limits are fraction-free integers with key-format names.
- Customers, licenses and activations tables (ADR-0013): plan snapshot (incl. binding policy) and resolved entitlements checked like the license format, encrypted key with per-tenant lookup hash, status and expiry invariants (expiry derived), activations bound as the license requires, one active activation per machine, never deleted, same-tenant keys and forced RLS; plans gain a binding policy.
- Catalog tables (ADR-0015): features, plans (calendar-month or second terms) and plan features; keys, slugs and types immutable and rows archived, never deleted, enforced by column-level grants; database-enforced formats and ranges; same-tenant/same-product/type composite keys; schema-vs-migration and same-tenant structural guard tests.
- Go SDK module `licenseforge.io/licenseforge/sdk/go` with `licensefile`: sign and verify `lf1` licenses (Ed25519, key ID in the envelope, algorithm bound to the trusted key).
- `lf1` conformance vectors in `spec/vectors/lf1.json`.
- `internal/issue`: signed offline license files for site licenses (air-gapped installs): `activation:offline` on the product, active and unexpired license with offline allowed, the tenant's active key, expiry rounded down, and an audit entry (`license.offline_file`) written before the file is returned; denied and failed attempts are audited too. The server module now uses the Go SDK module (`replace => ./sdk/go`, ADR-0023).
- `licensefile.Encode`: writes the lf1 payload for issuers and refuses claims that `ParseClaims` wouldn't read back identically (no rounding, no silently dropped fields).
- `licensefile.ParseClaims`, `Claims.Check` and `Open`: parse and check lf1 claims (version, product, binding, clock skew, not-before, max offline, expiry with grace, updates_until) in the order defined by the spec.
- Claim conformance vectors in `spec/vectors/lf1-claims.json` (98 cases); fingerprint derivation vectors in `spec/vectors/fingerprint.json`.
- `Entitlements.HasFeature`, `Limit` and `Allows` (ADR-0015): unknown keys are never an error; an absent limit behaves as 0; `Allows` takes the resulting total and rejects negative values.
- Go SDK `clock` package: clock rollback protection (ADR-0018): HMAC-authenticated high-water mark, `Now`/`Observe`/`Reset`, 24h default tolerance (0 = strict), rollback check that always runs (also on read-only storage), and a `FileStore` with OS file locks that is atomic and safe across processes.
- CI runs the SDK's OS-specific tests on Windows only; macOS returns with a self-hosted runner (darwin is still type-checked by `make vet-cross`).
- CI runs tests in FIPS 140-3 mode (`GOFIPS140=certified`).
- Go SDK `fingerprint` package: default machine/cluster fingerprints (vendor override, opt-in `LICENSEFORGE_FINGERPRINT`, Kubernetes kube-system UID with retries, Linux machine-id with tmpfs and container safeguards, Windows MachineGuid, macOS IOPlatformUUID), hashed per tenant and product.

### Changed
- PostgreSQL 17 or newer is required (ADR-0028); `store.Open` and `store.Migrate` refuse older versions.
