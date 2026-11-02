# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Added
- Repository setup, Apache-2.0 license, community files, CI.
- Architecture Decision Records 0001–0024 (0024: HIPAA, NIST and FedRAMP readiness) and the `lf1` license file format draft.
- Minimal server with `/healthz` and `/readyz`.
- Go SDK module `licenseforge.io/licenseforge/sdk/go` with `licensefile`: sign and verify `lf1` licenses (Ed25519, key ID in the envelope, algorithm bound to the trusted key).
- `lf1` conformance vectors in `spec/vectors/lf1.json`.
- `licensefile.ParseClaims`, `Claims.Check` and `Open`: parse and check lf1 claims (version, product, binding, clock skew, not-before, max offline, expiry with grace, updates_until) in the order defined by the spec.
- Claim conformance vectors in `spec/vectors/lf1-claims.json` (93 cases).
- `Entitlements.HasFeature`, `Limit` and `Allows` (ADR-0015): unknown keys are never an error; an absent limit behaves as 0; `Allows` takes the resulting total and rejects negative values.
- Go SDK `clock` package: clock rollback protection (ADR-0018) with an HMAC-authenticated high-water mark, 24h default tolerance, `Reset` after online refresh, and an atomic `FileStore`.
- CI runs tests in FIPS 140-3 mode (`GOFIPS140=certified`).
- Go SDK `fingerprint` package: default machine/cluster fingerprints (vendor override, opt-in `LICENSEFORGE_FINGERPRINT`, Kubernetes kube-system UID with retries, Linux machine-id with tmpfs and container safeguards, Windows MachineGuid, macOS IOPlatformUUID), hashed per tenant and product.
