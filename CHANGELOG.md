# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Added
- Repository setup, Apache-2.0 license, community files, CI.
- Architecture Decision Records 0001–0024 (0024: HIPAA, NIST and FedRAMP readiness) and the `lf1` license file format draft.
- Minimal server with `/healthz` and `/readyz`.
- Go SDK module `licenseforge.io/licenseforge/sdk/go` with `licensefile`: sign and verify `lf1` licenses (Ed25519, key ID in the envelope, algorithm bound to the trusted key).
- `lf1` conformance vectors in `spec/vectors/lf1.json`.
- CI runs tests in FIPS 140-3 mode (`GOFIPS140=certified`).
