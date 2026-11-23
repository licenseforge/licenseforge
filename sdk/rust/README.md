# LicenseForge SDK for Rust

Verifies LicenseForge license files (`lf1`, [spec](../../spec/license-format.md)) in a Rust program, offline, against the keys built into your app (ADR-0050). Ed25519 comes from the [dalek](https://github.com/dalek-cryptography/curve25519-dalek) crates (`ed25519-dalek`, `curve25519-dalek`), which are its only runtime dependencies. JSON and base64url are hand-written to the spec. Rust 1.85 or later.

Status: alpha, not published yet. Today it covers the envelope, the signature and the trusted key set, and passes `spec/vectors/lf1.json`. Next: claims and claim checks (`lf1-claims.json`), fingerprints, offline formats and the clock guard, then the online client.

```rust
// Your tenant's trusted key set, as the dashboard shows it (Settings →
// Signing keys → JSON), shipped with your build.
let keys = licenseforge::parse_key_set(include_bytes!("licenseforge-keys.json"))?;

match licenseforge::verify(&std::fs::read_to_string("license.lic")?, &keys) {
    Ok(v) => { /* v.payload: the verified claims JSON; v.kid: the key that signed it */ }
    Err(e) => refuse(e.code().as_str()), // malformed, unknown_key, bad_signature, …
}
```

- Every step runs in the spec's order, so the error class is the same as in the Go, Java and TypeScript SDKs: `malformed`, `unknown_key`, `unsupported_alg`, `bad_signature`, `invalid_key_set` (`Code`, `#[non_exhaustive]`).
- Verification is cofactorless and refuses a non-canonical `S`, like Go, the JDK and OpenSSL. Weak and mixed-order trusted keys (`invalid_key_set`) and a weak `R` (`bad_signature`) are refused before the signature check, as the spec requires.
- Keys load as given: an unknown `alg`, a duplicate `kid` or a wrong key length surface in `verify`, when that key is used.
- Error messages never echo the license or key set.

Build and test: `cargo test` (serde_json reads the vectors in tests only).
