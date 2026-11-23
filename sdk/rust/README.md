# LicenseForge SDK for Rust

Verifies LicenseForge license files (`lf1`, [spec](../../spec/license-format.md)) in a Rust program, offline, against the keys built into your app (ADR-0050). Ed25519 comes from the [dalek](https://github.com/dalek-cryptography/curve25519-dalek) crates (`ed25519-dalek`, `curve25519-dalek`), which are its only runtime dependencies. JSON and base64url are hand-written to the spec. Rust 1.85 or later.

Status: alpha, not published yet. Today it covers the envelope, the signature, the trusted key set, the claims and the claim checks, and passes `spec/vectors/lf1.json` and `lf1-claims.json`. Next: fingerprints, offline formats and the clock guard, then the online client.

```rust
// Your tenant's trusted key set, as the dashboard shows it (Settings →
// Signing keys → JSON), shipped with your build.
let keys = licenseforge::parse_key_set(include_bytes!("licenseforge-keys.json"))?;

let opts = licenseforge::CheckOptions::new(std::time::SystemTime::now(), "acme-db").with_fingerprint(fingerprint);
match licenseforge::open(&std::fs::read_to_string("license.lic")?, &keys, &opts) {
    Ok(lic) => {
        if lic.status == licenseforge::Status::Grace {
            warn("license expired: renew it");
        }
        if !lic.claims.entitlements.allows("nodes", nodes + 1) {
            refuse("node limit reached");
        }
    }
    Err(e) => refuse(e.code().as_str()), // malformed, bad_signature, expired, …
}
```

`verify`, `parse_claims` and `check` are the three steps of `open` on their own.

- Every step runs in the spec's order, so the error class is the same as in the Go, Java and TypeScript SDKs (`Code`, `#[non_exhaustive]`): `malformed`, `unknown_key`, `unsupported_alg`, `bad_signature`, `invalid_key_set`, then `unsupported_version`, `wrong_product`, `binding_mismatch`, `clock_skew`, `not_yet_valid`, `offline_exceeded`, `expired`, `updates_expired`.
- Claims are decoded under the spec's strict rules (no duplicate keys, exact timestamp and duration formats, integer tokens only, nothing lenient); times compare to the nanosecond, so `now` equal to `exp` is still valid. `clock_tolerance` defaults to 24 hours (`DEFAULT_CLOCK_TOLERANCE`).
- Entitlements: `has_feature(key)`, `limit(key)` (0 when absent, `Entitlements::UNLIMITED` = -1) and `allows(key, total_after_action)`.
- Verification is cofactorless and refuses a non-canonical `S` (checked by the SDK itself, whatever dalek features the rest of your build enables), like Go, the JDK and OpenSSL. Weak and mixed-order trusted keys (`invalid_key_set`) and a weak `R` (`bad_signature`) are refused before the signature check, as the spec requires.
- Keys load as given: an unknown `alg`, a duplicate `kid` or a wrong key length surface in `verify`, when that key is used.
- Error messages never echo the license or key set, beyond a validated `kid`.

Build and test: `cargo test` (serde_json reads the vectors in tests only).
