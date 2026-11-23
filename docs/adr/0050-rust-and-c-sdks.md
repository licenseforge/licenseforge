# ADR-0050 Rust and C++ SDKs

*Status: accepted · Date: 2026-11-23*

## Context
[ADR-0010 Official SDKs Go, Java, TypeScript](0010-official-sdks-go-java-typescript.md) chose three SDKs and, amended 2026-11-02, "no new native SDKs before v0.4": the in-cluster agent was to close the gap for other languages. The owner asked for Rust and C++ SDKs on 2026-11-23.

Native desktop and on-prem software (CAD, EDA, simulation, media, games, embedded and appliance software) is the traditional market for license managers, and it's mostly C++. Those apps often run without a cluster, so the agent doesn't reach them. Rust is increasingly used for CLIs, agents and services and needs native verification for the same offline cases.

## Decision
Two more official SDKs, Apache-2.0, held to the same spec and conformance vectors as the other three:

| SDK | Ed25519 from | Other crypto | Targets |
|---|---|---|---|
| Rust (`sdk/rust`, crate `licenseforge`) | `ed25519-dalek` (3.x), `curve25519-dalek` for the subgroup check | `sha2`, `hmac` (RustCrypto) | CLIs, services, agents; stable Rust, MSRV documented and tested |
| C++ (`sdk/cpp`, C++17, CMake) | OpenSSL 3 `libcrypto` (EVP Ed25519) | the same libcrypto (SHA-256, HMAC) | desktop and on-prem native apps on Linux, macOS, Windows |

- **Dependencies:** neither language has Ed25519 in its standard library, so each SDK takes one well-audited crypto project (the dalek crates; OpenSSL, which is already on almost every target). Nothing else: JSON and base64url are hand-written to the spec, as in the Java SDK.
- **Same answers:** verification is cofactorless and refuses a non-canonical S, like Go, SunEC and OpenSSL. The SDK refuses weak keys and weak R itself, before calling the library. The conformance vectors are the gate in each SDK's CI.
- **FIPS (C++):** OpenSSL 3.5+ has a FIPS provider that approves Ed25519. The C++ SDK gets a FIPS mode later, the same way as Java (the validated provider by name, no fallback). The Rust SDK has no FIPS mode; a buyer who needs one uses Go, Java or C++.
- **Scope, in order:**
  1. Offline parity first: lf1 verify, claims, key sets, entitlements and fingerprints.
  2. Then the offline request/receipt formats and the clock guard.
  3. The online client (activate, refresh, deactivate) follows: in Rust behind an optional feature with `ureq` + `rustls`, in C++ on libcurl. Both are the platform's common HTTP client, not part of verification.
- **Milestone:** v0.3. Each SDK gets its own release tag (`sdk/rust/vX.Y.Z` → crates.io with trusted publishing; `sdk/cpp/vX.Y.Z` → source release, later vcpkg/Conan).

## Consequences
- Five implementations to keep in step; the vectors and the "same answers" rule carry the load, as with three.
- Each SDK lists its one crypto dependency, which buyers' security reviews see.
- C++ users build against their system OpenSSL; the SDK doesn't bundle it.
- The 2026-11-02 amendment of ADR-0010 ("no new native SDKs before v0.4") no longer holds for Rust and C++. The C-ABI core with .NET and Python bindings stays Later.

## Alternatives considered
- **Rust core with a C ABI and a C++ header:** one implementation for both, and later .NET/Python. Rejected for now: every C++ user would need prebuilt Rust libraries per platform and toolchain, which is the FFI packaging pain ADR-0010 rejected. C++ users expect source plus their system OpenSSL.
- **Hand-written Ed25519:** no dependency, but an unaudited implementation of the most security-critical step. Rejected.
- **libsodium for C++:** small and good, but it verifies differently on edge cases (it refuses some small-order points that the spec handles itself) and is less often already present than OpenSSL. Rejected.
- **`ring` or `aws-lc-rs` for Rust:** `aws-lc-rs` would allow FIPS later, but it needs a C toolchain at build time. RustCrypto stays pure Rust. Revisit if a Rust FIPS buyer appears.
