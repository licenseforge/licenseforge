# ADR-0010 Official SDKs: Go, Java, TypeScript

*Status: accepted · Date: 2026-11-02*

## Context
Vendors integrate LicenseForge through SDKs. Each SDK is a security-critical component that must behave identically. Every extra language is a permanent maintenance cost.

## Decision
Three official SDKs, all Apache-2.0, all **zero runtime dependencies** for verification:

| SDK | Ed25519 from | Targets | Milestone |
|---|---|---|---|
| Go | `crypto/ed25519` (stdlib) | CLIs, k8s operators, backend services | v0.1 |
| Java | JCA `Ed25519` (JDK 15+) | Enterprise on-prem, JVM apps (Kotlin/Scala for free) | v0.2 |
| TypeScript | `node:crypto` (Ed25519) | Node backend services; also Electron main process and Node CLIs | v0.2 |

Each SDK has the same surface: `verify(file)`, `activate(key)`, `refresh()`, `deactivate()`, `entitlements()`, `requestOffline()`. Core verification is hand-written (small, auditable); HTTP calls use the platform's built-in client.

**Conformance test vectors**: the spec repo holds a set of license files + public keys + expected results (valid, expired, in grace, bad signature, wrong kid, wrong fingerprint, clock rollback). Every SDK's CI must pass all of them. This is what keeps three implementations honest.

## Consequences
- Covers the large majority of on-prem and B2B vendors.
- **TypeScript SDK is server-side only (Node ≥ 20).** No browser build: client-side JS can be edited by anyone, so it can't enforce anything. A frontend asks its own backend for entitlements. Bun/Deno may work via `node:crypto` compatibility but aren't officially supported.
- Java 15+ minimum; Java 8/11 users need BouncyCastle (document, don't support officially).
- Gaps: other languages are covered first by the in-cluster agent's local API and an OpenFeature provider ([ADR-0012 In-cluster license agent](0012-in-cluster-license-agent.md), v0.3). A C-ABI core with .NET and Python bindings is Later. Community SDKs can certify against the test vectors.

> [!NOTE]
> **Amended 2026-11-02**
> After Licensing competitor feature gaps: no new native SDKs before v0.4; the agent closes the server-side language gap.

> [!NOTE]
> **Amended 2026-11-10**
> Java FIPS mode: the SDK verifies through the validated Bouncy Castle FIPS Java jar, BC-FJA 2.1.1 (certificate #4943, Ed25519 approved under FIPS 186-5), or a later version once a CMVP certificate lists it; the SDK documents the exact validated version ([ADR-0024 HIPAA, NIST and FedRAMP readiness from day 1](0024-hipaa-nist-and-fedramp-readiness-from-day-1.md)).

## Alternatives considered
- **One C core + bindings**: single implementation, but FFI/packaging pain on every platform.
- **Generate SDKs from OpenAPI**: fine for the admin API later, doesn't cover offline verification, which is the critical part.
