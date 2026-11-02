# ADR-0012 In-cluster license agent

*Status: accepted · Date: 2026-11-02*

## Context
Native SDKs cover Go, Java and TypeScript ([ADR-0010 Official SDKs Go, Java, TypeScript](0010-official-sdks-go-java-typescript.md)). Python, .NET, Rust, Ruby, etc. remain uncovered, and each new native SDK is a permanent cost. Replicated covers every language with one in-cluster Service (Licensing competitor feature gaps).

## Decision
Ship `licenseforge-agent` in **v0.3** (moved up from v0.4):
- Small Go binary, deployed as a Helm subchart the vendor adds to their own chart (one Deployment per install, not a sidecar per pod).
- Holds the license key (Secret), does activation/refresh against LicenseForge, binds to the cluster (kube-system UID), stores the lease (memory / ConfigMap / secret-manager add-on).
- Exposes a **local REST API** on a ClusterIP Service: `GET /v1/license`, `GET /v1/entitlements`, `GET /v1/entitlements/{feature}`, `POST /v1/usage/{counter}` (v0.3 metering).
- When upstream is unreachable it serves the cached lease and says so via a response header (`X-LicenseForge-Stale: true`) until `max_offline` passes.
- Air-gapped: reads the mounted license file instead of calling upstream.
- Also ships an **OpenFeature provider** so apps can read entitlements as feature flags in any OpenFeature language.
- v0.4: same agent reports cluster capacity (nodes, vCPU) and hosts the admission webhook.

### Admission webhook rules (v0.4)
- **Fail-open** by default (`failurePolicy: Ignore`), plus a grace period.
- Enforce by blocking *new* installs/upgrades of the vendor's workloads, never by killing running ones. Breaking a customer's cluster is the fastest way to lose trust.

## Consequences
- Any language gets licensing with an HTTP call; native SDKs stay at three for now.
- The agent's local API is unauthenticated inside the cluster by default; document NetworkPolicy and optional shared-token auth.
- Anyone with cluster access can fake the agent's answers. Same threat model as patching an SDK ([ADR-0014 Product scope and won't-do list](0014-product-scope-and-won-t-do-list.md)); apps that care can verify the raw signed lease returned by `GET /v1/license`.

## Alternatives considered
- **More native SDKs first**: 10× the cost per language.
- **Sidecar per pod**: more activations and resource use; one agent per install is enough.
