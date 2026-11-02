# ADR-0004 Signed license files with Ed25519

*Status: accepted · Date: 2026-11-02*

## Context
We need online activation, revocation, and air-gapped operation. Maintaining two separate mechanisms doubles the SDK and attack surface.

## Decision
A single artifact: a **signed license file** ([License File Format](../../spec/license-format.md)).
- Online activation returns a license file with a short `exp` (lease) bound to the machine. The SDK refreshes it before expiry. **Revocation = server refuses to refresh.**
- Air-gapped returns the same format with a long `exp` ([ADR-0006 Air-gapped licensing](0006-air-gapped-licensing.md)).
- Signature: **Ed25519**, per-tenant keys, `kid` for rotation. Signed over raw payload bytes; JSON payload.

## User experience: online = just a key
For online activation the end user only ever handles a **license key** (e.g. `LF-XXXX-XXXX-XXXX`). The signed lease is an SDK implementation detail, never shown or copied by anyone:
- `activate(key)` → SDK receives the lease and caches it (default: a file in the app's data dir).
- **Storage is pluggable**: file, memory-only (stateless containers, read-only FS), or vendor-provided (k8s Secret, DB row). Memory-only means re-activating on every start, so the server must be reachable at startup.
- A license *file* is only something a human handles in air-gapped mode ([ADR-0006 Air-gapped licensing](0006-air-gapped-licensing.md)).

### On Kubernetes
| What | Where | Why |
|---|---|---|
| License key | `Secret` (env var or mounted) | It's a credential |
| Air-gapped license file | `ConfigMap` (or Secret) **mounted as a directory** | Signed, not secret; admin updates it, kubelet propagates it, SDK re-reads on change |
| Online lease | Memory, or SDK writes a ConfigMap **via the k8s API** | Mounted ConfigMaps are read-only inside the pod; writing needs a ServiceAccount with `get/update` on that one ConfigMap |

- Don't mount with `subPath`: subPath mounts never receive updates, so a renewed license wouldn't be seen until pod restart.
- Default binding on k8s is `cluster` (kube-system namespace UID), not per-pod: pods are ephemeral, so per-pod fingerprints would burn activations on every reschedule. All replicas share one activation and one lease.

## Consequences
- SDK core is tiny and identical for online/offline: verify signature, check time, check binding.
- Apps keep working through server outages for the lease duration. Good for vendors' uptime, and our hosted SLA pressure drops.
- Revocation latency = lease length. Vendors tune per plan (`lease_ttl`).
- Public keys embedded in vendor's app; key rotation requires shipping both old and new kid for a while.

## Certification amendments (2026-11-02)
See [ADR-0021 Certification readiness](0021-certification-readiness.md).
- **Ed25519 is FIPS-approved** (FIPS 186-5, 2023). Server signs through Go's FIPS 140-3 module (`GOFIPS140`) in FIPS builds.
- **Algorithm agility without `alg` headers**: algorithm is bound to `kid` in the trusted key set ([License File Format](../../spec/license-format.md)). ECDSA P-256 (for FIPS modules lacking EdDSA) and ML-DSA (post-quantum, CNSA 2.0) are new key types, not new formats.
- `kid` moved to the envelope, outside the payload; customer name removed from payload by default.

## Alternatives considered
- **JWT (EdDSA)**: ubiquitous, but algorithm-agility footguns (`alg: none`, RS/HS confusion) in many libraries; we'd still have to pin and audit every SDK's JWT lib.
- **PASETO v4.public**: good design, same crypto, thinner library coverage (C/embedded).
- **RSA**: larger keys and signatures, slower, no benefit.
- **Online-only validation API**: breaks air-gapped and makes vendor apps depend on our uptime.
