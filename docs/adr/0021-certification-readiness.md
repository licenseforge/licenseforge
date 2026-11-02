# ADR-0021 Certification readiness

*Status: accepted · Date: 2026-11-02*

> [!note] Extended by [ADR-0024 HIPAA, NIST and FedRAMP readiness from day 1](0024-hipaa-nist-and-fedramp-readiness-from-day-1.md) (2026-11-02): FedRAMP, HIPAA and NIST readiness move to day 1.

## Context
To sell LicenseForge (hosted and enterprise) and to be embedded in vendors' regulated products, we will be asked for certifications. None are needed for v0.1, but architecture choices made now must not block them. Reviewed against ADR-0004, 0005, 0006, 0009 on 2026-11-02.

## Which certifications matter, and for what
| Certification / regime | Applies to | When | Blocked by our design? |
|---|---|---|---|
| **SOC 2 Type II** | Our company + hosted cloud | Before selling hosted to mid-market/enterprise | No. Needs audit logs, access control, change management, vendor reviews: process work |
| **ISO 27001** | Our company (ISMS) | EU enterprise deals | No. Same controls as SOC 2 |
| **GDPR** (+ DPA with each vendor) | Hosted cloud; EU vendors | From first EU customer | No, after data minimisation below |
| **EU Cyber Resilience Act (CRA)** | Our SDKs/agent embedded in vendors' products; vendors will pass obligations to us | Reporting obligations from Sep 2026, full application Dec 2027 | No. Needs SBOM, vulnerability handling, security updates |
| **FIPS 140-3** (validated crypto) | US federal, defence, regulated buyers | On demand, per deal | No. Ed25519 is approved (FIPS 186-5); FIPS builds via Go's FIPS 140-3 module; ECDSA P-256 fallback by new key type |
| **FedRAMP / StateRAMP** | Hosted for US government | Much later, only if pursued | No. Dedicated-instance deployments + FIPS images cover the architecture side |
| **CNSA 2.0 / post-quantum** | Defence/national security buyers | 2030+ timelines | No. ML-DSA (FIPS 204) can be added as a key type without a format change |
| **PCI DSS** | Card payments | Never | Avoided by delegating billing ([ADR-0007 Billing and campaigns delegated to payment providers](0007-billing-and-campaigns-delegated-to-payment-providers.md)) |
| **OpenSSF Best Practices badge / Scorecard, SLSA** | Open-source trust, procurement | v0.1 onwards | No |

## Decision: built in from v0.1 (cheap now, expensive later)
**Crypto**
- Only Go stdlib crypto (FIPS-capable module). No hand-rolled primitives.
- Algorithm bound to `kid`, never read from the license file; `kid` outside payload ([License File Format](../../spec/license-format.md)).
- `Signer` interface from day one so KMS/Vault Transit/HSM drop in for FIPS Level 2/3 key custody (Architecture Overview).
- FIPS image variant built with `GOFIPS140`.

**Audit and access** (SOC 2 / ISO 27001 core evidence)
- Append-only audit log, **hash-chained** (each entry includes hash of previous) for tamper evidence; export to SIEM via webhook/OTel.
- Logs every admin action, login, token use, offline issuance, key operation, platform-admin impersonation.
- RBAC with least privilege, scoped expiring API tokens, MFA delegated to IdP ([ADR-0019 Authorization model](0019-authorization-model.md), [ADR-0003 Identity via generic OIDC, Keycloak as default](0003-identity-via-generic-oidc-keycloak-as-default.md)).
- Configurable retention.

**Data protection (GDPR)**
- Data inventory: personal data = customer names/emails, member identities, IPs and hostnames on activations. Fingerprints are hashed ([ADR-0017 Default machine fingerprint](0017-default-machine-fingerprint.md)).
- License files carry customer **ID only** by default.
- Tenant export and hard-delete; IP/hostname capture configurable per tenant.
- Encryption in transit (TLS) and at rest (DB/disk + envelope-encrypted secrets).

**Supply chain** (CRA, SLSA, enterprise procurement)
- Signed images, Helm chart and SDK releases (cosign/Sigstore), SBOM per release, SLSA provenance from CI.
- `SECURITY.md` with coordinated disclosure, security advisories via GitHub, a documented supported-versions and patch policy.
- Dependency scanning and OpenSSF Scorecard in CI; DCO enforced ([ADR-0002 Open source licensing model](0002-open-source-licensing-model.md)).

**Deployment** ([ADR-0005 Kubernetes deployment via Helm](0005-kubernetes-deployment-via-helm.md), [ADR-0009 Multi-tenancy](0009-multi-tenancy.md))
- Hardened chart defaults (restricted PSS, non-root, read-only FS, NetworkPolicies).
- Dedicated-instance and per-region deployments are the same chart: no fork for residency or government needs.

## Decision: deferred (process, not architecture)
- SOC 2 Type II audit, ISO 27001 ISMS, external pen test: start when hosted launches.
- CMVP-validated status: depend on the Go module's certificate; don't validate our own module.

## Open verification items
- [x] Go Cryptographic Module v1.0.0: CMVP #5247 active, EdDSA approved (see Compliance verification 2026-11).
- [ ] Confirm Ed25519 in Bouncy Castle FIPS (Java); OpenSSL 3.5+ FIPS provider (Node) lists Ed25519 as approved. If missing, FIPS customers get ECDSA P-256 keys.
- [ ] Confirm CRA obligations for open-source projects vs. commercial distributors (we are both).

## Consequences
- A few days of extra v0.1 work (hash-chained audit, Signer interface, signed releases, hardened chart) instead of retrofits under audit pressure.
- Certification becomes mostly a process and paperwork effort, not a rewrite.
