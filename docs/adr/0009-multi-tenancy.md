# ADR-0009 Multi-tenancy

*Status: accepted · Date: 2026-11-02*

## Context
The same codebase must serve (a) one vendor self-hosting and (b) our hosted cloud with many vendors.

## Decision
- Every vendor is a **tenant**. All rows carry `tenant_id`; Postgres **row-level security** enforces isolation as a second line of defence behind application checks.
- Each tenant has its own signing keys ([ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md)); a compromise of one tenant's key can't forge another's licenses.
- Self-hosted installs simply run with one tenant.

## Consequences
- Hosted SaaS needs no fork or separate deployment per customer.
- Every query must set tenant context; enforce with a DB-session helper and tests.

## Certification amendments (2026-11-02)
Shared-database tenancy is accepted by SOC 2 / ISO 27001 when isolation is enforced and tested. To keep stricter regimes open ([ADR-0021 Certification readiness](0021-certification-readiness.md)):
- **Dedicated instance option**: because self-hosted = single tenant, a "dedicated" hosted customer is just another deployment of the same chart (own DB, own region). Covers data-residency, FedRAMP-style or bank requirements without a code fork.
- **Region is a deployment property**: no cross-region data flows; hosted can run EU and US instances separately.
- **Tenant export and hard delete** (GDPR access/erasure, contract exit), audit log retained per retention policy.
- Per-tenant **data-encryption keys** (envelope encryption) are possible later through the same key interface used for signing keys.
- Cross-tenant isolation test in CI is a release blocker.

## Alternatives considered
- **Database per tenant**: stronger isolation, painful migrations and ops at scale. Could be an enterprise option later.
- **Single-tenant only**: simpler now, rewrite later when hosting.
