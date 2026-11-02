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

## Amendment: database role model (2026-11-02, from security review; accepted)
Row-level security is only a backstop if the serving process can't switch it off or widen its own scope. So:

| Login | Group | Used for | Can |
|---|---|---|---|
| owner | – | `licenseforge migrate` (Helm job / init container) only | Owns the schema; `migrator_all` policy lets data migrations see all rows |
| api | `licenseforge_app` | every tenant request (tenant pool) | Only rows where `tenant_id = app.tenant_id` (set per transaction); `tenants`: read own row only |
| admin | `licenseforge_platform` | platform-admin operations (separate pool) | All tenants |

- Platform access is a **database identity**, not a setting: the api login is not a member of `licenseforge_platform`, so a SQL bug in a tenant request can't reach other tenants (no `SET ROLE`, no GUC).
- `store.Open` refuses a login that switched role via connection options, is superuser / BYPASSRLS / CREATEROLE (covers `rds_superuser`, `cloudsqlsuperuser`), is a member of such a role or of the other pool's group, owns any relation, or has `app.tenant_id` preset.
- Every relation follows one canonical pattern (enable + force RLS, exactly the expected policies, explicit grants, no default privileges). Views, materialized views, partitioned and foreign tables are refused until reviewed. A release-blocking test checks all of it, plus cross-tenant read/write/delete/insert, own-tenant-row writes, escalation attempts, unscoped access and setting leakage on a reused connection.
- Setup for operators: `deploy/database-setup.sql` (group roles, three logins, `REVOKE CONNECT ... FROM PUBLIC` so other installs on the same cluster are kept out).
- Limitation (documented): arbitrary SQL execution as the api login could still set another `app.tenant_id`; tenant IDs are 128-bit random, and RLS remains a backstop for application bugs, not a defence against full SQL injection.

## Alternatives considered
- **Database per tenant**: stronger isolation, painful migrations and ops at scale. Could be an enterprise option later.
- **Single-tenant only**: simpler now, rewrite later when hosting.
