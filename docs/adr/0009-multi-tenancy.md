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
- `store.Open` refuses a login that switched role via connection options; has SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION (covers `rds_superuser`, `cloudsqlsuperuser`), or whose group does; is a member of **any role other than its own group** (allow-list: rules out the owner, the other group and predefined roles like `pg_execute_server_program`); owns or is a member of the owner of the database, schema or any relation; can create **temporary tables** (a temp table can shadow a real one for later requests on a pooled connection) or create schemas/objects in any schema (functions or operators could intercept queries); or has `app.tenant_id` preset. **PostgreSQL 15+ is required** (older versions let every role create objects in `public` by default). *Raised to 17 by [ADR-0028 PostgreSQL 17 minimum](0028-postgresql-17-minimum.md).*
- **No session state survives between requests**: serving pools run statements unnamed (pgx `QueryExecModeExec`, so no cached prepared statements to replace) and run `DISCARD ALL` before every connection reuse (session settings, prepared statements, temp state, advisory locks). Together with no TEMPORARY privilege, one request can't plant anything on a pooled connection for the next tenant.
- Every relation follows one canonical pattern (enable + force RLS, exactly the expected policies, explicit grants, no default privileges). Schemas other than `public`, views, materialized views, partitioned and foreign tables, triggers, rules, and any function other than `app_tenant_id` (exact body, not SECURITY DEFINER, not executable by PUBLIC) are refused until reviewed; functions are not executable by PUBLIC by default. A release-blocking test checks all of it, plus cross-tenant read/write/delete/insert, own-tenant-row writes, escalation attempts, unscoped access and setting leakage on a reused connection.
- **Cross-tenant references**: foreign key checks bypass RLS, so every reference between tenant tables is covered by a composite key named `*_same_tenant`, into the same table, that pairs `tenant_id` with `tenant_id` (plus the referenced ID and, where needed, product or type). The migration tool's diff hook keeps these keys; a structural test enforces the rule for every table.
- **Tenant hard delete** (contract exit, GDPR) is an owner-login operation (`licenseforge migrate`-level privileges): serving logins have no `DELETE` on licensing tables and foreign keys are `NO ACTION`, so a tenant can only be removed deliberately, child tables first. A `licenseforge tenant purge` command will script it.
- Setup for operators: `deploy/database-setup.sql` (group roles, three logins, `REVOKE CONNECT` and `REVOKE TEMPORARY ... FROM PUBLIC`).
- Limitation (documented): arbitrary SQL execution as the api login could still set another tenant's `app.tenant_id` if it knows the ID (IDs appear in licenses, so they are not secrets). RLS is a backstop for application bugs; SQL injection is prevented at the application layer (ent's parameterized queries, no string-built SQL).

## Alternatives considered
- **Database per tenant**: stronger isolation, painful migrations and ops at scale. Could be an enterprise option later.
- **Single-tenant only**: simpler now, rewrite later when hosting.
