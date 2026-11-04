# ADR-0033 Platform audit chain

*Status: accepted · Date: 2026-11-04*

## Context
[ADR-0027 Audit log](0027-audit-log.md) puts events without a tenant (platform-admin actions, logins) on a **platform chain** under a reserved tenant row, and leaves two things "to be decided with the authn implementation": how the row is marked reserved, and the write path. It also lists "failed logins for unknown accounts" among the platform events. Implemented in PR #50; decided under the maintainer's delegation.

## Decision
- **The reserved row** is a fixed, well-known tenant ID (`audit.PlatformTenant`, slug `platform`). It is marked by **filtering it inside `app_tenant_id()`**: for that ID the function returns NULL, so no tenant-pool or identity-pool policy can match it, today or in tables added later, and the canonical policies stay unchanged ([ADR-0009 Multi-tenancy](0009-multi-tenancy.md)). No schema column is added.
  - The identity pool's tenant read and the platform pool's `tenants` policy also exclude the row, so no listing, slug resolution, rename or delete ever touches it.
  - Other tenant-scoped tables are not guarded on the platform pool (its policies are `true`): platform code must not create rows under the reserved tenant, and readers that join tenants must tolerate a missing tenant.
- **Write path**: `audit.Record` with `audit.PlatformTenant` inside a platform-pool transaction; the same entry format, hash chain and `Verify` as tenant chains.
- **Which login events**: `user.login` success (the session cookie is sent only after its entry is written; the session (identity pool) and the entry (platform pool) can't share a transaction, so a failed entry ends the session and fails the login, a deliberate exception to [ADR-0027 Audit log](0027-audit-log.md)'s same-transaction rule), a disabled user refused, and refusals **after a verified ID token** (nonce, claims, `azp`). Failures before a verified token (no flow cookie, state mismatch, code exchange, bad signature) are **logged, not chained**: anyone can trigger them without an account, and chain writes are serialized.
- **Bootstrap admin** ([ADR-0031 Platform admin lifecycle](0031-platform-admin-lifecycle.md)): granted at login when `LICENSEFORGE_BOOTSTRAP_ADMIN` matches the stored user and there is no platform admin yet, recorded as `platform_admin.bootstrap` (actor `system`) in the grant's transaction. A failed bootstrap doesn't fail the login.

## Consequences
- Every login writes one platform-chain entry, so all logins serialize on that chain's advisory lock. A caller with raw SQL access can hold that lock (advisory locks are callable by PUBLIC) and stall logins for every tenant; per-tenant chains already had this property for their tenant.
- The platform chain grows fastest (one entry per login): `Verify`'s in-memory walk ([ADR-0027 Audit log](0027-audit-log.md)) needs paging before retention and SIEM export.
- The slug `platform` is taken; creating a tenant with it fails as a duplicate.
- The pinned `app_tenant_id()` body ([ADR-0009 Multi-tenancy](0009-multi-tenancy.md) release-blocking test) changes with this ADR.
- ADR-0027's "failed logins for unknown accounts" is narrowed on purpose: users are created at login, so an unknown account only exists before a verified token, which is logged, not chained.

## Alternatives considered
- **A `reserved` column on tenants**: every policy, present and future, would have to test it.
- **Chain every login failure**: complete, but an unauthenticated amplifier for serialized writes; pre-token failures are noise better served by logs and metrics.
