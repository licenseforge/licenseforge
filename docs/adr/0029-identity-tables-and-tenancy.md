# ADR-0029 Identity tables and tenancy

*Status: accepted · Date: 2026-11-04*

## Context
[ADR-0019 Authorization model](0019-authorization-model.md) defines users `(issuer, sub)`, memberships (user × tenant × role, optional product scope), invitations and API tokens. [ADR-0009 Multi-tenancy](0009-multi-tenancy.md) puts every row under a tenant with one canonical RLS pattern, and the tenant pool only sees `app.tenant_id`'s rows. A **user is not tenant-scoped**: one person can belong to several tenants. And at login the server must find the user and their tenants *before* any tenant is known (the tenant switcher in [ADR-0020 Admin dashboard](0020-admin-dashboard.md)). That doesn't fit the canonical pattern, so it needs a decision.

## Options
1. **Identity resolution in the platform pool.** Login (find/create the user by `(issuer, sub)`, list their memberships for the tenant switcher, accept an invitation) runs through a small `identity` package on the platform pool. Every tenant request then runs on the tenant pool as today.
2. **A second RLS key** `app.user_id`: users and memberships readable where `user_id = app.user_id`. Login still needs a lookup by `(issuer, sub)` before the user ID is known, so it would need a SECURITY DEFINER function, which ADR-0009 refuses.
3. **Copy users per tenant** (a user row per membership). Breaks "one person, one identity", makes tenant switching and offboarding messy.

## Decision (option 1)
- **`users`** (`usr_`): `issuer`, `subject`, `email`, `name`, `disabled_at`; unique `(issuer, subject)`; **no `tenant_id`**. Platform pool: SELECT, INSERT, UPDATE of profile columns. Tenant pool: **SELECT only on users with a membership in the current tenant** (policy `users_member_of_tenant`, a join on `memberships` under the current `app.tenant_id`), so member lists show names and emails without exposing other tenants' users. A new canonical variant, added to the isolation test.
- **`memberships`** (`mem_`), **`invitations`** (`inv_`), **`api_tokens`** (`tok_`): ordinary tenant tables (canonical RLS, `*_same_tenant` keys), plus platform SELECT on memberships so login can list a user's tenants.
- **Login path** (platform pool, `identity` package only): upsert the user by `(issuer, sub)`, refresh email/name from claims, list memberships for the switcher, accept invitations matching a verified email. Every other request: tenant pool, membership checked for `(user, tenant from URL)`, then `authz.Principal`.
- **API tokens** carry no tenant; requests name the tenant in the URL (`/v1/tenants/{tenant}/…`), so the lookup by hash runs on the tenant pool under that tenant. A token used against another tenant's URL simply isn't found.
- **Platform admin**: a `platform_admins` table (user ID), platform pool only, bootstrapped by `LICENSEFORGE_BOOTSTRAP_ADMIN` ([ADR-0003 Identity via generic OIDC, Keycloak as default](0003-identity-via-generic-oidc-keycloak-as-default.md)).
- **Invitations** are accepted only for an email the IdP marks `email_verified`, and expire (default 7 days).

## Consequences
- The platform pool is used on the login path, not only for platform-admin operations. Kept narrow: one package, reviewed like `internal/tenant`, and no tenant data beyond memberships.
- One non-canonical policy (`users_member_of_tenant`) the isolation test must know about.
- Users survive tenant deletion; a user with no memberships left is kept (re-invitable) until a GDPR erasure removes them.

## Resolved at acceptance (2026-11-04)
Decided under the maintainer's delegation ("what is best for the product and for people to adopt it"):
- **User erasure (GDPR)**: a user row is erasable on request. Audit entries keep only the opaque user ID, which no longer resolves to a person once the row is gone ([ADR-0027 Audit log](0027-audit-log.md) retention removes the entries themselves later).
- **API tokens outlive their creator**: tokens belong to the tenant, so removing a member doesn't break the integrations they set up (CI, billing, provisioning). The dashboard shows each token's creator and last use, and admins revoke. Revoking a removed member's tokens is one click, not automatic.
