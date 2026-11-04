# ADR-0029 Identity tables and tenancy

*Status: accepted · Date: 2026-11-04*

## Context
[ADR-0019 Authorization model](0019-authorization-model.md) defines users `(issuer, sub)`, memberships (user × tenant × role, optional product scope), invitations and API tokens. [ADR-0009 Multi-tenancy](0009-multi-tenancy.md) puts every row under a tenant with one canonical RLS pattern, and the tenant pool only sees `app.tenant_id`'s rows. A **user is not tenant-scoped**: one person can belong to several tenants. And at login the server must find the user and their tenants *before* any tenant is known (the tenant switcher in [ADR-0020 Admin dashboard](0020-admin-dashboard.md)). That doesn't fit the canonical pattern, so it needs a decision.

## Options
1. **Identity resolution in the platform pool.** Login (find/create the user by `(issuer, sub)`, list their memberships for the tenant switcher, accept an invitation) runs through a small `identity` package on the platform pool. Every tenant request then runs on the tenant pool as today.
2. **A second RLS key** `app.user_id`: users and memberships readable where `user_id = app.user_id`. Login still needs a lookup by `(issuer, sub)` before the user ID is known, so it would need a SECURITY DEFINER function, which ADR-0009 refuses.
3. **Copy users per tenant** (a user row per membership). Breaks "one person, one identity", makes tenant switching and offboarding messy.

## Decision (option 1, with its own database login)
### A fourth login: identity
The login path handles untrusted OIDC claims on the internet-facing path, so it must not run with platform rights (all tenants). **This amends [ADR-0009 Multi-tenancy](0009-multi-tenancy.md)**: a fourth group role `licenseforge_identity` with its own login and pool, granted only what login needs:

| Table | identity | tenant pool (`licenseforge_app`) | platform |
|---|---|---|---|
| `tenants` | SELECT (id, slug, name), excluding the reserved platform tenant | own row (unchanged) | all |
| `users` | SELECT; INSERT; UPDATE (email, name, last_login_at) | SELECT (id, email, name) of members of the current tenant only | SELECT, UPDATE |
| `memberships` | SELECT; INSERT only as an invitation's acceptance (policy below) | SELECT; UPDATE (role); DELETE | all |
| `membership_products` | INSERT only the accepted invitation's products (policy) | SELECT, INSERT, DELETE | all |
| `invitations` | SELECT; UPDATE (accepted_at, accepted_by) | SELECT; INSERT; UPDATE (revoked_at) | all |
| `invitation_products` | SELECT | SELECT, INSERT | all |
| `platform_admins` | SELECT | none | all |
| `audit_events` | SELECT, INSERT under `app.tenant_id` (the invitation's tenant) | unchanged | unchanged |
| licensing tables | **none** | unchanged | unchanged |

Every table uses FORCE row-level security, so the identity role has explicit `identity_*` policies on each table it touches (with none, PostgreSQL silently returns no rows); the isolation test checks the exact policy set for all three serving roles. UPDATE grants are column grants: identity can never change `disabled_at`, `issuer`, `subject`, an invitation's role or scope, and the tenant pool can only revoke an invitation.

### Acceptance is enforced by the database
A bug on the login path must not be able to add anyone to any tenant, so the database ties every new membership to its invitation:
- `memberships.invitation_id` is NOT NULL and UNIQUE (an invitation is used once; a double accept creates nothing), with key `memberships_invitation_same_tenant (tenant_id, invitation_id) → invitations (tenant_id, id)`; `UNIQUE (tenant_id, user_id)`.
- Policy `identity_accept` (INSERT, identity role), `WITH CHECK`:
  `tenant_id = app_tenant_id() AND EXISTS (SELECT 1 FROM invitations i JOIN users u ON u.id = memberships.user_id WHERE i.id = memberships.invitation_id AND i.tenant_id = memberships.tenant_id AND i.role = memberships.role AND i.scope_all = memberships.scope_all AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now() AND lower(u.email) = lower(i.email))`.
- Product scope is explicit: `scope_all` boolean on invitations and memberships (never "no rows = all products"); `membership_products` rows may only copy the invitation's `invitation_products` (policy on the identity INSERT).
- The acceptance transaction sets `app.tenant_id` to the invitation's tenant and writes its audit entry in the same transaction (ADR-0027: no unrecorded change). Like the api login (ADR-0009's documented limitation), this guards against SQL bugs, not arbitrary SQL execution.

`store.Open` checks the identity login like the other two (its allow-list already refuses membership in any other group); `deploy/database-setup.sql`, the Helm Secret and the env list gain it. A bug on the login path can at most read identity data and accept invitations that exist; it can't touch licenses or keys, or add anyone to a tenant without an invitation.

### Global tables (exempt from "every row has tenant_id")
- **`users`** (`usr_`): `issuer`, `subject`, `email`, `name`, `last_login_at`, `disabled_at`; unique `(issuer, subject)`. `email` is not unique and never a lookup key (except the bootstrap admin, below).
- **`platform_admins`** (user ID), and later the dashboard **sessions** of [ADR-0020 Admin dashboard](0020-admin-dashboard.md) (per user).
- They get their own canonical patterns in the isolation test. ent queries of `users` on the tenant pool must `.Select(id, email, name)` (the column grant makes anything else fail loudly). The tenant pool's read of `users` is a **column grant** (id, email, name) with policy `users_member_of_tenant`: `EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = users.id AND m.tenant_id = app_tenant_id())`. The subquery runs under `memberships` RLS, so it sees only the current tenant; with `app.tenant_id` unset it returns nothing (tested).
- References from tenant tables to `users` (`memberships.user_id`, `invitations.invited_by`, `api_tokens.created_by`) have no `*_same_tenant` key: users belong to no tenant. That is safe because the tenant pool can't INSERT memberships: a tenant admin can't attach an arbitrary user ID to read their profile or pull them into the tenant.

### Tenant tables
- **`memberships`** (`mem_`): user × tenant × role, `scope_all` or `membership_products` rows (`*_same_tenant` keys), `invitation_id`. Created **only** by accepting an invitation (above); changed and removed by tenant admins ([ADR-0019 Authorization model](0019-authorization-model.md) `CanAssign`). **Last owner**: a demotion or removal first locks the tenant's owner memberships (`SELECT … WHERE role = 'owner' FOR UPDATE`), then refuses if none would remain, so two owners demoting each other can't leave the tenant without one.
- **`invitations`** (`inv_`): email, role, `scope_all` or `invitation_products` rows, `invited_by`, `expires_at` (default 7 days), a **single-use token** (shown once in the invite link, stored as a hash), `accepted_at` / `accepted_by` / `revoked_at`. The role and scope can't exceed the inviter's (`CanAssign`).
- **`api_tokens`** (`tok_`): role, optional product scope, `created_by`, `last_used_at`, hash and display prefix (#25). **Expiry is required**: default 90 days, at most 1 year. The role and scope can't exceed the creator's at creation (`CanAssign`). The hash is unique per `(tenant_id, hash)`, not globally, so an insert conflict can't reveal another tenant's token.

### Login and invitations
- **Login** (identity pool): upsert the user by `(issuer, sub)`; refresh `email` from claims **only when `email_verified` is true** (otherwise a user could make their member-list entry look like a colleague); list memberships for the tenant switcher.
- **Accepting an invitation** (this amends ADR-0019's "accepted by logging in") needs all of: the invite link's token, a logged-in user whose email matches (compared case-insensitively after Unicode NFC), `email_verified` true, invitation not expired or revoked. Acceptance is an explicit click, never automatic on login; the user can decline.
- **Requests** name the tenant by slug in the URL; the slug is resolved to an ID once per request (identity pool, or the session), then the tenant pool runs with `app.tenant_id` and the membership for `(user, tenant)` is checked before building the `authz.Principal`.
- **API tokens** carry no tenant: the lookup by hash runs on the tenant pool under the URL's tenant. Unknown and wrong-tenant tokens get the same response and the same work (no timing difference).
- **Platform admin**: `platform_admins`, bootstrapped by `LICENSEFORGE_BOOTSTRAP_ADMIN` ([ADR-0003 Identity via generic OIDC, Keycloak as default](0003-identity-via-generic-oidc-keycloak-as-default.md)) **on the platform pool and only while `platform_admins` is empty**, so a removed admin isn't re-granted on the next login. The `issuer|sub` form is recommended; an email value only matches with `email_verified` true.
- **Trusted issuers**: `email_verified` is only as trustworthy as the weakest configured issuer; the docs say so, and an invitation can optionally be bound to one issuer.
- **Login events** (failed logins for unknown accounts, platform-admin logins) go to the platform chain ([ADR-0027 Audit log](0027-audit-log.md)) through the platform pool's `audit.Record`; the reserved platform tenant is hidden from the identity pool's `tenants` read, the switcher and slug resolution.
- **Suspension** (`disabled_at`, platform pool) also deletes the user's dashboard sessions, so access ends at once, not at the next login.

## Consequences
- Operators create a fourth login (one more line in the setup script and one more Secret key). In exchange the internet-facing login path has no access to licensing data.
- A user who belongs to no tenant any more is kept (re-invitable) until erased.

## Resolved at acceptance (2026-11-04)
Decided under the maintainer's delegation ("what is best for the product and for people to adopt it"):
- **User erasure (GDPR)**: `licenseforge user erase <usr_id>` (owner login, like `tenant purge` in ADR-0009) deletes the user row, their memberships, the invitations they accepted and every invitation addressed to their email, and nulls `invited_by` / `created_by` (tokens stay with the tenant). It refuses while the user is a tenant's last owner (hand over first). Audit entries keep the opaque user ID; source IP and user agent in them age out by retention ([ADR-0027 Audit log](0027-audit-log.md)), and audit `details` must never carry emails. If the person logs in again they get a new `usr_` ID. `disabled_at` is suspension (login refused, everything kept), not erasure.
- **API tokens belong to the tenant** (ADR-0019: the tenant issues them), so offboarding a person doesn't silently break integrations. But removing a member **defaults to revoking their tokens**: the dashboard lists them with "revoke all" preselected, and each revocation is audited. Required expiry, the role cap at creation and `last_used_at` keep forgotten tokens from becoming standing access (SOC 2 deprovisioning).
