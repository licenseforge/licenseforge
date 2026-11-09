# ADR-0042 Platform tenant onboarding

*Status: accepted · Date: 2026-11-08*

## Context
A tenant can't be created through the product: no route, no command, no screen. Installs and the e2e environment ([ADR-0041 End-to-end tests](0041-end-to-end-tests.md)) seed one with SQL. [ADR-0019 Authorization model](0019-authorization-model.md) gives a platform admin flag "outside tenant roles" (list tenants, suspend, impersonate). [ADR-0031 Platform admin lifecycle](0031-platform-admin-lifecycle.md) covers how admins are granted and removed. [ADR-0032 REST API conventions](0032-rest-api-conventions.md) reserves `/api/v1/platform/…`. [ADR-0038 Per-tenant MFA policy](0038-per-tenant-mfa-policy.md) defines `LICENSEFORGE_PLATFORM_MFA_POLICY`, which gates nothing until a platform route exists. Decided under the maintainer's delegation.

## Decision
- **First routes:**
  - `GET /api/v1/platform/tenants`: the tenants, newest first, cursor-paged (ADR-0032). The reserved platform tenant isn't listed.
  - `POST /api/v1/platform/tenants` with `{slug, name, owner_email}`: creates the tenant **and an owner invitation** for that email, in one transaction on the platform pool. It answers 201 with the tenant and the invitation, whose **token appears in this response only**, as for tenant invitations.
  - Suspending, impersonating and granting platform admins come later, each with its own line here or a new ADR.
- **The first owner joins through the normal invitation flow** ([ADR-0029 Identity tables and tenancy](0029-identity-tables-and-tenancy.md)): they sign in with the invited, verified email and accept. The platform admin doesn't become a member of the tenant. The invitation has role owner and every product, with the same 7-day expiry, token hashing and acceptance checks as any invitation.
- **Who may call:** a dashboard session whose user is a platform admin and isn't disabled. It's checked on every request on the platform pool. API tokens are tenant-scoped (ADR-0035) and get 401 on platform paths. A signed-in user who isn't a platform admin gets **403 `forbidden`**: the paths are public, so there's nothing to hide. CSRF protection is the same as on other session writes.
- **Platform MFA policy:** `LICENSEFORGE_PLATFORM_MFA_POLICY` (`none` by default, as ADR-0038 says) is checked on every platform request against the session's assurance. A session that falls short gets `403 mfa_required` with a step-up URL that comes back to the platform screen.
- **Validation:** the slug follows the tenant slug rules (it can't be the reserved platform tenant's slug, and a taken slug is 409). The name follows the usual name rules. The email is validated as for invitations.
- **Audit:**
  - `tenant.create` goes on the platform chain, with the platform admin as actor and the tenant's slug in the details.
  - `invitation.create` goes on the new tenant's chain, as the tenant's first entry, with the same details as a tenant invitation (role, scope, expiry, never the email).
  - Refusals are audited on the platform chain.
- **Headless installs:** `licenseforge tenant create --slug … --name … --owner-email …` does the same on the platform login (`LICENSEFORGE_PLATFORM_DATABASE_URL`). It records the system as actor (`via: cli`) and prints the invite path once, to be prefixed with the public URL.
- **Dashboard:** platform admins get a Tenants screen (list, create, the invite link shown once). The session endpoint says whether the user is a platform admin, so the screen appears only for them.

### Re-issuing the owner invitation (amended 2026-11-09)
- `POST /api/v1/platform/tenants/{id}/owner-invitation` with `{owner_email}` (the same or a corrected address), and `licenseforge tenant invite-owner --tenant SLUG|ID --owner-email E` on the platform login: a new owner invitation, the token in the response only, as at creation. Needed when the create response was lost or the invitation expired: until then the tenant had no way in (the slug is taken, the admin isn't a member).
- **Only while the tenant has no owner**: once an owner exists, the tenant runs its own invitations (409 `conflict`). Platform admins never add members to a tenant that has one, keeping ADR-0019's separation.
- Every pending owner invitation of the tenant is revoked in the same transaction, so a lost link can't be used afterwards. The pending invitations are locked before the owner check, the lock acceptance takes, so a concurrent acceptance either wins (409) or finds its invitation revoked.
- Audit: `tenant.owner_invitation` on the platform chain (the tenant, the number revoked); on the tenant's chain `invitation.revoke` for each revoked invitation and `invitation.create` for the new one (never the email). Refusals on the platform chain.

## Consequences
- Installs, the hosted offering and the e2e journeys onboard tenants through the product. The SQL seed in `e2e/env` goes.
- The platform MFA policy now has something to gate.
- Platform admins can create tenants but can't see inside them, which matches ADR-0019's separation of platform and tenant roles. Support-style access (impersonation, with audit) stays a later decision.

## Alternatives considered
- **Make the platform admin the first owner**: it mixes platform and tenant roles, and the operator would have to hand ownership over by hand.
- **CLI only**: hosted onboarding needs the API and the dashboard. The CLI covers air-gapped and headless installs.
