# ADR-0038 Per-tenant MFA policy

*Status: accepted · Date: 2026-11-05*

## Context
[ADR-0024 HIPAA, NIST and FedRAMP readiness from day 1](0024-hipaa-nist-and-fedramp-readiness-from-day-1.md) requires MFA enforcement per tenant through the ID token's `amr`/`acr`, including a "phishing-resistant MFA" policy (passkeys, PIV/CAC through the IdP) (IA-2(1), IA-2(2), IA-2(6), IA-2(8)). LicenseForge doesn't authenticate people itself ([ADR-0003 Identity via generic OIDC, Keycloak as default](0003-identity-via-generic-oidc-keycloak-as-default.md)); it can only check what the IdP asserts. A session can reach several tenants with different policies. Decided under the maintainer's delegation.

## Decision
### Policy
- `tenants.mfa_policy`: `none` (default), `mfa`, `phishing_resistant`. Changed only by owners (`tenant:write`) from a session through `PATCH /api/v1/tenants/{tenant}`, audited as `tenant.mfa_policy.update` (from, to).
- **No self-lockout**: raising the policy is refused (`409 mfa_policy_unmet`) unless the caller's own session meets the new level.
- The tenant pool gets a column grant of UPDATE on `mfa_policy` (and `updated_at`) only, under a permissive UPDATE-only policy `id = app_tenant_id()`; the RLS pin changes with it.

### Session assurance
- At login the session stores the verified ID token's `amr`, `acr` (and Entra's `acrs`), `auth_time`, and a computed level `none` / `mfa` / `phishing_resistant`. Missing or unknown claims mean `none` (fail closed).
- Default value sets, all configurable (`LICENSEFORGE_OIDC_*`):
  - **phishing-resistant**: `amr` contains `hwk`, `sc` or `pop`; or a configured `acr`/`acrs` value (e.g. Okta `phr`, `phrh`; an Entra authentication context that requires phishing-resistant MFA);
  - **MFA**: the above, or `amr` contains `mfa`, `otp` or `swk`.
  - `pwd`, `sms`, `tel` never count. `swk` isn't phishing-resistant by default (RFC 8176 doesn't say the key is WebAuthn); deployments with synced passkeys can add it.
  - On Entra the `acrs` claim is the signal of record; its `amr` is advisory.
- Support for each IdP (Keycloak, Entra, Okta) is claimed only after an integration test with its configuration documented.

### Enforcement
- Checked on every request that resolves a tenant, right after the membership check: a non-member still gets 404 (the policy isn't revealed), a member whose session falls short gets `403 mfa_required` with the required and current levels and a step-up URL. A policy change applies to live sessions on their next request.
- **Step-up**: `/auth/login?assurance=<level>` sends `acr_values` (when configured) and `max_age=0` with a validated same-origin return path, and replaces the session with a fresh one. The first login never forces `acr_values`. The result is checked from the returned claims, never assumed; the dashboard explains, rather than loops, when the IdP still doesn't deliver.
- `/me/tenants` keeps listing every membership and adds `mfa_policy` and `accessible`.
- Accepting an invitation isn't gated; using the tenant afterwards is.
- Refusals are audited **once per session per tenant** (on the tenant's chain) and counted in a metric on every refusal, so a polling dashboard can't flood a serialized chain.
- No maximum age since authentication per tenant for now: the 12-hour absolute session cap bounds it.

### API tokens
- Tokens are exempt at use (machines have no `amr`); creating one requires a session that meets the tenant's policy. Raising the policy doesn't revoke existing tokens; the response reports how many active tokens were created before the change, and the dashboard links to them.

### Platform admins
- `LICENSEFORGE_PLATFORM_MFA_POLICY` (default `none`, so a self-hosted install without IdP MFA can't lock out its operator; the hosted and FedRAMP chart values set `phishing_resistant`). The bootstrap grant isn't gated.
- Platform access inside a tenant must meet the stricter of the platform and tenant policies. A platform admin may lower a tenant's policy to recover a locked-out tenant, audited on that tenant's chain.

## Consequences
- One migration (column, grant, policy) and new session columns; the login path records claims it ignored before.
- Owners can require MFA without trusting every member's IdP setup; enforcement is only as strong as the IdP's assertions, which the Secure Configuration Guide states.
- PRs: (1) session assurance + policy column/endpoint; (2) enforcement, step-up, `/me/tenants`; (3) dashboard interstitial and policy setting.

## Alternatives considered
- **Check only at login**: a policy raised later wouldn't apply to live sessions, and one session spans tenants.
- **Request `acr_values` at every login**: forces the strongest method on everyone and breaks IdPs that don't support it.
- **Gate API tokens too**: tokens carry no authentication context; the creation gate and ADR-0035 bound them instead.
- **Audit every refusal**: an authenticated member could stall the tenant's chain.
