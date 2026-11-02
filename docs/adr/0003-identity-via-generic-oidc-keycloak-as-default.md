# ADR-0003 Identity via generic OIDC, Keycloak as default

*Status: accepted · Date: 2026-11-02*

## Context
LicenseForge needs login for humans (vendor admins, later end-customer portal users) and auth for machines (CI, billing webhooks, SDKs). Options: build our own auth, depend on Keycloak specifically, or speak standard OIDC.

There is no "licensing certification" a dependency gives us. What reduces risk is never building password storage, MFA, recovery and brute-force protection ourselves.

## Decision
**LicenseForge is an OIDC relying party, never an identity provider.**

- Generic OIDC in Go with **`github.com/coreos/go-oidc/v3`** + **`golang.org/x/oauth2`** (same libraries Dex and much of the Kubernetes ecosystem use). Authorization Code + PKCE for the dashboard; JWT access-token validation for API clients.
- Works with any compliant IdP: Keycloak, Entra ID, Okta, Auth0, Google, Zitadel, Authentik, Dex.
- **No Keycloak-specific features** (no Keycloak Authorization Services, UMA, realm roles as our permission source). Keycloak is replaceable.
- Helm chart ships **Keycloak as an optional subchart** for batteries-included installs.
- **Hosted cloud** runs Keycloak; per-tenant enterprise SSO (a vendor bringing their own Okta/Entra) uses Keycloak **identity brokering**. This is where Keycloak earns its place.
- Config: a list of trusted issuers (`issuer`, `client_id`, claim mapping for email). User identity = `(issuer, sub)`, never email alone.
- **Authorization is ours, not the IdP's** ([ADR-0019 Authorization model](0019-authorization-model.md)). The IdP proves *who*; LicenseForge decides *what*.

### Three kinds of caller
| Caller | Authenticates with | Issued by |
|---|---|---|
| Human in dashboard | OIDC login → server-side session cookie ([ADR-0020 Admin dashboard](0020-admin-dashboard.md)) | IdP |
| Machine (CI, scripts, integrations) | LicenseForge **API token** (opaque, shown once, stored hashed, scoped) or IdP client-credentials JWT | LicenseForge / IdP |
| Vendor's app via SDK/agent | License key + fingerprint | LicenseForge |

### Bootstrap
`LICENSEFORGE_BOOTSTRAP_ADMIN` (email or `issuer|sub`) becomes platform admin on first login. Everyone else joins by invitation.

## Consequences
- SSO, MFA, passkeys, password policy come from the IdP.
- We maintain ~a few hundred lines of OIDC glue, using audited libraries.
- Self-hosters without an IdP use the Keycloak subchart.

## Alternatives considered
- **Build our own auth**: biggest security liability in the product; no.
- **Keycloak-only, use its authz services**: lock-in, Java-centric config, hard to self-host lightly, tenant model doesn't map cleanly.
- **Embed Dex / ory**: another component to run; doesn't remove the need for an upstream IdP.
