# ADR-0047 Test-mode tenants

*Status: accepted · Date: 2026-11-10*

## Context
Vendors integrate the SDK, try plans and run CI against LicenseForge before they sell. Cryptlex, LicenseSpring and Keygen offer sandboxes (Licensing competitor feature gaps). The Roadmap's v0.2 item is "test-mode tenants/keys, excluded from metrics", and [ADR-0020 Admin dashboard](0020-admin-dashboard.md) asks for test-mode tenants to be clearly marked.

A tenant already isolates almost everything a sandbox needs: its own signing keys ([ADR-0026 Signing key lifecycle](0026-signing-key-lifecycle.md)), data under RLS, members and API tokens. A build trusts one tenant's public keys, so it never accepts a file signed by another tenant. What's missing is a way to say that a tenant is for testing, so that people see it and usage measures leave it out. Decided under the maintainer's delegation of 2026-11-04 (work log 2026-11-10).

## Decision
- **Test mode is a property of the tenant**: a `test` boolean, set when the tenant is created and **never changed**.
  - A live tenant can't turn test, which would hide its usage from billing ([ADR-0016 Hosted pricing model](0016-hosted-pricing-model.md)).
  - A test tenant can't go live, which would mix test licenses and keys with sold ones. To go live, create a live tenant.
  - The database enforces this: the serving login has no UPDATE grant on the column, and a restrictive policy (`test_fixed`) holds the platform pool, which can update the table.
- **Created by a platform admin**, like any tenant ([ADR-0042 Platform tenant onboarding](0042-platform-tenant-onboarding.md)): `"test": true` in `POST /platform/tenants`, and `licenseforge tenant create --test`. The default is live.
- **Visible everywhere the tenant is**: `test` in `/me/tenants` and the platform tenant list.
  - The dashboard shows a persistent "Test mode" banner in a test tenant, and marks it in the tenant switcher and on the platform page.
  - On the signing keys page, the banner says not to embed these keys in release builds.
- **Excluded from usage measures across tenants**: when hosted billing or any platform-level aggregate counts tenants, active customers or licenses ([ADR-0016 Hosted pricing model](0016-hosted-pricing-model.md), [ADR-0040 Active customer measure](0040-active-customer-measure.md)), it leaves out test tenants. There is no such aggregate today, so this is a rule for the future.
  - A test tenant's own `summary` and daily series still show its data: they describe that tenant alone. This amends ADR-0046's "Test mode" note.
  - Prometheus metrics stay operational and include test traffic.
- **No change to the license format**: a test tenant's files and leases are signed with its own keys. They are kept out of production builds by the key set, not by a claim. Test and live licenses differ by tenant; the license `type` (dev, trial, paid, community) is a separate thing.

## Not included
- Per-key or per-license test mode inside a live tenant: it would mix test and sold data in one tenant, and every count would need a filter.
- Limits on test tenants (row caps, expiry): add when hosting needs them.
- Copying the catalog from a test tenant to a live one: a later import or export feature.

## Consequences
- One immutable column, one create parameter, and a dashboard banner. Nothing changes in signing or verification.
- A vendor runs two tenants, `acme-test` and `acme`, with separate keys, members and tokens. CI uses the test tenant's tokens.
