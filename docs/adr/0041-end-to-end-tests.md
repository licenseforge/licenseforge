# ADR-0041 End-to-end tests

*Status: accepted · Date: 2026-11-08*

## Context
Go tests run the services against a real PostgreSQL, and the dashboard's tests run against a stubbed API. Both test parts in isolation. Deploying `0.1.0-alpha.1` on minikube and clicking through it found four dead ends in about half an hour: no way to create a tenant; an issue form asking for a plan ID the dashboard showed nowhere; no dashboard way to create the signing key that every activation needs; and site licenses that no app can consume yet. Each part worked; the journey didn't. Nothing exercised the real binary, chart, identity provider and SDK together. The maintainer wants e2e tests run locally first, so they don't load the CI pipelines, with a path to CI later.

## Decision
- **The environment** is a real deployment, not a mock: minikube with the ingress addon; PostgreSQL 17 set up by `deploy/database-setup.sql`; Keycloak as the OIDC provider; LicenseForge installed by its Helm chart, either the published chart and image of a release or a chart and image built from the checkout. Everything is served over HTTPS on `*.<minikube ip>.nip.io` hostnames, signed by a local CA that the script creates. It lives in `e2e/env/` with one script, `up.sh`, and is for local use only (dev passwords throughout).
- **Two layers of tests:**
  1. **API journeys in Go** (`e2e/`, build tag `e2e`, `make e2e`). They log in through Keycloak like a browser, then drive the management API and the Go SDK as a vendor's app does: catalog, signing key, issue, activate, verify the lease offline, refresh, revoke, refused refresh. They import only the module's own packages and the standard library. The TypeScript and Java SDKs, as built from the checkout, run the same customer app one step per process through a small driver each (`e2e/sdk/`), with a restart from the saved lease, suspend/reinstate and the HTTP status of each refusal added. The maintainer runs `make e2e` on the commit an SDK release is tagged from (docs/verifying-releases.md); the release workflows can't enforce it until the suite runs in CI. (Amended 2026-11-11.)
  2. **Browser smoke tests** with Playwright, added separately: one or two journeys through the real dashboard. Playwright is a new development dependency.
- **Isolation:** each run creates its own uniquely named products, plans, customers and licenses in the shared test tenant and never depends on earlier runs, so the environment can be reused between runs.
- **The test tenant is created through the product:** `up.sh` runs `licenseforge tenant create` ([ADR-0042 Platform tenant onboarding](0042-platform-tenant-onboarding.md)) once per environment, and runs share that tenant. A journey creates a new tenant through the platform API on every run, so onboarding itself is tested. Giving every journey its own tenant would also mean a signing key and its setup per run, for no extra coverage. (Amended 2026-11-08: the original text had journeys switch to their own tenants once platform routes existed.)
- **Local only for now.** `make e2e` needs a running environment and isn't part of `make test` or of CI. A nightly CI job on kind with the same script is the intended next step once the suite is stable.

## Consequences
- An e2e run needs minikube with about 4 CPUs and 6 GB of memory. The first `up.sh` takes a few minutes, mostly pulling images; later runs reuse the environment.
- Journeys test what customers run: the chart, the image and the published API. A dead end like the four above fails a journey.
- The suite isn't a gate yet, so a broken journey is noticed when someone runs it. Each PR that changes a journey's path runs `make e2e` locally and says so.

## Alternatives considered
- **docker compose with a mock IdP:** faster, but it skips the chart, the ingress and a real OIDC provider, which is where deployment gaps show up.
- **Browser tests only:** slow and brittle for the license and SDK paths, which have no UI.
- **In CI on every PR now:** the maintainer chose local first to keep pipelines light.
