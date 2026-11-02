# ADR-0020 Admin dashboard

*Status: accepted · Date: 2026-11-02*

## Context
A very good dashboard is required to sell the product and to demo to design partners; curl doesn't sell. It must be multi-tenant: one person, many tenants; one hosted operator, many vendors.

## Decision
### Architecture
- **React + TypeScript + Vite** SPA, **TanStack Query/Router**, **shadcn/ui + Tailwind** components.
- API client **generated from the OpenAPI spec** (one source of truth; the dashboard uses only the public API, so anything it does is scriptable).
- Built static files are **embedded in the Go binary** (`go:embed`) and served by the server: still one container, one Helm release.
- **BFF session pattern**: Go server does the OIDC login, keeps the session server-side (Postgres), browser holds only an `HttpOnly; Secure; SameSite=Lax` cookie + CSRF token. No tokens in browser storage.

### Multi-tenant UX
- Tenant in the URL: `/t/{tenant-slug}/products/...`, so links are shareable and tabs can show different tenants.
- Tenant switcher in the header; last-used tenant remembered.
- UI hides actions the user's role can't do, but the API is the real check ([ADR-0019 Authorization model](0019-authorization-model.md)).
- **Platform admin area** (`/platform`) for the hosted operator: tenants, usage, suspend, audited impersonation.
- Test-mode tenants clearly marked (banner/colour).

### Screens
| v0.1 (demoable) | v0.2 (complete) | v0.3 |
|---|---|---|
| Login, tenant switcher, members/invites | Audit log viewer with filters | Customer self-service portal (separate app, same stack) |
| Products, **feature catalog**, plans, **feature × plan matrix** ([ADR-0015 Feature catalog per product](0015-feature-catalog-per-product.md)) | API tokens, webhooks + delivery log | Billing connectors setup |
| Customers, licenses (issue / suspend / revoke / rehost), activations | Offline activation upload/download | Usage counters |
| License detail: entitlements, machines, history | Signing keys and rotation | |
| Overview: active customers, activations, failures | Metrics charts | |

Also: dark mode, keyboard-navigable, WCAG AA, i18n-ready strings (English first).

## Consequences
- Basic dashboard moves **from v0.2 into v0.1**; v0.2 completes it.
- A separate frontend toolchain (Node) in the repo, built in CI; release artifact is still one Go binary/image.
- Frontend skills needed on the team; shadcn/ui keeps it consistent without a designer early on.

## Alternatives considered
- **Server-rendered Go templates + htmx**: no Node, but a rich matrix editor and charts get painful.
- **Next.js**: needs a Node server at runtime; breaks single-binary deployment.
- **Separate dashboard container**: more to deploy for self-hosters, for no gain.
