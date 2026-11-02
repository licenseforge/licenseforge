# ADR-0008 Go, PostgreSQL and ent

*Status: accepted · Date: 2026-11-02*

## Context
Need a language for a stateless, security-sensitive API server shipped as a container, plus a CLI and the Go SDK, and a data-access layer.

## Decision
- **Go** for server and CLI. Single static binary, distroless images, Ed25519 in stdlib, FIPS 140-3 module, dominant in the Kubernetes ecosystem.
- **PostgreSQL** as the only datastore.
- **ent** as ORM (schema-as-code, generated type-safe client, graph traversal fits Tenant → Product → Plan → License → Activation).
- **Atlas versioned migrations** (ent's companion tool) checked into the repo. No `client.Schema.Create` auto-migration in production.
- Tenant isolation ([ADR-0009 Multi-tenancy](0009-multi-tenancy.md)): an ent **privacy policy / interceptor** adds `tenant_id` filters on every query, and a transaction hook runs `SET LOCAL app.tenant_id = ...` so Postgres RLS is the backstop.
- Activation counting: lock the license row (`ent` `ForUpdate()` with the sql/lock feature flag) inside a transaction to enforce `max_activations` under concurrency.
- No cache, queue, or search engine in v0.1.

## Implementation note (2026-11-02)
- **IDs**: text primary keys `<prefix>_<26 lowercase base32 chars>` (128 random bits), e.g. `tnt_…`, `prd_…`: readable in logs and licenses, no UUID dependency.
- **Migrations**: Atlas (library, via ent) *generates* versioned SQL at dev time (`internal/store/tools/migrate diff|hash|check`); hand-written SQL (grants, RLS policies) sits next to it with `atlas.sum` rehashed. The server *applies* them as the owner login with a small built-in runner: embedded files, one transaction per file with `lock_timeout = 30s` (a first line `-- lf:no-transaction` runs a single-statement file outside a transaction, e.g. `CREATE INDEX CONCURRENTLY`), a session advisory lock so replicas starting together apply once, a SHA-256 checksum per applied file (edited files are refused), and refusal of unknown newer or out-of-order versions. No Atlas CLI in the image or Helm chart.
- **Database constraints**: column sizes (`varchar(n)`) and `CHECK` constraints for ID and slug formats and non-empty names are enforced by PostgreSQL, not only by ent validators. `tenant_id` immutability is enforced by ent and by the tenant policy's `WITH CHECK`; platform code must never move rows between tenants.
- Migrations live in `internal/store/migrations` (Go embed can't reach a root `migrations/` dir).
- CI: generated code must be current, and `migrate check` fails if the schema needs a migration that isn't committed.

## Consequences
- One repo, one binary, one DB. Easy for self-hosters.
- ent codegen adds a `go generate` step to the build; generated code is committed.
- RLS isn't native to ent: the session-variable hook must be tested (a test that a cross-tenant query returns nothing even with the app filter disabled).

## Alternatives considered
- **sqlc**: SQL-first, less magic, but more boilerplate for a graph-shaped model.
- **GORM**: runtime reflection, weaker typing.
- **Rust**: safer, slower iteration, smaller contributor pool.
- **Java/Kotlin**: heavier runtime and images.
- **Node/TypeScript**: weaker single-binary CLI and crypto story.
