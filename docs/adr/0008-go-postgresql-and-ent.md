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
