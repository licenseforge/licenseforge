# ADR-0037 User routes

*Status: accepted · Date: 2026-11-05*

## Context
[ADR-0032 REST API conventions](0032-rest-api-conventions.md) puts tenant resources under `/api/v1/tenants/{tenant}/…`, reserves `/api/v1/platform/…`, and gives the activation API its own prefix. Two endpoints act for the signed-in person rather than inside a tenant: accepting an invitation (PR #64) and listing the person's tenants for the dashboard switcher (PR #65). ADR-0032 doesn't cover them, and its list rules (cursor, newest first) don't fit a short per-user list. Decided under the maintainer's delegation.

## Decision
- **User routes** are a small, explicit allow-list of paths outside any tenant path: today `POST /api/v1/invitations/accept` and `GET /api/v1/me/tenants`. Matching is exact on the escaped path (no prefix or trailing-slash match); a wrong method gets the router's 405, and any other non-tenant path answers 404 to a session and 401 to a token.
- **Sessions only**: an API token on a user route answers 401, and so does any request on a configured API host (sessions are refused there, ADR-0032). CSRF and the cross-origin check apply to unsafe methods as everywhere.
- The handler gets a principal with **no tenant**, which `authz` denies every tenant permission; each user-route handler checks for exactly that principal (a user, no tenant) and acts as that user only; any tenant comes from the request's own proof (an invitation token), never from a path or the principal.
- **`/me/tenants`** returns the person's memberships (tenant ID, slug, name, role, product scope) in **one page sorted by slug**, at most 200 entries (the platform tenant is filtered in the query, so it never takes a slot); unknown query parameters answer 400. This is an exception to ADR-0032's *Lists* rules (cursor, `created_at` order) for `/me/tenants` only. The `{items}` envelope lets a cursor be added later; if it is, the default page stays at least 200, so clients that ignore `next_cursor` lose nothing they see today. The reserved platform tenant never appears (ADR-0033).
- New user routes need an ADR line here; everything else stays under tenant, platform or activation paths.

## Consequences
- The dashboard can build its tenant switcher and accept invitations through the public API, as ADR-0020 requires.
- A person with more than 200 memberships sees the first 200 by slug until pagination is added.

## Alternatives considered
- **Put them under a tenant path**: accept happens before membership exists, and the tenant list spans tenants.
- **Cursor pagination for `/me/tenants` now**: no real user has that many tenants; the envelope keeps the option open.
