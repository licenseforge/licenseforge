# ADR-0048 Admin CLI via the REST API

*Status: accepted · Date: 2026-11-10*

## Context
The Roadmap's v0.2 item is "`lf` CLI (admin + offline signing)". [ADR-0023 Repository structure](0023-repository-structure.md) planned an `lf` binary. Since then:
- Offline signing has shipped as `licenseforge offline activate|return` ([ADR-0043 Offline activation and deactivation receipts](0043-offline-activation-and-deactivation-receipts.md), #131). It calls the API with an API token.
- Headless onboarding has shipped as `licenseforge tenant create|invite-owner`, on the platform database login ([ADR-0042 Platform tenant onboarding](0042-platform-tenant-onboarding.md)).

What's left is admin: issuing and changing licenses, customers and the catalog from scripts and CI. The REST API covers all of it with scoped tokens ([ADR-0035 API tokens follow their creator's access](0035-api-tokens-follow-their-creator-s-access.md)). Decided under the maintainer's delegation of 2026-11-04 (work log 2026-11-10).

## Decision
- **One binary.** The CLI is `licenseforge`'s subcommands, with no separate `lf` binary. Operators and vendors download and verify one signed release.
- **`licenseforge api METHOD PATH [--data JSON|@file|-]`** is the admin CLI. It sends one request to `$LICENSEFORGE_URL/api/v1` + PATH with `Authorization: Bearer $LICENSEFORGE_TOKEN`, the same environment as `offline`.
  - `{tenant}` in PATH is replaced by `$LICENSEFORGE_TENANT`.
  - It prints the JSON response body to stdout.
  - It covers every route the token may call, so the CLI can't drift from the API, and OpenAPI stays the reference.
  - Like `gh api`, it is scriptable with `jq`.
- **Behaviour:**
  - Only `GET`, `POST`, `PATCH` and `DELETE` are allowed.
  - PATH must start with `/` and stays under `/api/v1`. A full URL or `..` is refused, so the token never goes to another host.
  - It sends `Idempotency-Key` with `--idempotency-key`.
  - PATCH bodies use `application/merge-patch+json`, and other bodies `application/json`.
  - https only, unless the host is loopback. This is the same rule as `offline`, so a token is never sent in the clear.
- **Exit codes:** 0 for 2xx. 1 for an API problem: the body goes to stdout, and the problem's `code` and `detail` go to stderr. 2 for usage errors. 3 for transport errors (connection, TLS, timeout). Scripts can tell "the API said no" from "couldn't reach it".
- **Paging stays explicit.** A list's `next_cursor` is passed back with `?cursor=`. The CLI doesn't follow it.

## Not included
- Typed commands (`licenseforge license issue …`): add them when a frequent task needs flags rather than JSON.
- Interactive login, or tokens kept in a file: the token comes from the environment or a secret manager ([ADR-0011 Secret manager integrations](0011-secret-manager-integrations.md)).
- Offline signing with a local private key: keys stay in the server ([ADR-0026 Signing key lifecycle](0026-signing-key-lifecycle.md)), and offline files come from `offline activate`.

## Consequences
- One small command. Docs show recipes for the common tasks: issue a license, suspend, list a customer's licenses, renew maintenance.
- The Roadmap's "`lf` CLI" item is done with this, `offline` and `tenant`.
