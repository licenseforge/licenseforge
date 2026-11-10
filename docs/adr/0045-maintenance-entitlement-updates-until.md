# ADR-0045 Maintenance entitlement updates_until

*Status: accepted · Date: 2026-11-10*

## Context
Perpetual and long-term licenses are often sold with a maintenance period: the customer keeps using the versions released while maintenance was paid, and newer builds need a renewal ("perpetual fallback", as JetBrains, Sublime and Keygen's maintain-access strategy do it). [License File Format](../../spec/license-format.md) already defines the `updates_until` claim and the check (step 8: a build dated after `updates_until` → `updates_expired`). The Go SDK checks it against `BuildDate`, the `licenses.updates_until` column exists (ADR-0013 reserved it) and every lease and offline file copies it into the claims. Nothing sets it yet. Decided under the maintainer's delegation of 2026-11-04 (work log 2026-11-10).

## Decision
- **Plan term `updates_months`** (1–1200 calendar months, or null). Null means builds aren't limited: the license gets no `updates_until`, and every build is covered. Months only: maintenance is sold per month or year. Seconds would be needed only for tests, and a test can set the date directly.
- **Snapshot at issue**, like the other plan terms: `updates_until = issued_at + updates_months`, using the same month arithmetic as expiry (clamped to the month's last day), truncated to the second (the claim's precision).
  - It counts **from issue** whatever the plan's expiry basis. The customer paid for maintenance at the purchase, and a build release date doesn't depend on when the machine first activated.
  - Changing the plan later changes no license already issued.
- **Explicit date**: an issue request may set `updates_until` instead (a contract's maintenance end), overriding the plan.
- **Change later**: `POST /tenants/{t}/licenses/{id}/updates-until` with `{"updates_until": <timestamp> | null}` sets the value, either to renew maintenance or to correct it. It needs `license:write` on the license's product, the permission for edits like suspend.
  - Every change is audited as `license.updates_until`, with the old and new value.
  - Refused on a revoked license (final).
  - Billing connectors (v0.3) will renew through the same service call.
- **Invariant** (database CHECK): `updates_until` is null or later than `issued_at`. The service stores whole seconds; the claims truncate in any case.
- **Takes effect on the next file**: online leases pick it up at their next refresh. Offline files already issued keep the value they were signed with until they're replaced. The docs say so, as they do for suspensions.
- **No webhook event or payload field** for it yet (ADR-0044's payloads don't carry it). Both can be added when a receiver needs them.

## Consequences
- Vendors can sell perpetual-with-maintenance and subscription-with-fallback without custom code. The SDK enforcement already exists (Go; Java and TypeScript with their SDKs).
- Shortening maintenance is possible (a correction). It affects only builds dated after the new value, and only once the app gets a new file.
- Implementation, in steps:
  1. the plan term and the snapshot at issue;
  2. the explicit date at issue and the change endpoint;
  3. the dashboard.
