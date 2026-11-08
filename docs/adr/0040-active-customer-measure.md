# ADR-0040 Active customer measure

*Status: accepted · Date: 2026-11-08*

## Context
[ADR-0016 Hosted pricing model](0016-hosted-pricing-model.md) bills per **active customer** per month: "a customer with at least one activation, validation, or refresh in the billing month". For v0.1 it asks for a per-tenant active-customer count per month, as a "query + Prometheus metric". The metrics package and [ADR-0036 Audit retention and SIEM export](0036-audit-retention-and-siem-export.md) forbid tenant IDs as label values: they would leak which tenants exist and make cardinality unbounded. Decided under the maintainer's delegation.

## Decision
- **Measure**: the customers with at least one activation whose `last_seen_at` falls in the current calendar month in UTC, by the database clock. `last_seen_at` is set when a machine activates and on every refresh. Archived customers and deactivated machines seen in the month count, since they were used. Refused requests (revoked, suspended, expired licenses) don't update it, so they don't count.
- **Exposed per tenant** in `GET /tenants/{tenant}/summary` as `customers.seen_this_month`, with `customers.month_start`, under RLS. It has the same gate as the other customer counts: customer:read on every product, since customers are tenant-wide. The dashboard overview shows it.
- **No Prometheus metric**. A per-tenant count can't be a label. A platform-wide sum would need a database query per scrape, or a new background job, for a number that single-tenant self-hosters already get from the API. Hosted billing will read the database directly.

## Known limits
- "Validation" happens in the SDK, offline by design ([ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md)), so the server can't see it. The measure counts what reaches the server.
- The SDK refreshes at about half the lease. A plan with a lease longer than about two months may not refresh within a month, so the measure **undercounts** customers on such plans. With the 7-day default lease, a running machine refreshes about every 3.5 days.
- Site licenses (no activations) and air-gapped offline files have no server activity, so they are never counted. A vendor billing them uses license counts instead.

## Consequences
- The billing measure can be audited and reproduced from the activations table. A future billing export reads the same query for past months.
- If a later hosted offering needs Prometheus, it can export a platform-wide gauge from a periodic job, still without tenant labels.
