# ADR-0046 Daily metrics series

*Status: accepted · Date: 2026-11-10*

## Context
[ADR-0020 Admin dashboard](0020-admin-dashboard.md) puts "metrics charts" in v0.2. The overview shows exact counts from `GET /tenants/{t}/summary`, which are a snapshot with no history. Prometheus `/metrics` (PR #58) is for the operator, across tenants, and a tenant's members can't read it. A vendor wants to see the trend in their own tenant: how many licenses they issue, and how many machines activate and leave. Decided under the maintainer's delegation of 2026-11-04 (work log 2026-11-10).

## Decision
- **`GET /tenants/{t}/metrics/daily?days=N`**: one entry per UTC day, oldest first, for the last `N` days ending today (today is partial). `N` is 1–90, default 30. Days with nothing have zeros; every day is present.
- **Series** per day:
  - `licenses_issued`: licenses created that day (`licenses.created_at`).
  - `activations`: machines activated that day, online or offline (`activations.first_seen_at`).
  - `deactivations`: machines deactivated that day (`activations.deactivated_at`), by the customer, a receipt or a support reset.
- **Source: the domain tables**, not the audit log. The audit log is indexed by sequence, not time. Its refusals often name no product (an unknown key has none), so they can't be filtered by product scope. Indexes on `activations (tenant_id, first_seen_at)` and `(tenant_id, deactivated_at)`, built concurrently, bound the scan to the window.
- **Access**: `license:read`. A product-scoped caller counts only its products' licenses and those licenses' activations, under RLS. That's the same rule as `summary`'s license counts.
- **Day boundary**: UTC, by the database clock, like `customers.month_start` ([ADR-0040 Active customer measure](0040-active-customer-measure.md)).
- **Dashboard**: the overview shows the three series as simple bar charts, drawn as SVG with no chart library, each with a text summary (total over the window) for screen readers.

## Not included
- **Refused activations**: no product scope (see above). Operators have Prometheus' `licenseforge_activations_total{outcome}`; the overview's "failures" tile stays a v0.3 item.
- **Active customers per day**: ADR-0040 defines the monthly measure only.
- **A product filter and custom ranges**: add when a vendor asks.
- **Test mode**: when test-mode tenants or keys land (v0.2), their licenses are left out of these series.

## Consequences
- One read-only endpoint and one migration (two indexes), with no new write path or audit action.
- The numbers are exact and match the lists: they come from the same rows.
