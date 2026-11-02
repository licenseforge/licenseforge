# ADR-0013 License data model hardening

*Status: accepted · Date: 2026-11-02*

## Context
Competitor research (Licensing competitor feature gaps) found several fields that are trivial to add now and require migrations or a license-format break later.

## Decision
In v0.1:
1. **Entitlement snapshot**: at issue time, the plan's entitlements, duration and limits are copied into the license. Editing a plan never changes licenses already sold. Explicit "upgrade to latest plan" is an audited operation. (10Duke, Distr do this.)
2. **`expiry_basis`** on plans: `from_issue` or `from_first_activation` (needed for pre-sold and reseller keys).
3. **License `type`**: `dev`, `trial`, `paid`, `community`, for reporting and trial limits.
4. **`external_refs`** (JSON map) on customers and licenses: order, CRM, ERP IDs. Billing connectors become webhook mappings, not schema changes.
5. **Activation metadata**: app version, SDK version, binding details recorded at activate/refresh, giving version-adoption reporting for free.
6. **Lease claims** ([License File Format](../../spec/license-format.md)): `max_offline` (how long the app may run without a successful refresh) and `refresh_after`; SDK rejects an `iat` in the future (clock tampering).
7. **Rehost** is a named, audited operation (deactivate old binding + activate new) with per-license rehost limits.
8. **Prometheus metrics** endpoint from day one.

Later fields already reserved: `updates_until` (v0.2), usage counters and `overage` (v0.3).

## Consequences
- Slightly bigger v0.1 schema; avoids later data migrations of every license and a v2 file format.
- Snapshots mean "change the price/features of plan X for everyone" is deliberately not a one-click action.
