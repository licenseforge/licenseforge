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

## Implementation note (2026-11-02)
Tables `customers`, `licenses`, `activations` (`internal/store/schema`):
- **Snapshot**: each license copies the plan's slug and terms (expiry basis, months or seconds, activation/rehost limits, offline, lease, max offline, grace) and the resolved entitlements (`{"features": [...], "limits": {...}}`, plan plus per-license overrides). Changing the plan of a license (upgrade) is allowed only to a plan of the same product (composite key) and rewrites the snapshot.
- **Status** is `active` / `suspended` / `revoked`, with `suspended_at` / `revoked_at` set exactly when the status says so (CHECKs). **Expired is derived** from `expires_at`, not stored, so no job has to flip it. `expires_at` is null for perpetual licenses or until first activation (`from_first_activation`).
- **Key**: ciphertext, lookup hash and the last 6 characters as a display hint ([ADR-0025 License key storage and encryption at rest](0025-license-key-storage-and-encryption-at-rest.md)); the lookup hash is unique across all tenants.
- **Never deleted**: customers archived (GDPR erasure anonymises name and email), licenses revoked, activations deactivated. Column-level grants keep tenant, product, customer, issue time and an activation's identity immutable.
- **Activations**: hashed fingerprint and its source, binding (`machine` / `cluster`), mode (`online` / `offline`), app/SDK version, first and last seen. At most one active activation per fingerprint per license (partial unique index); re-activation after deactivation creates a new row, so history stays auditable. `rehost_count` on the license supports `max_rehosts`.
- Revocation being final and the activation limit are enforced by the licensing service (row lock on the license), not by the schema.

## Consequences
- Slightly bigger v0.1 schema; avoids later data migrations of every license and a v2 file format.
- Snapshots mean "change the price/features of plan X for everyone" is deliberately not a one-click action.
