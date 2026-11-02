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
Tables `customers`, `licenses`, `activations` (`internal/store/schema`), revised after review:
- **Snapshot**: each license copies the plan's slug and terms (expiry basis, months or seconds, **binding policy** `none`/`machine`/`cluster`, activation/rehost limits, offline, lease, max offline, grace) and the resolved entitlements (plan plus per-license overrides). An upgrade may move a license only to another plan of the same product, and the composite key includes the slug, so the signed `plan` claim always names the license's plan.
- **Entitlements are checked like the license format**: features are strings in the key format, limits integers in −1 … 2^53−1, so the database can't hold a snapshot that SDKs would reject as `malformed`. Nil features/limits are stored as `[]`/`{}`.
- **Status** `active` / `suspended` / `revoked` with matching timestamps. **Expired is derived** from `expires_at`. CHECKs: expiry after issue; first activation not before issue; perpetual licenses have no expiry; `from_first_activation` has no expiry before first activation and has one after; rehosts within the limit.
- **Key**: ciphertext (format and minimum length), lookup hash **unique per tenant** (a global index would reveal whether a key exists in another tenant), 6-character display hint ([ADR-0025 License key storage and encryption at rest](0025-license-key-storage-and-encryption-at-rest.md)).
- **Activations**: hashed fingerprint and source, binding, mode, app/SDK version, first/last/deactivated times in order; Kubernetes fingerprints bind the cluster, all others the machine; an activation must bind what its license requires (site licenses have none); one active activation per fingerprint per license.
- **Never deleted**; column grants keep tenant, product, customer, issue time and activation identity immutable.
- **GDPR erasure** (data subject request): null or replace the customer's name, email and `external_refs`, its licenses' `external_refs` and its activations' `hostname`. `external_refs` values must be strings.
- **Service-enforced, recorded in the audit log** (CHECKs can't see the previous row and triggers aren't used): revocation is final, deactivation can't be undone, first activation is set once, the activation limit (row lock on the license). A test pins that the database does not enforce these, so a change is deliberate.

## Consequences
- Slightly bigger v0.1 schema; avoids later data migrations of every license and a v2 file format.
- Snapshots mean "change the price/features of plan X for everyone" is deliberately not a one-click action.
