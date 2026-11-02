# ADR-0007 Billing and campaigns delegated to payment providers

*Status: accepted · Date: 2026-11-02*

## Context
Want campaigns (promotions, discounts, trials). Pricing, coupons, tax, invoicing and dunning are a whole product (Stripe, Paddle, Polar, Chargebee, Lago) and a compliance burden (tax registration/filing, PCI).

Research (Startup billing providers 2026): Stripe is the startup default; Paddle the main Merchant of Record; Polar/Creem/Dodo are newcomers; Lemon Squeezy is being folded into Stripe Managed Payments. The two biggest providers (Stripe, Paddle Billing) issue **no license keys**, and every entitlement product found (Stripe Entitlements, Autumn, Schematic, Chargebee, Lago) is an online check. None issues signed, offline-verifiable licenses. The market is churning, so provider portability matters more than any billing feature we could build.

## Decision
LicenseForge does **not** handle money, prices, coupons, invoices or tax. Billing systems decide *what was bought*; LicenseForge turns it into a signed license.

### 1. Provider-neutral billing event model
Connectors only translate provider webhooks into internal events; one core handler applies them to licenses:

| Internal event | License action |
|---|---|
| `purchase.completed` | Issue license (plan from product/price mapping) |
| `trial.started` | Issue `type: trial` license |
| `period.renewed` | Extend expiry |
| `payment.failed` | Suspend after per-product grace |
| `payment.recovered` | Unsuspend |
| `subscription.ended` | Expire at period end |
| `refund.issued` / `dispute.lost` | Revoke or keep, **per-product policy** |
| `entitlements.changed` | Re-fetch purchased features, re-snapshot license ([ADR-0015 Feature catalog per product](0015-feature-catalog-per-product.md)) |

Provider-to-event mapping: Billing Integrations.

### 2. Reliability rules for every connector
- Verify signatures (Stripe signing secret, Paddle signature, Standard Webhooks for Polar).
- Insert `(provider, event_id)` under a **unique constraint** before acting; duplicates are no-ops.
- Return 2xx fast, process asynchronously.
- Treat events as hints: **re-fetch the object's current state** from the provider before changing a license (events arrive late and out of order).
- **Reconciliation job** polls provider state periodically, because some providers (Polar, Lemon Squeezy) don't send dispute events and webhooks can be lost.
- All actions audit-logged with the provider event ID.

### 3. Manual / contract issuance path
Enterprise and on-prem deals run on quotes, contracts, POs and invoices, not checkouts. First-class API + dashboard flow: "contract signed / invoice paid" → issue license with `external_refs` (contract, PO, CRM IDs) ([ADR-0013 License data model hardening](0013-license-data-model-hardening.md)). Also covers bring-your-own-license cloud-marketplace deals.

### 4. Entitlements ingest
Stripe Entitlements (`entitlements.active_entitlement_summary.updated`) and Polar benefits map onto our feature catalog. LicenseForge adds what they lack: numeric limits, seat counts, offline signed verification.

### Connector order
| # | Connector | Milestone | Effort |
|---|---|---|---|
| 1 | **Stripe**: Billing + Managed Payments + Entitlements ingest, one connector | v0.3 | M |
| 2 | **Generic signed webhook + manual/contract issuance** (covers Zapier/n8n, Kill Bill, Recurly, Creem, Dodo, invoices) | v0.3 | S |
| 3 | **Paddle Billing** | v0.3 | M |
| 4 | **Lemon Squeezy key import** (one-off migration, read-only webhooks during migration) | v0.3 | S |
| 5 | Polar | v0.4 | S |
| 6 | Lago (self-hosted billing for the same k8s buyers; HTTP only, AGPL) | v0.4 | M |
| 7 | Chargebee | Later | M |
| 8 | Creem, Dodo first-class | Later | S |
| 9 | FastSpring | Later | S |
| 10 | AWS Marketplace License Manager | Later | L |

### Usage and campaigns
- Usage counters (v0.3) support **prepaid credit balances**: decrement, top-up from a billing webhook, periodic reset, plus `max_uses` caps. LicenseForge pushes usage *to* the provider's meters; it never invoices.
- When a usage/entitlement check can't reach the server, deny after `max_offline` grace, never silent allow.
- Campaign support stays thin: **trial plans**, **campaign tags**, **bulk issuance**. Discounts and promotions live in the billing provider.

## Consequences
- No PCI scope, no tax engine, no invoicing.
- Connectors stay thin; adding a provider = a mapping table + signature check.
- Vendors without a billing provider use the manual/contract path or API.
- Risk to track: Stripe adding quantity limits to Entitlements. Our moat remains offline signatures, self-hosting and portability.

## Positioning
- Lemon Squeezy sellers: "Stripe is taking your MoR; LicenseForge keeps your license keys."
- Stripe/Paddle sellers: "your billing decides what was bought; LicenseForge turns it into a signed license that works air-gapped."
- Against Autumn/Schematic: we serve software running on infrastructure the vendor doesn't control.

## Open verification
- [ ] Test Stripe lifecycle events on a live Managed Payments account before v0.3.
- [ ] Creem and Dodo webhook event lists.
- [ ] Lemon Squeezy key export format/API for the import tool.

## Alternatives considered
- **Built-in billing**: months of work, regulated, competes with Stripe/Lago instead of integrating.
- **One connector per provider without a shared model**: duplicated edge-case handling (Keygen's own Stripe example is "90% of the way", revocation on cancel left undone).
