# ADR-0016 Hosted pricing model

*Status: accepted · Date: 2026-11-02*

## Context
Self-hosted LicenseForge is free (Apache-2.0). Revenue comes from the hosted cloud and enterprise deals (Vision). Competitors price per active licensed user (Keygen), per license (Replicated, on top of $24–36k/yr platform fees), or flat tiers (Cryptlex, LicenseSpring). See Licensing competitor feature gaps.

## Decision
Two pricing models for the hosted offering:

1. **Per active customer** (default, self-serve)
   - Vendor pays per **active customer** per month. Active = a customer with at least one activation, validation, or refresh in the billing month.
   - Licenses, activations, products and plans are unlimited within reason (fair-use rate limits).
   - Free tier with a small number of active customers for indie vendors and evaluation.
2. **Enterprise flat fee**
   - Fixed **X per month**, regardless of customers, licenses or activations. Negotiated per deal, annual contract.
   - Bundles SLA, support, and later SSO/SAML, dedicated tenant/region.

Self-hosted: free, no feature gating in the Apache-2.0 code. Paid support contracts available for self-hosters.

## Implementation consequences
- v0.1: activations already store `last_seen`; add a per-tenant **active customer count per month** (query + Prometheus metric). No billing code yet.
- Hosted (Later): a tenant `billing_plan` with `per_active_customer` or `flat`, and an optional soft cap. Flat plans skip metering enforcement but still report usage (for renewal conversations).
- Our own billing uses Stripe, same as we tell vendors to ([ADR-0007 Billing and campaigns delegated to payment providers](0007-billing-and-campaigns-delegated-to-payment-providers.md)).

## Consequences
- Per-customer pricing tracks the vendor's revenue, which is easy to justify, and avoids punishing vendors whose customers run many machines.
- Vendors with few, large customers pay little on per-customer pricing; that segment is the Enterprise flat deal's target.
- Exact price points stay open until design partners are found (Open Questions).

## Alternatives considered
- **Per license / per activation**: penalises Kubernetes customers whose replicas scale; contradicts cluster binding.
- **Per active end user (Keygen)**: we don't track end users in v0.1.
- **Flat tiers only**: simple, but leaves money on the table at both ends.
