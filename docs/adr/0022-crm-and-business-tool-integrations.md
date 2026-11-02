# ADR-0022 CRM and business tool integrations

*Status: accepted · Date: 2026-11-02*

## Context
Our target buyer, B2B vendors shipping into customer clusters ([ADR-0014 Product scope and won't-do list](0014-product-scope-and-won-t-do-list.md)), sells through **sales-led deals**: quotes, contracts, POs. The source of truth for "who bought what" is the CRM, usually **Salesforce** (enterprise) or **HubSpot** (startups/mid-market). Replicated syncs licenses from Salesforce; Thales, Revenera, LicenseSpring and Zentitle ship Salesforce connectors (Licensing competitor feature gaps).

ADR-0014 listed "prebuilt SAP / Oracle / Salesforce connectors" as won't-do. That was too broad for Salesforce: without it, every license issuance in an enterprise deal is manual re-typing from the CRM.

## Decision
Make integrations a **first-class product area**, built in layers so each step is usable alone:

### Layer 1: Integration foundation (v0.2–v0.3, mostly already planned)
- Public REST API + OpenAPI; manual/contract issuance with `external_refs` ([ADR-0007 Billing and campaigns delegated to payment providers](0007-billing-and-campaigns-delegated-to-payment-providers.md), [ADR-0013 License data model hardening](0013-license-data-model-hardening.md)).
- **Signed outbound webhooks** with a documented event catalog.
- Reuses the billing integration core: event inbox with dedupe, re-fetch, reconciliation (Billing Integrations).

### Layer 2: No-code recipes (v0.3, docs + small packages)
- **Salesforce Flow recipe**: "Opportunity Closed Won" → Flow HTTP Callout via a Named Credential → LicenseForge contract-issuance API. Zero Salesforce code from us.
- **n8n node** (open source, fits our audience) and **Zapier/Make** apps over the same API. Covers HubSpot, Pipedrive, Slack and anything else for free.

### Layer 3: Native Salesforce connector (v0.4)
Server-to-server, implemented in LicenseForge (Go), plus a **metadata-only package** in the customer's Salesforce org:
- **Package** (unlocked package on GitHub): custom objects `LicenseForge_License__c`, `LicenseForge_Activation__c` related to Account / Opportunity / Contract, a permission set, page layouts. No Apex in v1.
- **Inbound (Salesforce → LicenseForge)**: subscribe to Change Data Capture / Platform Events via the **Pub/Sub API** (gRPC, Go-friendly). Configurable trigger (e.g. Opportunity Closed Won, Contract Activated, or a custom "Provision license" checkbox). Opportunity line items map to products/plans via a mapping table in LicenseForge.
- **Outbound (LicenseForge → Salesforce)**: write license status, expiry, entitlements, activation count back to the custom objects, so sales and CSMs see usage and renewals inside Salesforce.
- Auth: OAuth 2.0 (JWT bearer or client credentials) via an External Client App; tokens stored via the secret-manager layer ([ADR-0011 Secret manager integrations](0011-secret-manager-integrations.md)).
- Renewals and upsells: a new/changed Opportunity updates the existing license (re-snapshot features), never silently creates duplicates.

### Layer 4: Native HubSpot connector (v0.4 / Later)
Same pattern: HubSpot deal stage → issue; write back to a custom object or deal/company properties. Built on the same connector core.

### Later
- **AppExchange-listed managed package** with a Lightning component (license panel on Account), CPQ product → plan mapping. Requires Salesforce security review; do it after design partners confirm demand.
- **Support tools**: Zendesk / Intercom sidebar app showing the customer's licenses and machines (support's top request in licensing).
- **Slack** alerts (expiring licenses, activation spikes, failed renewals) via webhooks.
- SAP / Oracle / MS Dynamics: still **won't do natively**. Layer 1–2 (API, webhooks, iPaaS like MuleSoft/Workato) covers them; partners may build connectors.

## Consequences
- Enterprise deals flow CRM → license automatically: our biggest gap vs. Thales/Revenera/Replicated for sales-led vendors is closed.
- Layer 2 gives a credible Salesforce story already in v0.3 at near-zero cost.
- Layer 3 needs Salesforce expertise (metadata, Pub/Sub API, sandbox testing) and a Salesforce Developer Edition/partner org in CI.
- CRM write-back adds personal data (contact names) flowing into Salesforce: covered by the vendor's own Salesforce DPA; we only write license data, never pull contacts we don't need (GDPR minimisation, [ADR-0021 Certification readiness](0021-certification-readiness.md)).
- ADR-0014's won't-do row narrows to "SAP / Oracle / Dynamics native connectors".

## Alternatives considered
- **Keep Salesforce on won't-do, rely on iPaaS only**: cheapest, but enterprise buyers expect a native connector; competitors have one.
- **Managed package with Apex logic first**: richer in-org UX, but security review, Apex skills and package versioning before we know demand.
- **Use MuleSoft as the official path**: expensive for customers, ties us to Salesforce's iPaaS.
