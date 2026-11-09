# ADR-0044 Outbound webhooks

*Status: accepted · Date: 2026-11-09*

## Context
Vendors want their own systems told when licenses and activations change: CRM sync, provisioning, Slack alerts, iPaaS flows ([ADR-0022 CRM and business tool integrations](0022-crm-and-business-tool-integrations.md) promises "signed outbound webhooks with a documented event catalog"; [ADR-0014 Product scope and won't-do list](0014-product-scope-and-won-t-do-list.md) leans on them for SAP/Oracle/Dynamics). The Roadmap item asks for signed payloads, retries, no redirect following, and the events `license.issued`, `license.revoked`, `activation.created`. Decided by the maintainer under the owner's delegation (2026-11-04), by the docs and adoption below.

## Decision
### Source: the tenant's audit chain is the outbox
- Every license and activation change already writes an audit entry in the **same transaction** ([ADR-0036 Audit retention and SIEM export](0036-audit-retention-and-siem-export.md)): per-chain `seq` is gap-free in commit order. Webhooks read that chain, so an event exists if and only if the change committed. No second outbox table, no dual write.
- Events are derived from **successful** entries only, by a fixed mapping:

| Event | Audit action |
|---|---|
| `license.issued` | `license.issue` |
| `license.revoked` | `license.revoke` |
| `license.suspended` | `license.suspend` |
| `license.reinstated` | `license.reinstate` |
| `activation.created` | `activation.create` or `activation.offline` that took a new seat |
| `activation.deactivated` | `activation.deactivate`, `activation.offline_return` |

- New events are added to the catalog by adding a mapping row; the catalog is documented and versioned with the API.

### Endpoints
- Per tenant: `webhook_endpoints` (RLS like every tenant table, [ADR-0009 Multi-tenancy](0009-multi-tenancy.md)): URL, subscribed event types (non-empty), enabled flag, disabled reason, the cursor (last delivered `seq`) and retry state. A limit of 10 endpoints per tenant.
- Created with the cursor at the chain's current end: an endpoint gets events from its creation on, never history.
- **Secret**: `whsec_` + base64 of 32 random bytes, shown once at creation and on rotation, stored encrypted with the master keyring, bound to tenant and row ([ADR-0025 License key storage and encryption at rest](0025-license-key-storage-and-encryption-at-rest.md)). Rotation keeps the previous secret for 24 hours and signs with both (receivers switch without downtime).
- Managed by tenant owners and admins (`webhook:manage`); every create, update, rotate, delete, disable and re-enable is audited on the tenant chain.

### Payload and signature: Standard Webhooks
- **[Standard Webhooks](https://www.standardwebhooks.com) v1**, adopted by Svix, OpenAI, Twilio, Supabase, ngrok, Kong, Polar and others, with receiver libraries in most languages: headers `webhook-id` (the audit entry ID: the receiver's deduplication key, stable across retries), `webhook-timestamp` (Unix seconds of this attempt), `webhook-signature` (`v1,` + base64 HMAC-SHA256 over `id.timestamp.body`, space-separated when two secrets are active). HMAC-SHA256 is FIPS-approved.
- Body: `{"type": "license.issued", "timestamp": <occurred_at, RFC 3339>, "data": {...}}`. `data` carries IDs and the audit entry's details (license, product, customer, activation, fingerprint), **never a license key, a license file or a secret** (audit details hold none, [ADR-0025 License key storage and encryption at rest](0025-license-key-storage-and-encryption-at-rest.md)). One event per request.

### Delivery
- A replica leases one endpoint at a time (`FOR UPDATE SKIP LOCKED`, as audit export), sends its next event **outside any transaction**, then advances the cursor if it still holds the lease. **At-least-once, in order per endpoint**; receivers deduplicate on `webhook-id`.
- Success: any 2xx within 10 seconds. Anything else (non-2xx, timeout, refused address, TLS error) is a failure; the response body is read up to 64 KiB and discarded.
- **Retries** with the Standard Webhooks schedule and jitter: 5 s, 5 min, 30 min, 2 h, 5 h, 10 h, 10 h (about 28 hours). In-order delivery means a failing event holds back the endpoint's later events, not other endpoints'.
- After the last retry fails, the endpoint is **disabled** (reason recorded, audited, a metric). Re-enabling resumes from the failed event; the dashboard also offers "skip to now".
- Metrics: deliveries by outcome, endpoint lag (events behind), disabled endpoints.

### Egress (SSRF)
- **https only**; certificates verified against the system roots plus `extraCA`; TLS 1.2+, FIPS policy in the FIPS build.
- **Redirects are never followed** (a 3xx is a failure).
- **The connection's IP address is checked at dial time**, after DNS resolution, for every attempt: loopback, private (RFC 1918, ULA), link-local (cloud metadata), CGNAT, multicast, unspecified and other non-global ranges are refused. Checking at dial time covers DNS rebinding. URLs with credentials, or a host that is an IP literal in those ranges, are refused when saved.
- An operator allowlist of CIDRs (`LICENSEFORGE_WEBHOOK_ALLOW_CIDRS`) lets self-hosted installs reach internal receivers. The Helm chart adds a NetworkPolicy egress rule for webhooks (port 443, destinations configurable).
- No proxy from the environment: the delivery client sets its own transport.

## Consequences
- No outbox to keep consistent with the data: the audit chain is already the source of truth, and the SIEM export proved the cursor pattern.
- Ordered, at-least-once delivery per endpoint; one slow or broken receiver can't delay others, and can't fill a queue: its cursor just stays behind, and it is disabled within about 28 hours.
- Audit retention ([ADR-0036 Audit retention and SIEM export](0036-audit-retention-and-siem-export.md), 365 days minimum) doesn't wait for webhooks: an enabled endpoint is never more than a day or so behind. Re-enabling an endpoint whose next entry was pruned resumes at the oldest kept entry, and says so.
- Receivers verify with any Standard Webhooks library; the docs show it in Go, Python and Node.
- Delivery history (last attempts per endpoint) is a follow-up for the dashboard; v0.2 shows the endpoint's state, last error and lag.

## Alternatives considered
- **A separate outbox table written in each transaction**: duplicates what the audit chain already guarantees, and every new event needs a second write.
- **Fan-out queue per delivery (one row per event × endpoint)**: allows parallel, unordered delivery, at the cost of a table that grows with every event and a cleanup job. Ordered per-endpoint cursors are simpler, and order matters for state sync (issued before revoked).
- **Custom signature scheme (e.g. Stripe-style `t=…,v1=…`)**: works, but every receiver writes its own verifier; Standard Webhooks has libraries.
- **Asymmetric signatures (Ed25519)**: the spec allows them (`v1a`); symmetric is what receivers' libraries support best today. Revisit if vendors ask.
- **Following redirects with re-checks**: more code, little value; receivers can register the final URL.
