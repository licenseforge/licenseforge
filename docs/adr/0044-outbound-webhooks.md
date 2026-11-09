# ADR-0044 Outbound webhooks

*Status: accepted · Date: 2026-11-09*

## Context
Vendors want their own systems told when licenses and activations change: CRM sync, provisioning, Slack alerts, iPaaS flows ([ADR-0022 CRM and business tool integrations](0022-crm-and-business-tool-integrations.md) promises "signed outbound webhooks with a documented event catalog"; [ADR-0014 Product scope and won't-do list](0014-product-scope-and-won-t-do-list.md) leans on them for SAP/Oracle/Dynamics; [ADR-0020 Admin dashboard](0020-admin-dashboard.md) lists "webhooks + delivery log"). The Roadmap item asks for signed payloads, retries, no redirect following, and the events `license.issued`, `license.revoked`, `activation.created`. Decided by the maintainer under the owner's delegation (2026-11-04), by the docs and adoption below.

## Decision
### Source: the tenant's audit chain is the outbox
- Every license and activation change already writes an audit entry on the tenant's chain in the **same transaction** ([ADR-0036 Audit retention and SIEM export](0036-audit-retention-and-siem-export.md)); `audit.Record` assigns `seq` under the chain's lock held until commit, so per-chain `seq` is gap-free in commit order. Webhooks read that chain: an event exists if and only if the change committed. No second outbox table, no dual write.
- Events come from entries with `outcome = success` only (refusals reuse the same action names), by a fixed mapping:

| Event | Audit action |
|---|---|
| `license.issued` | `license.issue` |
| `license.revoked` | `license.revoke` |
| `license.suspended` | `license.suspend` |
| `license.reinstated` | `license.reinstate` |
| `activation.created` | `activation.create` (recorded only for a new seat), `activation.offline` with `details.new_seat = true` |
| `activation.deactivated` | `activation.deactivate`, `activation.offline_return` |

- **Not events (v0.2)**: license expiry (derived from `expires_at`; nothing is recorded when it passes), so no `license.expired` or `license.expiring` yet. A follow-up adds a scheduled job that records `license.expire` entries on the tenant chain, which then map like the others (and serve [ADR-0022 CRM and business tool integrations](0022-crm-and-business-tool-integrations.md)'s Slack expiry alerts). Key reveals, offline file exports and rehost resets aren't events.

### Event payloads
- Each event has a **documented schema of its own**, part of the versioned API (OpenAPI), never the raw audit details: internal audit keys can change without breaking receivers.
  - License events: `license_id`, `product_id`, `customer_id`, `plan`, `status` (after), `expires_at`.
  - Activation events: `activation_id`, `license_id`, `product_id`, `customer_id`, `fingerprint`, `binding`, `mode` (online or offline).
- The fields are a **snapshot at the change**: the change's transaction records them in the audit details (the implementation adds the missing IDs, e.g. `customer_id`, `product_id` on activation entries), and the dispatcher builds the payload from the entry alone, never from current rows.
- **Never** a license key, a license file, a request, or a secret.
- Body: `{"type": "license.revoked", "timestamp": <occurred_at, RFC 3339>, "data": {...}}`. One event per request.

### Endpoints
- Per tenant: `webhook_endpoints` (RLS, [ADR-0009 Multi-tenancy](0009-multi-tenancy.md)): URL, subscribed event types (non-empty), enabled flag and disabled reason. At most 10 per tenant.
- Delivery state lives apart, in `webhook_cursors` (one row per endpoint, RLS: last `seq` passed, lease holder and expiry, attempt count, next attempt time), with **column-level rights per login** and a restrictive policy that moves `seq` only forward, to an existing entry of its chain or to the chain's anchor:
  - tenant pool: `SELECT` of every column but the lease holder (the dashboard shows lag, retry state, the next attempt and whether a delivery is in flight, never a pod name), `INSERT` and `DELETE` (with the endpoint, in the same transaction), `UPDATE` of `seq`, attempt count and next attempt time only, with a policy that allows the attempt count only to be reset to 0 (the recovery actions below); never the lease columns.
  - platform pool (the dispatcher): `SELECT`, `UPDATE` of `seq`, the lease columns, attempt count and next attempt time; no `INSERT` or `DELETE`.
  - A `CHECK` keeps the attempt count between 0 and the schedule's length; the dispatcher increments it (`attempts + 1`), never writes an absolute value.
- Created with its cursor in the same transaction, at the chain's current last `seq`: events from creation on, never history. The `INSERT` policy allows nothing above the last `seq`; the lower bound (no replay of history) is the application's, since a policy can't pin it without racing concurrent commits. Deleting an endpoint deletes its cursor and delivery records in the same transaction.
- **The URL is a secret too** (Slack, Zapier, n8n and Make URLs carry a token in the path or query): stored encrypted like the signing secret; reads (`webhook:read`, which viewers have) and audit details show only the scheme, host and port, with the path and query masked.
- **Signing secret**: `whsec_` + base64 of 32 random bytes, shown once at creation and on rotation, stored encrypted with the master keyring ([ADR-0025 License key storage and encryption at rest](0025-license-key-storage-and-encryption-at-rest.md), a new purpose), bound to the tenant and row; the current and previous secret have distinct bindings so their ciphertexts can't be swapped. Rotation keeps the previous secret for 24 hours and signs with both.
- Managed with `webhook:write` (owners and admins, [ADR-0019 Authorization model](0019-authorization-model.md)); create, update, rotate, delete, disable, re-enable, "skip event" and "skip to now" are audited on the tenant chain.
- `tenant purge` deletes the tenant's endpoints, cursors and delivery records with its other data.

### Signature: Standard Webhooks
- **[Standard Webhooks](https://www.standardwebhooks.com) v1** (Svix, OpenAI, Twilio, Supabase, ngrok, Kong, Polar and others; receiver libraries in most languages): `webhook-id` (the audit entry ID: the receiver's deduplication key, the same on every retry), `webhook-timestamp` (Unix seconds of this attempt), `webhook-signature` (`v1,` + base64 HMAC-SHA256 over `id.timestamp.body`; space-separated when two secrets are active). HMAC-SHA256 is FIPS-approved.

### Delivery
- **Who**: a dispatcher in every server replica, on the platform pool (the login that reads every chain, as audit export; [ADR-0009 Multi-tenancy](0009-multi-tenancy.md) role table). The platform login gains: `SELECT` on `webhook_endpoints` and `UPDATE` of only its enabled flag and disabled reason (to disable); its `webhook_cursors` rights above; `INSERT` and `DELETE` (records older than 7 days) on delivery records; the tenant pool has `SELECT` (the delivery log) and `DELETE` (with the endpoint) on them, under RLS. It already reads audit entries and anchors and records audit entries (disabling and pruned ranges are audited on the tenant chain). Secrets are decrypted in process. The isolation test pins these grants and policies.
- **Claiming**: a pool of workers per replica (default 8). Each claims one **due** endpoint, chosen at random (`FOR UPDATE SKIP LOCKED` on its cursor, as audit export), so workers are shared by endpoints, not by backlog. A tenant holds at most 2 unexpired leases across the cluster: the claim query leaves out tenants at the cap, and the claim takes a per-tenant transaction advisory lock (its own key, `licenseforge.webhook:<tenant>`, not the audit lock's) before counting them, so concurrent claims can't both pass. Due: enabled, next attempt time passed (or none), and its chain has a later entry. The claim checks the cursor against the chain's anchor (every claim: a lagging endpoint can fall behind a prune), then scans forward from the cursor to the next entry that maps to a subscribed event, advancing the cursor past entries that don't (bounded per claim).
- **Sending**: outside any transaction, within half the lease. Then one transaction advances the cursor, or writes the retry state, only if the update still matches the lease holder and the cursor's `seq` (a stalled replica can't move it or reset retry state); the delivery record, and disabling the endpoint (after the last retry, or on 410) with its audit entry, happen in that transaction and only if that update changed a row. So a send that a tenant's skip, re-enable or delete overtook changes nothing. **At-least-once, in order per endpoint.**
- **Success**: any 2xx within 15 seconds (the spec recommends 15 to 30). The response body is read up to 64 KiB and discarded. **410 Gone** disables the endpoint at once. Anything else is a failure.
- **Retries**: 5 s, 5 min, 30 min, 2 h, 5 h, 10 h, 10 h with jitter (Svix's production schedule; about 28 hours), never sooner than a `Retry-After` on 429 or 503 (capped at 10 hours). After the last failure the endpoint is **disabled** (reason recorded, audited, metric). In-order delivery means a failing event holds back that endpoint's later events, not other endpoints'.
- **Recovering** (tenant actions, each one transaction on the tenant pool, audited with what it actually did):
  - **Re-enable** (only a disabled endpoint): `enabled` on, attempt count reset, next attempt now; resumes at the failed event.
  - **Skip this event** names the event (its `seq` N, from the dashboard): in the transaction, N must be the next entry after the cursor that maps to a subscribed event; then the cursor moves to N and the retry state resets. Otherwise (delivered meanwhile, or not the stuck event) nothing changes and the answer says so.
  - **Skip to now**: the cursor moves to the chain's last `seq` read in that transaction, retry state reset.
  - A delivery in flight meanwhile is harmless: the dispatcher's advance and retry writes match the lease holder and the `seq` it sent, so they don't apply after a skip (the receiver may still get that event once: at-least-once).
  - If entries after the cursor were pruned by retention (the cursor is below the chain's anchor), the dispatcher moves the cursor to the anchor and an audit entry records the skipped `seq` range (which of them were events can't be known any more).
- **Delivery records**: each attempt (event, time, outcome category, status code, duration), kept 7 days, for the dashboard's delivery log. Error texts are categories (`timeout`, `connection failed`, `tls`, `http <code>`, `redirect`), never resolved addresses, and a blocked address reads as `connection failed`, so tenants can't probe the network.
- **Throughput**: one event per request, serially per endpoint, and at most 2 endpoints of a tenant in flight: a receiver taking 1 s handles about 86,000 events a day, shared by the tenant's busy endpoints. Lag is a metric; batching isn't in v0.2.
- **Metrics** without tenant labels ([ADR-0036 Audit retention and SIEM export](0036-audit-retention-and-siem-export.md)): deliveries by outcome, maximum lag in events and seconds, disabled endpoints.

### Egress (SSRF)
- **https only**, port 443 unless the operator allows more (`LICENSEFORGE_WEBHOOK_PORTS`); URLs with credentials refused. TLS 1.2+ (FIPS policy in the FIPS build), certificates against the system roots plus `extraCA`.
- **Redirects are never followed** (a 3xx is a failure). No proxy from the environment: the delivery client has its own transport.
- **Every address is checked at dial time** in `net.Dialer.Control`, so each resolved candidate (Happy Eyeballs included) is checked on every attempt and DNS rebinding doesn't help. Refused: every range the IANA IPv4 and IPv6 Special-Purpose Address Registries mark not globally reachable (loopback, RFC 1918, ULA, link-local and cloud metadata, CGNAT `100.64.0.0/10`, `0.0.0.0/8`, `192.0.0.0/24`, benchmarking `198.18.0.0/15`, `240.0.0.0/4`, multicast, unspecified, documentation) and Azure's platform address `168.63.129.16` (WireServer and host DNS; globally routable, so the registries don't cover it), IPv4-mapped addresses and the well-known NAT64 prefix `64:ff9b::/96` (the only route to IPv4 receivers on IPv6-only clusters with DNS64) checked as the IPv4 address they carry, and the other IPv6 forms that embed IPv4 refused outright: the local-use NAT64 block `64:ff9b:1::/48` (its prefix length, and so where the IPv4 bits sit, is the operator's choice, RFC 8215), 6to4 `2002::/16`, Teredo `2001::/32`, IPv4-compatible `::/96`. A NAT64 prefix an operator chose can't be recognized: such clusters must add it to the deny list (`LICENSEFORGE_WEBHOOK_DENY_CIDRS`). The list is a table in the code with a test per range; Go's `IsGlobalUnicast` alone isn't enough.
- **Self-hosted allowlist**: `LICENSEFORGE_WEBHOOK_ALLOW_CIDRS` lets an install reach internal receivers; it applies to every tenant, so it's for single-vendor self-hosted installs, not hosted ones. Loopback, link-local (`169.254.0.0/16`, `fe80::/10`) and the cloud metadata addresses stay refused even when allowlisted: `169.254.169.254`, `fd00:ec2::254` (AWS, in ULA space), `100.100.100.200` (Alibaba, in CGNAT space), `192.0.0.192` (Oracle).
- The Helm chart adds a NetworkPolicy egress rule for webhooks (the allowed ports, destinations configurable).

## Consequences
- No outbox to keep consistent with the data: the audit chain is already the source of truth, and audit export proved the cursor pattern.
- Ordered, at-least-once delivery per endpoint; a broken receiver holds back only its own endpoint and is disabled within about 28 hours; a slow but working receiver just lags (visible in the metric and the dashboard).
- Audit details gain the IDs the payloads need; audit retention doesn't wait for webhooks.
- Receivers verify with any Standard Webhooks library; the docs show it in Go, Python and Node.
- Compliance: SC-7 and AC-4 (egress), SC-8, SC-12/13 (signing), AU (management audited) are updated in the implementing PRs (OSCAL and matrix, Roadmap compliance item).

## Alternatives considered
- **A separate outbox table written in each transaction**: duplicates what the audit chain already guarantees, and every new event needs a second write.
- **Fan-out queue (one row per event × endpoint)**: parallel, unordered delivery, at the cost of a table that grows with every event and a cleanup job. Ordered cursors are simpler, and order matters for state sync (issued before revoked).
- **Payloads built from current rows at send time**: always complete, but not what happened (a license suspended then reinstated would send `suspended` with status active).
- **The spec's longer example schedule (10 attempts over about 75 hours)**: holds an endpoint's later events back for three days; with "skip this event" and re-enable, 28 hours is enough.
- **Custom signature scheme (Stripe-style `t=…,v1=…`)**: every receiver writes its own verifier.
- **Asymmetric signatures (Ed25519, the spec's `v1a`)**: symmetric is what receiver libraries support best today; revisit if vendors ask.
- **Following redirects with re-checks**: more code, little value; receivers register the final URL.
