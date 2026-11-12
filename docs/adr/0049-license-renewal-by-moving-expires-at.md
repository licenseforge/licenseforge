# ADR-0049 License renewal by moving expires_at

*Status: accepted · Date: 2026-11-12*

## Context
A license's term is a snapshot of its plan at issue ([ADR-0013](0013-license-data-model-hardening.md)): `expires_at` is set at issue, or at the first activation for `from_first_activation` plans, and nothing can change it afterwards. A subscription renewal therefore meant issuing a new license with a new key, and the customer reconfiguring every machine. That blocks the v0.3 billing connectors ([ADR-0007](0007-billing-and-campaigns-delegated-to-payment-providers.md)), which must extend a license when a payment succeeds. The readiness check of 2026-11-12 listed it as a gap. The owner asked for it on 2026-11-12. The details are decided under the delegation of 2026-11-04.

## Decision
- **`POST /tenants/{t}/licenses/{id}/expires-at`** with `{"expires_at": <timestamp>}` sets the end of the license's term. It is the same shape as `updates-until` ([ADR-0045](0045-maintenance-entitlement-updates-until.md)).
  - Later is a renewal; earlier, even in the past, is a correction, or ends the term now. The license's `grace_seconds` still applies after the new date, as after any expiry.
  - Stored in whole seconds. It must be after `issued_at` (the existing CHECK) and in year 9999 or earlier (UTC).
  - The key, the activations, the plan terms (duration, basis, seats, lease) and `updates_until` stay. Maintenance is a separate decision; a connector that sells both renews both.
- **An explicit date, not "one more term".** The payment provider knows the paid period's end (Stripe's `current_period_end`), and so does a person entering a contract date. "Add one term from the old expiry or from now" (Keygen's renewal basis) can be computed by the caller in one line. This also keeps one rule for humans, the CLI and connectors.
- **Only a term with an end moves.** A perpetual license (no duration) and a `from_first_activation` license that hasn't started have no `expires_at`, and the existing CHECKs keep it that way. Both answer **409 `no_term`**. Turning a term license perpetual, or a perpetual one into a term, isn't offered: issue a new license.
- **Rights and states:** `license:write` on the license's product, like suspend and `updates-until`. Active and suspended licenses can change; a revoked one answers 409 `invalid_state` (final). Order of checks as in ADR-0032: lookup, rights, value, then state.
- **Audit:** `license.expires_at`, with the previous and new value, the product, customer and plan.
- **Effect:** online leases carry the new date from their next refresh. That includes an expired license: the server refuses its refresh until the renewal, then serves it again, with the same activation and no new seat. Offline files already issued keep the date they were signed with until replaced (an offline re-activation, or a new site license file).
- **No webhook event yet**, as for ADR-0045. The webhook payloads already carry `expires_at` on later events. Add `license.renewed` when a receiver (a CRM sync) needs it.
- **Dashboard:** an Expiry date on the license's dialog, valid through the end of the picked day (UTC), shown only when the license has an end.

## Consequences
- Renewals keep the customer's key and machines. Billing connectors (v0.3) renew through `licenses.Service.SetExpiresAt`.
- A license expired past its grace comes back at its next refresh after the renewal. The SDKs' refresh loops retry a `license_expired` refusal with backoff, at most 5 minutes apart, so a running app recovers without user action.
- Shortening is possible and takes effect at the next refresh. A lease already signed keeps its own end, which is never after the license's expiry at signing.
