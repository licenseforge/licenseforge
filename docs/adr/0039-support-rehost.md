# ADR-0039 Support rehost

*Status: accepted · Date: 2026-11-07*

## Context
[ADR-0013 License data model hardening](0013-license-data-model-hardening.md) makes rehost a named operation limited by `max_rehosts`. [ADR-0034 Online leases and seat moves](0034-online-leases-and-seat-moves.md) counts self-service seat moves in `rehost_count` and refuses them past the limit (`409 rehost_limit_reached`). That covers the customer's side. It leaves open what the vendor's support does when a customer at the limit loses a machine again. Every incumbent offers a first-class support transfer (Thales `hasp_transfer`, Cryptlex and Keygen machine resets). [ADR-0019 Authorization model](0019-authorization-model.md) already names the permission `activation:manage` ("rehost, deactivate machines, reset activations"). Decided under the maintainer's delegation.

## Decision
- **A support rehost is two audited steps on the management API**, both under `activation:manage` on the license's product:
  1. Free the old machine: `POST /tenants/{tenant}/licenses/{id}/activations/{activation_id}/deactivate` (exists, #86; `activation.deactivate`).
  2. If the license is at its limit, reset the move counter: `POST /tenants/{tenant}/licenses/{id}/rehosts/reset`. It sets `rehost_count` to 0 and is audited as `license.rehosts_reset` with `previous_rehost_count` and `max_rehosts`.
  
  The customer's next activation on the new machine is then an ordinary seat move.
- Reset on a license whose count is already 0 returns it unchanged and writes no entry, as deactivating an inactive activation does.
- A revoked license can't be reset (`409 invalid_state`, as other status refusals of the management API; `license_revoked` is the SDK's 403). It takes no new activations anyway. Suspended and expired licenses can be reset, so support can prepare a reinstatement.
- Checks run in [ADR-0032 REST API conventions](0032-rest-api-conventions.md) order: the license under the caller's product scope (missing and hidden both give 404), then `activation:manage` (403). Refusals are audited.
- The license lock is the same one activation takes (`FOR NO KEY UPDATE` on the license row), so a reset and a concurrent seat move serialize.
- License responses expose `rehost_count` and `max_rehosts` (null means unlimited), so the dashboard can show "moves used".
- **Narrows [ADR-0034 Online leases and seat moves](0034-online-leases-and-seat-moves.md)**: there, at the limit "support raises the license's `max_rehosts` or resets `rehost_count`" and "the support-side rehost operation increments `rehost_count` too". Here support only resets. Raising the limit is an upgrade (see Alternatives). The move itself is counted when the customer activates the new machine, not by the support step.

## Alternatives considered
- **Raise `max_rehosts` on the license**: it edits sold terms, which [ADR-0013 License data model hardening](0013-license-data-model-hardening.md) keeps as a snapshot changed only by an upgrade. That remains the way to sell more moves.
- **A one-shot "free move" credit**: needs new state and a second counter for the same outcome as a reset.
- **A single combined `rehost` endpoint (deactivate + reset)**: hides one of two separate decisions. Support often only needs the deactivate.

## Consequences
- No schema change: `rehost_count` is already writable by the serving login and kept within limits by CHECKs.
- Resets are visible in the audit log, so a vendor can review how often support grants extra moves.
- **Trade-off, accepted**: any principal with `activation:manage` (support and above, and tokens with those roles) can reset as often as it likes. In effect, that grants as many moves as it chooses on top of `max_rehosts` as sold. The controls are the role assignment ([ADR-0019 Authorization model](0019-authorization-model.md)) and the audit trail: each reset carries `previous_rehost_count` and `max_rehosts` and reaches the SIEM export ([ADR-0036 Audit retention and SIEM export](0036-audit-retention-and-siem-export.md)), where a vendor can alert on how often resets happen. A free-text reason was left out: it would need an optional body (none of the API's POSTs has one), and a reason in the query string would end up in access logs. A ticket reference can be added later as an optional body field if vendors ask.
