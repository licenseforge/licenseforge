# ADR-0034 Online leases and seat moves

*Status: accepted · Date: 2026-11-04*

## Context
Online activation (PR #51) returns signed leases and lets the SDK deactivate a machine to free its seat. Two rules needed pinning down: [ADR-0013 License data model hardening](0013-license-data-model-hardening.md) makes **rehost** a named operation limited by `max_rehosts`, but a self-service deactivate followed by an activate on another machine is a rehost by another name; and [ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md) states that revocation latency equals the lease length, which only holds if a lease's grace doesn't extend it. Decided under the maintainer's delegation.

## Decision
- **Seat moves count when the vendor limits them**: if a license has `max_rehosts`, its **lifetime activations** (activation rows ever created, deactivated ones included) may not exceed `max_activations + max_rehosts`; a new activation beyond that is refused. Re-activating the same machine reuses its row and doesn't count. `rehost_count` records the moves beyond the seats. Without `max_rehosts`, moves are unlimited and only `max_activations` bounds the machines active at any time. The support-side rehost operation counts against the same limit.
- **Grace only at the end of the term**: a lease carries the license's grace only when its `exp` was capped at the license's own expiry (the term is ending; the app keeps working while a renewal is processed). An ordinary lease that simply wasn't refreshed ends at `exp`. So a revoked or suspended machine stops within one lease length, as [ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md) says; `max_offline` still bounds offline operation.
- **Refresh before the offline limit**: `refresh_after = iat + min(lease, max_offline) / 2`, so an SDK that obeys it never reaches `max_offline` first.
- **Signing after commit**: the activation is committed, then the lease signed; a signing failure leaves the seat taken and a retry reuses it. A revoke landing in that gap lets one lease out, within the one-lease latency above.
- Refused activations with a valid key are audited; unknown keys are counted in metrics, not audited. Rate limits on the activation API are keyed per license key, not only per client address.

## Consequences
- Vendors who sell node-locked licenses get a hard cap on machine moves by setting `max_rehosts`; others get Keygen-style free moves.
- Revocation takes effect within one lease (the vendor's `lease_seconds`), not lease + grace.

## Alternatives considered
- **Self-service deactivation never counts**: makes `max_rehosts` meaningless for online licenses.
- **Rate-limit deactivations instead of counting them**: a time window is harder to explain to customers than a number on the license.
- **Grace on every lease**: forgiving of outages, but revocation latency becomes lease + grace.
