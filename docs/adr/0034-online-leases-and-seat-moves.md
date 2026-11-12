# ADR-0034 Online leases and seat moves

*Status: accepted · Date: 2026-11-04*

## Context
Online activation (PR #51) returns signed leases and lets the SDK deactivate a machine to free its seat. Two rules needed pinning down: [ADR-0013 License data model hardening](0013-license-data-model-hardening.md) makes **rehost** a named operation limited by `max_rehosts`, but a self-service deactivate followed by an activate on another machine is a rehost by another name; and [ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md) states that revocation latency equals the lease length, which only holds if a lease's grace doesn't extend it. Decided under the maintainer's delegation.

## Decision
- **Seat moves count when the vendor limits them**: `rehost_count` is the counter (as in [ADR-0013 License data model hardening](0013-license-data-model-hardening.md), including its reset on upgrade). A new activation of a fingerprint **never activated on this license before**, once the license has already had `max_activations` distinct fingerprints, is a move: it increments `rehost_count` in the same transaction and is refused if that would exceed `max_rehosts` (the existing CHECK backs this). Activating a fingerprint seen before, active or deactivated, never counts again, so uninstall and reinstall on the same machine is free. Without `max_rehosts`, moves are unlimited and only `max_activations` bounds the machines active at any time; `max_rehosts` has no effect without `max_activations`. The support-side rehost operation (audited) increments `rehost_count` too; at the limit, support raises the license's `max_rehosts` or resets `rehost_count`, each audited. So a license runs on at most `max_activations + max_rehosts` distinct machines over its life, until `rehost_count` is reset.
- **Grace only at the end of the term**: a lease carries the license's grace only when its `exp` **is** the license's own expiry (the term ends with this lease; the app keeps working while a renewal is processed). An ordinary lease that simply wasn't refreshed ends at `exp`. So a revoked or suspended machine stops within one lease length, as [ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md) says, except during the license's last lease, where the term's grace follows `exp`.
- **During grace** the server still refreshes an existing activation (new `iat`; `exp` stays the license's expiry; grace kept), so `max_offline` doesn't cut the grace short; it takes no new activations once the term has ended (re-activating a machine that is still active reuses it, like a refresh).
- **Perpetual licenses**: online leases never carry grace (there is no term end); air-gapped files carry the license's grace as before. Grace is not outage tolerance: that is `lease_seconds` and `max_offline`.
- **Refresh before the offline limit**: `refresh_after = iat + min(lease, max_offline) / 2`; the SDK refreshes from `refresh_after` on (not before), so with the server reachable it never reaches `max_offline` first. With `max_offline` 0, `refresh_after = iat`: every use needs a refresh.
- **Signing before commit**: the lease is signed in the activation's transaction, with the license row still locked, so a signing failure (the tenant has no active key yet) rolls back the seat, the start of a `from_first_activation` term and the `activation.create` entry with its webhook, and a revoke can't land between the commit and the lease. The signer uses the same transaction, so one pool connection is enough. (Amended 2026-11-11: the original signed after the commit, which left the seat taken and the term running on a signing failure; only the idempotent path signed before the commit.)
- **Audit**: new activations (a move is marked in its entry, with the new `rehost_count`), deactivations, and refused activations and deactivations with a valid key are audited (bounded by the per-key rate limit); refreshes and re-activations of an active machine are not (high volume, [ADR-0027 Audit log](0027-audit-log.md)); unknown keys are counted in metrics. Rate limits on the activation API are keyed per license key, not only per client address.

## Consequences
- Vendors who sell node-locked licenses get a hard cap on machine moves by setting `max_rehosts`; others get Keygen-style free moves.
- Revocation takes effect within one lease (the vendor's `lease_seconds`), not lease + grace, except in the license's last lease.
- Moves increase `rehost_count` even when `max_rehosts` is unset; ADR-0013's upgrade reset must treat "no limit → a limit" as lower.
- `spec/license-format.md` needs prose updates (example payload, `grace` and `refresh_after` rows); no format or vector change.

## Alternatives considered
- **Self-service deactivation never counts**: makes `max_rehosts` meaningless for online licenses.
- **Rate-limit deactivations instead of counting them**: a time window is harder to explain to customers than a number on the license.
- **Grace on every lease**: forgiving of outages, but revocation latency becomes lease + grace.
