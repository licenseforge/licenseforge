# ADR-0018 Clock tampering protection

*Status: accepted · Date: 2026-11-02*

## Context
Offline and cached licenses are checked against the local clock. Setting the clock back would extend a license forever. Air-gapped machines also drift legitimately because they have no NTP to the internet.

## Decision
SDKs and agent apply three checks:

1. **High-water mark**: persist the highest trusted time ever seen (max of local clock, license `iat`, server time from leases). If the clock is more than **24h** behind it → license invalid until a fresh online refresh or a new license file.
2. **Future-issued check**: license `iat` more than **24h** in the future → treated as clock tamper/skew, invalid (message tells the admin to fix the clock).
3. **Online leases use server time**: each lease carries the server's time (`iat`); the SDK stores the offset and uses `max(local, server-adjusted)` for expiry checks while online.

- 24h tolerance is an SDK option (calibration knob): stricter vendors can lower it; sites with bad clocks can raise it.
- High-water mark is stored with the lease ([ADR-0011 Secret manager integrations](0011-secret-manager-integrations.md) storage). Memory-only storage resets it on restart, so offline/air-gapped use requires persistent storage (file, ConfigMap, Secret, or add-on); the SDK warns otherwise.
- The high-water value is HMAC'd with a key derived from the license key, so editing the stored value by hand is detectable (raises the bar; not a guarantee, see threat model in [ADR-0014 Product scope and won't-do list](0014-product-scope-and-won-t-do-list.md)).

## Consequences
- An attacker can gain at most 24h by rolling the clock back.
- Legitimate drift up to 24h never locks anyone out.
- Deleting the stored state resets the mark; this is within the documented threat model (client can be tampered with). `max_offline` on online leases bounds the damage.

## Alternatives considered
- **Secure time from TPM / trusted time servers**: unavailable air-gapped, complex.
- **No tolerance**: locks out sites with drifting clocks.
