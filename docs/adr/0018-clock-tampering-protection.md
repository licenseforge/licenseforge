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

## Implementation note (2026-11-02)
Go SDK package `sdk/go/clock`, revised after review:
- `Now(local)` returns `max(local, mark)` for `CheckOptions.Now`; it never folds the license `iat` in, so the future-`iat` check (#2) still works.
- `Observe(t, local)` raises the mark with a genuine time (a license `iat` *after* it passed its claim checks), **capped at local + tolerance** so a fast vendor clock can't lock out an air-gapped user. `Reset(serverTime)` after an online refresh is the only way to lower the mark.
- The rollback check always runs. If the state can't be locked or written (read-only directory, ConfigMap mount, contention) the time is returned with `ErrNotPersisted`; if locking is unavailable (network filesystem, unsupported OS) the write happens without the lock (rename is atomic). A store that can't run the check at all gives `ErrUnreadable` (no usable time). The mark is only rewritten when it moves ≥ 1 minute.
- Tolerance: nil = 24h, 0 = strict, negative rejected.
- `FileStore` serializes processes with an OS advisory lock (flock / LockFileEx, released by the OS if a process dies, so no clock-dependent stale-lock logic) and writes atomically (temp, fsync, rename with retries for Windows, directory fsync).
- State that is empty, unparsable, unreadable or fails the MAC (hand-edited, crash damage, a file left by a root run, a new license key) counts as **no state**, like deletion. A hard "tampered" error was dropped: an attacker could bypass it by writing garbage, so it would only lock out honest users. This refines the Decision above: hand edits are not *reported*, they are *ignored*. The MAC's remaining job is tying the state to one license key.
- HMAC key = `SHA-256("licenseforge clock v1|" + license key)`, not HKDF: FIPS 140-only mode rejects HKDF inputs under 112 bits. The MAC is tamper evidence, not a FIPS security function (the key is on the client, [ADR-0014 Product scope and won't-do list](0014-product-scope-and-won-t-do-list.md)). Replaying an old state file is equivalent to deleting it and is accepted.
- Offline recovery from `ErrRollback`, after fixing the clock: delete the state file. `Reset` must only receive an authenticated server time (a verified lease `iat`).

## Consequences
- An attacker can gain at most 24h by rolling the clock back.
- Legitimate drift up to 24h never locks anyone out.
- Deleting the stored state resets the mark; this is within the documented threat model (client can be tampered with). `max_offline` on online leases bounds the damage.

## Alternatives considered
- **Secure time from TPM / trusted time servers**: unavailable air-gapped, complex.
- **No tolerance**: locks out sites with drifting clocks.
