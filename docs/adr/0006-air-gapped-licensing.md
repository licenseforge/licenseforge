# ADR-0006 Air-gapped licensing

*Status: accepted · Date: 2026-11-02*

## Context
Customers running the vendor's software with no internet must still be licensed, for a limited time, and the software must stop (or degrade) if no renewed license is installed.

## Decision
Offline activation via file exchange, same format as online ([ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md)):
1. Vendor app (via SDK/CLI) generates an **activation request** file: license key + fingerprint + nonce. Not secret, can be carried on USB/email.
2. Someone with access uploads it to the vendor's LicenseForge (portal, API, or `lf` CLI).
3. LicenseForge returns a **license file** with `exp` = plan's offline duration (e.g. 90d) and `grace`.
4. File is installed into the air-gapped system: a file path, or on Kubernetes `kubectl create configmap app-license --from-file=license.lic` mounted as a directory. Renewal = update the ConfigMap; SDK picks it up without restart.
5. SDK verifies offline. After `exp` → grace warnings; after `exp + grace` → vendor-defined block.
6. Renewal = repeat with a new request before expiry.

Plan flag `offline_allowed` controls whether a plan permits this; offline activations count toward `max_activations`.

Clock rollback mitigation: SDK persists the highest timestamp seen; significant backwards jumps invalidate.

## Consequences
- No server needed at the customer site for v0.2.
- Offline licenses **can't be revoked early**. Documented trade-off; vendors pick shorter durations for riskier customers.
- Fingerprint must be stable across reboots/upgrades or customers get locked out. Fingerprint design is an open question.

## Certification amendments (2026-11-02)
- Every offline issuance and deactivation receipt is recorded server-side in the audit log (who, when, which request file hash), so offline licenses are as traceable as online ones.
- Air-gap delivery doubles as a selling point for regulated buyers (defence, government, critical infrastructure) where outbound connectivity is forbidden.

## Future (v0.4)
**On-prem license server**: vendor issues one site license to a self-hosted LicenseForge "edge" instance in the customer's cluster; it hands out floating seats locally. Same signing chain, delegated.

## Alternatives considered
- **Hardware dongles**: hardware logistics, not cloud/k8s friendly.
- **Phone-home required periodically**: defeats air-gapped.
