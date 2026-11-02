# ADR-0017 Default machine fingerprint

*Status: accepted · Date: 2026-11-02*

## Context
Licenses are bound to a machine or cluster ([License File Format](../../spec/license-format.md) `bind`). The fingerprint must be **stable** across reboots, upgrades and pod rescheduling (or customers get locked out) and **unique** enough to stop casual copying. Hardware-based fuzzy matching (Keygen, Cryptlex) targets desktops; our primary target is Kubernetes and servers ([ADR-0014 Product scope and won't-do list](0014-product-scope-and-won-t-do-list.md)).

## Decision
SDKs and the agent pick the first available source:

| Environment | Source | Notes |
|---|---|---|
| Kubernetes (in-cluster) | `kube-system` namespace UID | Stable for the cluster's lifetime. Needs `get` on that namespace (agent's ServiceAccount). Default `bind.type: cluster`. |
| Linux | `/etc/machine-id` | systemd standard. |
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | |
| macOS | `IOPlatformUUID` | |
| Docker without k8s | none reliable | SDK returns an error asking for an explicit ID (mount host `/etc/machine-id` or set `LICENSEFORGE_FINGERPRINT`). |

- The raw ID never leaves the machine: fingerprint = `sha256(product_id + ":" + raw_id)`. Different vendors get different fingerprints for the same machine (no cross-vendor tracking), and the raw ID isn't stored server-side.
- **Vendor override**: SDK option to supply their own fingerprint function or value (e.g. a hardware serial, a cloud instance ID, a TPM-backed ID).
- Fingerprint source is recorded in the activation (`fp_source`), so support can see why a machine changed.

## Amendment (2026-11-02, from implementation review; pending maintainer confirmation)
- `LICENSEFORGE_FINGERPRINT` is honoured **only when the vendor enables it** in the SDK (off by default). Anyone who can set an env var could otherwise reuse one binding on every machine without root. Vendors supporting plain Docker enable it, or customers mount the host `/etc/machine-id`.
- Linux: tmpfs machine-ids (regenerated each boot) are refused; in containers only a bind-mounted host machine-id is trusted; more container markers (`/run/systemd/container`, `container=` in PID 1's environment).
- Kubernetes lookups retry transient failures and report them as transient, separate from RBAC/permission errors.
- Exact per-source normalisation is in [License File Format](../../spec/license-format.md) (Fingerprints).
- Open: hash input uses the product ID only. On a multi-tenant hosted server two tenants could use the same product slug, giving identical fingerprints for the same machine across vendors. Decide whether the hash input becomes tenant-qualified.

## Consequences
- Zero config on Kubernetes, Linux, Windows, macOS.
- Known limit: cloned VMs that didn't reset `machine-id` share a fingerprint. Documented; vendors who care use the override.
- Rebuilding a cluster changes the UID → customer uses rehost ([ADR-0013 License data model hardening](0013-license-data-model-hardening.md)).
- No fuzzy multi-component matching until Later.

## Alternatives considered
- **MAC address / CPU / disk serials**: change on cloud and in containers; privacy-sensitive.
- **Node name / hostname**: random in containers, renamed freely.
