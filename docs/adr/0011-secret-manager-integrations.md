# ADR-0011 Secret manager integrations

*Status: accepted · Date: 2026-11-02*

## Context
Vendors' customers want the license key, license file, and online lease to live in the secret store they already run: AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, OpenBao.

Constraint: [ADR-0010 Official SDKs Go, Java, TypeScript](0010-official-sdks-go-java-typescript.md) says SDK cores have zero runtime dependencies. Pulling five cloud SDKs into every app that embeds LicenseForge would be massive dependency bloat and version-conflict pain for vendors.

## Decision
Three layers, cheapest first:

**1. Kubernetes: no SDK code, use the existing syncers (v0.2, docs + Helm examples)**
- External Secrets Operator: AWS SM, GCP SM, Azure KV, Vault, OpenBao → Kubernetes Secret → mounted file.
- Secrets Store CSI Driver (AWS/GCP/Azure/Vault providers) → mounted file.
- SDK just reads the mounted file and watches it (same path as [ADR-0006 Air-gapped licensing](0006-air-gapped-licensing.md)). Rotation in the vault flows through automatically.
  > **Amended 2026-11-09**: the SDK doesn't watch files. The app reads the mounted license key at start, and checks the mounted license file now and then, calling the offline client's `Install` when it changes (Go: `ExampleClient_Install_mounted`); `Install` refuses an older file of the same license, so a stale copy can't roll a renewal back. The "Helm examples" are the syncer manifests in `docs/secret-managers.md`: the LicenseForge chart already takes existing Secrets, so it needs no templates of its own.

**2. VMs / bare metal: agent-rendered files (v0.2, docs)**
- Vault Agent / OpenBao Agent templates render the secret to a file; SDK reads it.

**3. Official add-on packages (v0.3), the primary integration path**
- The SDK's storage interface ([ADR-0004 Signed license files with Ed25519](0004-signed-license-files-with-ed25519.md)) gets official adapters published as **separate modules**, e.g. `licenseforge-go/store/awssm`, `@licenseforge/store-azurekv`, `licenseforge-java-store-vault`.
- Read key/file, and read+write the online lease (for stateless apps that can't write disk or ConfigMaps).
- Core SDK stays dependency-free; vendors pull only the adapter they use.
- Vault and OpenBao share one adapter (OpenBao is API-compatible), KV v2.
- All four are official and supported. Build order: Vault/OpenBao → AWS → Azure → GCP.
- Each add-on passes a shared storage conformance suite (read, write, conflict on concurrent lease update) run against real backends in CI (Vault/OpenBao in containers; cloud ones against test accounts).

## Consequences
- Layers 1 and 2 cover most deployments with zero code, available as soon as file-watching ships.
- Layer 3 is 4 add-ons × 3 languages = 12 packages to maintain and release. Shared conformance suite and one release pipeline per language keep that manageable; the public storage interface lets the community add more (e.g. CyberArk, 1Password).
- Auth to the secret store (IRSA, GKE Workload Identity, Azure Workload Identity, Vault k8s auth) is delegated to each cloud's default credential chain, no custom auth code.

## Related, separate decision (future ADR)
Server-side **signing-key** custody in KMS / Vault Transit / OpenBao Transit / HSM, so tenant private keys never exist in LicenseForge memory. Requires each backend to support Ed25519 signing; verify per provider before committing (Vault Transit does; check current AWS KMS, GCP KMS, Azure Key Vault support).

## Alternatives considered
- **Built-in cloud clients in every SDK core**: breaks zero-dependency rule, bloats vendor apps.
- **LicenseForge sidecar that talks to vaults**: another process to deploy; ESO/CSI already do this better.
