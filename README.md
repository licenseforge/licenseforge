# LicenseForge

**Open-source, Kubernetes-native software licensing.** Define products, features and plans; issue licenses; control activations online and in air-gapped environments.

> [!WARNING]
> Alpha: online and air-gapped (offline) licensing, the admin dashboard, the CLI and the compliance baseline work on `main`; the latest release, `0.1.0-alpha.1`, predates offline activation, webhooks and `licenseforge tenant create`. The SDKs aren't published yet (see each SDK's README). The license format and API can change while 0.x and the spec is a draft. Not ready for production.

## Why
- **Apache-2.0, all of it.** Server, SDKs, Helm chart. No paywalled self-hosting.
- **Signed licenses** (Ed25519) that SDKs verify offline. Online activation is a short lease; revocation means the lease isn't renewed.
- **Air-gapped first-class.** Request file in, license file out, with expiry and grace period.
- **Kubernetes-native.** Helm chart, cluster-bound licenses, in-cluster agent, secret-manager integrations.
- **Feature catalog per product.** Sell a product in plans; the license decides which features each customer gets.

## Try it locally
With Docker, on your machine:

```sh
git clone https://github.com/licenseforge/licenseforge && cd licenseforge
docker compose up --build
```

1. Open http://localhost:8080 (`localhost`, not `127.0.0.1`: the sign-in cookies are per host) and sign in as **demo / demo** (a local Keycloak).
2. You're the platform admin. **New tenant**, with `demo@licenseforge.local` as the owner, then open the invitation link and accept it.
3. Follow [Getting started](docs/getting-started.md) from step 5: signing key, product, plan, customer, license. Point an SDK at `http://localhost:8080`; plain http is accepted for localhost only.

After `docker compose restart keycloak`, also run `docker compose restart server` (it shares Keycloak's network). `docker compose down -v` throws it all away. Every password and key in `compose.yaml` is a public dev value: never reuse them.

## Planned components
| Component | Status |
|---|---|
| Server (API, dashboard, workers) | in progress |
| CLI ([docs](docs/cli.md)) | `licenseforge api`, `offline` and `tenant` |
| Go SDK ([`sdk/go`](sdk/go/README.md)) | verification, fingerprints, clock guard, online client, Kubernetes lease stores, offline activation; not tagged yet |
| TypeScript SDK ([`sdk/ts`](sdk/ts/README.md)) | feature parity with Go; release workflow ready, first release pending |
| Java SDK ([`sdk/java`](sdk/java/README.md)) | feature parity with Go; release workflow ready, first release pending |
| Helm chart ([`deploy/helm/licenseforge`](deploy/helm/licenseforge/README.md)) | published with each release |
| In-cluster agent | planned (v0.3) |

## Docs
- **[Getting started](docs/getting-started.md)**: install, first tenant, first license, your app
- [Architecture Decision Records](docs/adr/README.md)
- [License file format (`lf1`)](spec/license-format.md)
- [Installing with Helm](deploy/helm/licenseforge/README.md), then the [Secure Configuration Guide](compliance/secure-configuration-guide.md) (OIDC client, TLS, backups)
- SDKs: [Go](sdk/go/README.md), [TypeScript](sdk/ts/README.md), [Java](sdk/java/README.md)
- [Webhooks](docs/webhooks.md) and [secret managers](docs/secret-managers.md)
- [Command line](docs/cli.md): `licenseforge api`, `offline` and `tenant`
- [Verifying a release](docs/verifying-releases.md): signatures, SBOMs and SLSA provenance of images, chart and binaries

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md). Commits must be signed off (DCO). Security issues: [SECURITY policy](https://github.com/licenseforge/.github/blob/main/SECURITY.md).

## License
[Apache License 2.0](LICENSE). "LicenseForge" is a trademark of its authors; the license does not grant trademark rights.
