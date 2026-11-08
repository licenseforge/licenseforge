# LicenseForge

**Open-source, Kubernetes-native software licensing.** Define products, features and plans; issue licenses; control activations online and in air-gapped environments.

> [!WARNING]
> Alpha (`0.1.0-alpha.1`): online licensing, the admin dashboard core and the compliance baseline work; air-gapped activation and the other SDKs come next (design in the [ADRs](docs/adr/README.md)). The license format and API can change while 0.x and the spec is a draft. Not ready for production.

## Why
- **Apache-2.0, all of it.** Server, SDKs, Helm chart. No paywalled self-hosting.
- **Signed licenses** (Ed25519) that SDKs verify offline. Online activation is a short lease; revocation means the lease isn't renewed.
- **Air-gapped first-class.** Request file in, license file out, with expiry and grace period.
- **Kubernetes-native.** Helm chart, cluster-bound licenses, in-cluster agent, secret-manager integrations.
- **Feature catalog per product.** Sell a product in plans; the license decides which features each customer gets.

## Planned components
| Component | Status |
|---|---|
| Server (API, dashboard, workers) | in progress |
| `lf` CLI | planned (v0.2) |
| Go SDK ([`sdk/go`](sdk/go/README.md)) | in progress: offline verification, fingerprints, clock guard, online client |
| Java / TypeScript SDKs | planned (v0.2) |
| In-cluster agent | planned (v0.3) |
| Helm chart | planned (v0.1) |

## Docs
- [Architecture Decision Records](docs/adr/README.md)
- [License file format (`lf1`)](spec/license-format.md)
- [Go SDK](sdk/go/README.md)
- [Verifying a release](docs/verifying-releases.md): signatures, SBOMs and SLSA provenance of images, chart and binaries

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md). Commits must be signed off (DCO). Security issues: [SECURITY policy](https://github.com/licenseforge/.github/blob/main/SECURITY.md).

## License
[Apache License 2.0](LICENSE). "LicenseForge" is a trademark of its authors; the license does not grant trademark rights.
