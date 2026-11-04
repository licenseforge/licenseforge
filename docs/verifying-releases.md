# Verifying a release

Every release is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) from a `v*` tag and signed keyless with [Sigstore](https://www.sigstore.dev/): there is no long-lived signing key; the signing certificate names the workflow and the tag that built it (ADR-0005, ADR-0021, ADR-0024).

| Artifact | Where | Signature | SBOM (SPDX) | SLSA provenance |
|---|---|---|---|---|
| Server image | `ghcr.io/licenseforge/licenseforge:X.Y.Z` | cosign | attestation | attestation |
| FIPS server image | `ghcr.io/licenseforge/licenseforge:X.Y.Z-fips` | cosign | attestation | attestation |
| Helm chart | `oci://ghcr.io/licenseforge/charts/licenseforge`, version `X.Y.Z` | cosign | | attestation |
| Server binaries, linux amd64 and arm64 | GitHub release assets | cosign bundle of `SHA256SUMS` | attestation and `.spdx.json` asset | attestation |

Images, chart and server share one version (ADR-0023). Attestations are stored with GitHub and, for images and chart, also in the registry next to the artifact.

Set the version once. The examples need [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v3 and the [GitHub CLI](https://cli.github.com/) (`gh auth login` first).

```sh
VERSION=0.1.0   # without the leading v
ID="https://github.com/licenseforge/licenseforge/.github/workflows/release.yml@refs/tags/v$VERSION"
ISSUER=https://token.actions.githubusercontent.com
```

Use the exact identity above, not a pattern: it pins the repository, the workflow and the tag.

## Images

```sh
IMAGE=ghcr.io/licenseforge/licenseforge:$VERSION   # or :$VERSION-fips
cosign verify "$IMAGE" --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"

# SLSA build provenance, then the SBOM
gh attestation verify "oci://$IMAGE" --repo licenseforge/licenseforge \
  --cert-identity "$ID" --source-ref "refs/tags/v$VERSION" --deny-self-hosted-runners
gh attestation verify "oci://$IMAGE" --repo licenseforge/licenseforge \
  --cert-identity "$ID" --predicate-type https://spdx.dev/Document/v2.3
```

Deploy by the verified digest (`cosign verify` prints it; the chart takes it as `image.digest`), not by the tag. Add `--bundle-from-oci` to `gh attestation verify` to read the attestations from the registry instead of GitHub, for example from a mirror.

## Helm chart

```sh
CHART=ghcr.io/licenseforge/charts/licenseforge:$VERSION
cosign verify "$CHART" --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
gh attestation verify "oci://$CHART" --repo licenseforge/licenseforge \
  --cert-identity "$ID" --source-ref "refs/tags/v$VERSION"
```

Install by the verified digest: `helm install licenseforge oci://ghcr.io/licenseforge/charts/licenseforge@sha256:…`.

## Server binaries

Download the binary for your architecture, `SHA256SUMS` and `SHA256SUMS.sigstore.json` from the release, then:

```sh
gh release download "v$VERSION" --repo licenseforge/licenseforge \
  -p "licenseforge_${VERSION}_linux_amd64" -p SHA256SUMS -p SHA256SUMS.sigstore.json

# 1. The checksums file was signed by the release workflow for this tag.
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$ID" --certificate-oidc-issuer "$ISSUER"
# 2. The binary matches it.
sha256sum --ignore-missing -c SHA256SUMS
# 3. SLSA build provenance of the binary.
gh attestation verify "licenseforge_${VERSION}_linux_amd64" --repo licenseforge/licenseforge \
  --cert-identity "$ID" --source-ref "refs/tags/v$VERSION" --deny-self-hosted-runners
```

On macOS use `shasum -a 256 --ignore-missing -c SHA256SUMS`.

## Air-gapped verification

`gh attestation download oci://$IMAGE --repo licenseforge/licenseforge` (and the same for the chart or a binary) saves the attestation bundles. Verify them offline with `gh attestation verify --bundle <file> --custom-trusted-root <trusted_root.jsonl>`; get the trusted root with `gh attestation trusted-root` while online.
