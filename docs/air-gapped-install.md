# Air-gapped install

Every release has one file with what an install without internet access needs: `licenseforge_<version>_airgap.tar` (ADR-0006, ADR-0024). It holds:

| Path | What |
|---|---|
| `images/licenseforge.oci.tar`, `images/licenseforge-fips.oci.tar` | The server images, standard and FIPS, linux/amd64 and linux/arm64 (OCI archives, the same bytes as on ghcr.io) |
| `images/DIGESTS` | Each image's digest: what the cosign signatures cover and what to deploy by |
| `chart/licenseforge-<version>.tgz` | The Helm chart |
| `database-setup.sql` | The one-time database setup ([getting started](getting-started.md), step 2) |
| `spec/` | The license format and its conformance vectors, for testing an SDK or your own verifier |
| `README.md` | This page |
| `SHA256SUMS` | Checksums of everything above |

PostgreSQL 17+ and an OIDC identity provider (e.g. Keycloak) are not in the bundle: run your own, as for any install.

## 1. On a connected machine: download and verify

```sh
VERSION=0.2.0   # without the leading v
gh release download "v$VERSION" --repo licenseforge/licenseforge \
  -p "licenseforge_${VERSION}_airgap.tar" -p SHA256SUMS -p SHA256SUMS.sigstore.json
```

Then verify `SHA256SUMS` and the bundle exactly as for a binary ([verifying releases](verifying-releases.md#server-binaries), steps 1 to 3, with the bundle's file name). Carry the bundle across the air gap.

## 2. Inside: unpack and check

```sh
tar -xf "licenseforge_${VERSION}_airgap.tar"
cd "licenseforge_${VERSION}_airgap"
sha256sum -c SHA256SUMS
```

## 3. Images into your registry

`--all --preserve-digests` keeps both platforms and the digest, so the signed digest is what runs:

```sh
REGISTRY=registry.internal.example/licenseforge
skopeo copy --all --preserve-digests oci-archive:images/licenseforge.oci.tar "docker://$REGISTRY/licenseforge:$VERSION"
skopeo copy --all --preserve-digests oci-archive:images/licenseforge-fips.oci.tar "docker://$REGISTRY/licenseforge:$VERSION-fips"   # if you run FIPS
cat images/DIGESTS
```

`skopeo inspect --raw "docker://$REGISTRY/licenseforge:$VERSION" | sha256sum` gives the same digest as `images/DIGESTS`.

To enforce signatures in the cluster (e.g. a cosign admission policy), the signatures and attestations have to be in your registry too. On the connected machine, `cosign save "ghcr.io/licenseforge/licenseforge@<digest>" --dir sigs` saves the image with them; carry `sigs/` across and run `cosign load --dir sigs "$REGISTRY/licenseforge"`. Verifying offline needs Sigstore's trusted root, as in [air-gapped verification](verifying-releases.md#air-gapped-verification).

## 4. Database, Secrets, install

Run `database-setup.sql` and create the Secrets as in [getting started](getting-started.md), step 2. Install from the bundled chart, pointing it at your registry and deploying by digest:

```sh
helm install licenseforge "chart/licenseforge-$VERSION.tgz" -n licenseforge \
  --set image.repository="$REGISTRY/licenseforge" \
  --set image.digest=sha256:…   # from images/DIGESTS; the -fips line for the FIPS image
  # …and the settings from getting started, step 3
```

The server never calls out: activations, refreshes and webhooks only reach what you configure. For machines that can't reach the server either, use [offline activation](cli.md).
