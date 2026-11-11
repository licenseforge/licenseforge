# Verifying a release

Every release is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) from a `v*` tag and signed keyless with [Sigstore](https://www.sigstore.dev/): there is no long-lived signing key; the signing certificate names the workflow and the tag that built it (ADR-0005, ADR-0021, ADR-0024).

| Artifact | Where | Signature | SBOM (SPDX) | SLSA provenance |
|---|---|---|---|---|
| Server image | `ghcr.io/licenseforge/licenseforge:X.Y.Z` | cosign | attestation | attestation |
| FIPS server image | `ghcr.io/licenseforge/licenseforge:X.Y.Z-fips` | cosign | attestation | attestation |
| Helm chart | `oci://ghcr.io/licenseforge/charts/licenseforge`, version `X.Y.Z` | cosign | | attestation |
| Server binaries, linux amd64 and arm64 | GitHub release assets | cosign bundle of `SHA256SUMS` | attestation and `.spdx.json` asset | attestation |
| TypeScript SDK | npm `@licenseforge/sdk` (its own version, tag `sdk/ts/vX.Y.Z`) | npm registry signature | | npm provenance |
| Java SDK | Maven Central `io.licenseforge:licenseforge-sdk` (its own version, tag `sdk/java/vX.Y.Z`) | PGP (`.asc`, Central's requirement) | | attestation |

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

## TypeScript SDK (npm)

[`sdk-ts-release.yml`](../.github/workflows/sdk-ts-release.yml) publishes `@licenseforge/sdk` from an `sdk/ts/vX.Y.Z` tag with npm trusted publishing (the workflow's GitHub OIDC identity; no npm token exists) and npm provenance: a Sigstore-signed SLSA attestation naming the repository, the commit and the workflow that built the tarball (ADR-0021, amended).

```sh
npm install @licenseforge/sdk@next   # prereleases; @licenseforge/sdk once a stable version exists
npm audit signatures                 # in your project, after npm ci or npm install
```

`npm audit signatures` checks the registry's signature on every installed package and the provenance attestations that are present. It doesn't fail on a package without one, and it doesn't check whose workflow made it. So check the identity yourself: the package's npm page shows the provenance; it must name `licenseforge/licenseforge`, `.github/workflows/sdk-ts-release.yml` and an `sdk/ts/v*` tag. The package's publishing access refuses tokens: any other version could only come from an npm maintainer publishing interactively with 2FA, and would have no provenance, so check it. Pin the version and keep the lockfile: its `integrity` hash makes every later install the same bytes.

## Java SDK (Maven Central)

[`sdk-java-release.yml`](../.github/workflows/sdk-java-release.yml) builds `io.licenseforge:licenseforge-sdk` from an `sdk/java/vX.Y.Z` tag, signs the jars and pom with the release PGP key (Maven Central requires PGP), and attests the jars' SLSA build provenance. The bundle is published on Central by a maintainer after checking it.

```sh
V=0.1.0-alpha.1
B=https://repo1.maven.org/maven2/io/licenseforge/licenseforge-sdk/$V
FPR=…   # the release key's fingerprint from SECURITY.md: 40 uppercase hex digits, no spaces
curl -fsSLO "$B/licenseforge-sdk-$V.jar" -fsSLO "$B/licenseforge-sdk-$V.jar.asc"
gpg --keyserver hkps://keys.openpgp.org --recv-keys "$FPR"
gpg --status-fd 1 --verify "licenseforge-sdk-$V.jar.asc" "licenseforge-sdk-$V.jar" | grep "VALIDSIG $FPR "   # that key, not any key you have
gh attestation verify "licenseforge-sdk-$V.jar" --repo licenseforge/licenseforge \
  --cert-identity "https://github.com/licenseforge/licenseforge/.github/workflows/sdk-java-release.yml@refs/tags/sdk/java/v$V" \
  --source-ref "refs/tags/sdk/java/v$V" --deny-self-hosted-runners
```

A "Good signature" from another key proves nothing: Central accepts any key on a public keyserver, so only the fingerprint ties a release to LicenseForge. In a build, pin the version, and check signatures with your build tool where it can (Gradle's dependency verification with the key's fingerprint, or Maven's PGP verification plugin).

## Air-gapped verification

`gh attestation download oci://$IMAGE --repo licenseforge/licenseforge` (and the same for the chart or a binary) saves the attestation bundles. Verify them offline with `gh attestation verify --bundle <file> --custom-trusted-root <trusted_root.jsonl>`; get the trusted root with `gh attestation trusted-root` while online.

## For maintainers: first npm release of the TypeScript SDK

npm attaches a trusted publisher only to a package that exists, so the first version needs a one-time bootstrap. A real version published by hand would have no provenance, so the bootstrap publishes a placeholder instead:

1. In GitHub, create the environment `npm` (a required reviewer; deployment tags `sdk/ts/v*`) and add `refs/tags/sdk/ts/v*` to the release-tag ruleset. Do this first: the trusted publisher of step 4 has a two-day window.
2. Create the npm organization `licenseforge`, with 2FA required for its members.
3. Publish a placeholder `@licenseforge/sdk@0.0.0` (a `package.json` and a README pointing to `@next`) from your own `npm login` session: `npm publish --access public` (a scoped package is otherwise restricted, which a free organization can't publish). No token is needed. Then `npm deprecate @licenseforge/sdk@0.0.0 "placeholder: install @licenseforge/sdk@next"`.
4. In the package settings, add the trusted publisher (GitHub Actions; `licenseforge/licenseforge`; workflow `sdk-ts-release.yml`; environment `npm`), and set Publishing access to "Require two-factor authentication and disallow tokens".
5. On the commit to tag, run the end-to-end journeys (`e2e/env/up.sh`, then `make e2e`, which runs the SDK as built there against the server): every journey passes.
6. Within two days, tag a commit on `main`: `git tag -s sdk/ts/v0.1.0-alpha.1 <commit> && git push origin sdk/ts/v0.1.0-alpha.1`. npm expires a trusted publisher configuration that hasn't published within two days; if that happens, delete it and add it again.
7. Check `npm dist-tag ls @licenseforge/sdk`: `next` is the alpha, and `latest` stays on the placeholder until the first stable version.

## For maintainers: first Maven Central release of the Java SDK

1. In GitHub, create the environment `maven-central` (a required reviewer; deployment tags `sdk/java/v*`) and add `refs/tags/sdk/java/v*` to the release-tag ruleset.
2. On the Central Portal (central.sonatype.com), with 2FA on the account, verify the namespace `io.licenseforge` with the DNS TXT record it gives for `licenseforge.io`, and generate a user token. Store `printf %s 'username:password' | base64 -w0` (no newline, no wrapping) as the environment secret `CENTRAL_TOKEN`.
3. Create the release PGP key: RSA 4096, the primary key itself signing (Central verifies against primary keys: no signing subkey), with an expiry. Publish it to keys.openpgp.org (verify the email so the user ID is kept) and keyserver.ubuntu.com, and add its fingerprint to `SECURITY.md` as one string of 40 uppercase hex digits without spaces. Store the armored private key and its passphrase as the environment secrets `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`, and the 40-hex-digit fingerprint (uppercase) as the environment variable `PGP_FINGERPRINT`; keep an offline, encrypted backup of the key.
4. On the commit to tag, run the end-to-end journeys (`e2e/env/up.sh`, then `make e2e`): every journey passes.
5. Tag a commit on `main`: `git tag -s sdk/java/v0.1.0-alpha.1 <commit> && git push origin sdk/java/v0.1.0-alpha.1`. The run fails unless Central validates the bundle; then check the deployment on the Central Portal (files, signatures) and press Publish. Central releases can't be removed: a mistake means a new version.

## For maintainers: a release that failed halfway

Published versions are never moved. If a release run fails after pushing (for example signing during a Sigstore outage), use **Re-run failed jobs** within 5 days, while the build artifact exists: the publish jobs recognise the identical images and chart and finish signing and attesting them. **Re-run all jobs** rebuilds with new timestamps, so the digests differ and the run stops with "already exists"; the way out then is a new version tag.
