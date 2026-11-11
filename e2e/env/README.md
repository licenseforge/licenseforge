# e2e environment

The deployment the end-to-end tests run against (ADR-0041). It runs locally on minikube and isn't part of CI yet. **Every secret here is a dev value: never reuse this setup outside your machine.**

What `up.sh` deploys, in namespace `licenseforge-e2e`:

- PostgreSQL 17, set up by [`deploy/database-setup.sql`](../../deploy/database-setup.sql).
- Keycloak as the OIDC provider, with realm `licenseforge`, a confidential client, and users `admin` and `viewer` (password `licenseforge`).
- LicenseForge from its Helm chart: by default the chart and an image built from this checkout, or a published release.
- HTTPS ingresses on `lf-e2e.<minikube ip>.nip.io` and `kc-e2e.<minikube ip>.nip.io`, signed by a local CA that the script creates.
- Tenant `acme`, with an owner invitation for `admin@licenseforge.local` that the journeys accept on their first login. This stays until tenants can be created through the product.

## Use
Needs minikube, kubectl, helm, openssl, python3 and curl; `make e2e` also builds the TypeScript and Java SDKs (Node 22+, JDK 17+ and Maven). kubectl's current context must be the minikube profile (`minikube`, or `MINIKUBE_PROFILE`); `up.sh` refuses any other cluster.

```sh
minikube start --driver=docker --cpus=4 --memory=6g --addons=ingress
e2e/env/up.sh                          # the checkout's chart and image (rebuilds the image)
e2e/env/up.sh --release 0.1.0-alpha.1  # or a published release
make e2e                               # the API and SDK journeys (MVN=… to pick Maven)
make e2e-browser                       # the dashboard smoke test (Playwright)
```

`up.sh` can be re-run, for example after changing code. The CA, the master key and the test tenant's invite token are kept in `e2e/env/.state/` (gitignored). Import `.state/ca.crt` in your browser to open the dashboard without certificate warnings.

Tear down with `kubectl delete ns licenseforge-e2e` and `rm -r e2e/env/.state`. Always remove both together, or neither: the invite token and the master key in `.state` belong to that namespace's database.

`up.sh` adds the two hostnames to CoreDNS's `hosts` block (cluster-wide, in `kube-system`), because some resolvers drop nip.io answers that point at private addresses. Remove those two lines with `kubectl -n kube-system edit configmap coredns`, or `minikube delete` drops everything.

Keycloak in dev mode keeps no data. After a restart it imports the realm again, with the same user IDs, so sign-ins and memberships carry over.

The test tenant `acme` is created by `up.sh` with `licenseforge tenant create` (ADR-0042), and is shared by runs. `TestPlatformAdminOnboardsTenant` creates a new tenant through the platform API on each run, owned by `viewer`. `--release` needs a version that has `tenant create` (any after 0.1.0-alpha.1).
