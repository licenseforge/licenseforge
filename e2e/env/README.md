# e2e environment

The deployment the end-to-end tests run against (ADR-0041). It runs locally on minikube and isn't part of CI yet. **Every secret here is a dev value: never reuse this setup outside your machine.**

What `up.sh` deploys, in namespace `licenseforge-e2e`:

- PostgreSQL 17, set up by [`deploy/database-setup.sql`](../../deploy/database-setup.sql).
- Keycloak as the OIDC provider, with realm `licenseforge`, a confidential client, and users `admin` and `viewer` (password `licenseforge`).
- LicenseForge from its Helm chart: by default the chart and an image built from this checkout, or a published release.
- HTTPS ingresses on `lf-e2e.<minikube ip>.nip.io` and `kc-e2e.<minikube ip>.nip.io`, signed by a local CA that the script creates.
- Tenant `acme`, with an owner invitation for `admin@licenseforge.local` that the journeys accept on their first login. This stays until tenants can be created through the product.

## Use

```sh
minikube start --driver=docker --cpus=4 --memory=6g --addons=ingress
e2e/env/up.sh                          # the checkout's chart and image (rebuilds the image)
e2e/env/up.sh --release 0.1.0-alpha.1  # or a published release
make e2e                               # the journeys
```

`up.sh` can be re-run, for example after changing code. The CA, the master key and the seed are kept in `e2e/env/.state/` (gitignored). Import `.state/ca.crt` in your browser to open the dashboard without certificate warnings.

Tear down with `kubectl delete ns licenseforge-e2e` and `rm -r e2e/env/.state`.

## Known gaps

- The chart can't trust an extra CA yet, so `up.sh` patches the Deployment so the server trusts the local CA for Keycloak.
- The tenant is seeded in the database, because there's no platform-admin route to create tenants yet.
