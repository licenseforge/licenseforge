# LicenseForge Helm chart

Runs the LicenseForge server on Kubernetes (ADR-0005): a stateless Deployment,
a pre-install/pre-upgrade Job for database migrations, a Service, a
PodDisruptionBudget, a NetworkPolicy and an optional HorizontalPodAutoscaler.
Pods meet the Pod Security Standard **restricted**.

## Before installing

1. PostgreSQL 17 or newer with the three logins from
   [`deploy/database-setup.sql`](../../database-setup.sql) (ADR-0009).
2. Two Secrets, created by you or by External Secrets (never in values):

   ```sh
   kubectl create secret generic licenseforge-server \
     --from-literal=database-url='postgres://licenseforge_api:…@db:5432/licenseforge?sslmode=verify-full' \
     --from-literal=platform-database-url='postgres://licenseforge_admin:…@db:5432/licenseforge?sslmode=verify-full' \
     --from-literal=master-keys="k1=$(openssl rand -base64 32)"
   kubectl create secret generic licenseforge-migrate \
     --from-literal=owner-database-url='postgres://licenseforge_owner:…@db:5432/licenseforge?sslmode=verify-full'
   ```

   Keep them separate: only the migration Job reads the owner login, and the
   server refuses to start if it can see it. Back up `master-keys`: without it
   encrypted data can't be read.

## Install

```sh
helm install licenseforge deploy/helm/licenseforge \
  --set secrets.server=licenseforge-server \
  --set secrets.migrate=licenseforge-migrate
```

Upgrades run `licenseforge migrate` first; the rollout starts only if it
succeeds. Set `image.digest` to pin the exact (signed) image, and
`image.tag=<version>-fips` for the FIPS build.

## Notes

- **NetworkPolicy**: ingress on 8080, egress to DNS and the database port only.
  It needs a CNI that enforces policies; narrow `networkPolicy.ingressFrom` to
  your ingress controller and `networkPolicy.databaseCIDRs` to the database.
- **Shutdown**: on SIGTERM the server fails readiness and keeps serving for
  `drainSeconds`, then shuts down gracefully (up to 15s). Keep
  `terminationGracePeriodSeconds` above the sum.
- Not in the chart yet: Ingress, optional Keycloak and PostgreSQL subcharts.
