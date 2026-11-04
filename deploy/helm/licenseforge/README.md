# LicenseForge Helm chart

Runs the LicenseForge server on Kubernetes (ADR-0005): a stateless Deployment,
a pre-install/pre-upgrade Job for database migrations, a Service, a
PodDisruptionBudget, a NetworkPolicy and an optional HorizontalPodAutoscaler.
Pods meet the Pod Security Standard **restricted**.

## Before installing

1. PostgreSQL 17 or newer with the four logins from
   [`deploy/database-setup.sql`](../../database-setup.sql) (ADR-0009).
2. Two Secrets, created by you or by External Secrets (never in values):

   ```sh
   kubectl create secret generic licenseforge-server \
     --from-literal=database-url='postgres://licenseforge_api:…@db:5432/licenseforge?sslmode=verify-full' \
     --from-literal=platform-database-url='postgres://licenseforge_admin:…@db:5432/licenseforge?sslmode=verify-full' \
     --from-literal=identity-database-url='postgres://licenseforge_login:…@db:5432/licenseforge?sslmode=verify-full' \
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
succeeds. The Job's deadline (`migrate.activeDeadlineSeconds`, 280s) is below
Helm's default `--timeout` of 5m; raise both together for long migrations. Set `image.digest` to pin the exact (signed) image, and
`image.tag=<version>-fips` for the FIPS build.

## Dashboard login (OIDC)

```sh
kubectl create secret generic licenseforge-oidc --from-literal=client-secret='…'   # omit for a public client
helm upgrade licenseforge deploy/helm/licenseforge --reuse-values \
  --set oidc.enabled=true --set oidc.issuer=https://idp.example/realms/acme \
  --set oidc.clientID=licenseforge --set oidc.redirectURL=https://licenseforge.example/auth/callback \
  --set oidc.clientSecret.secretName=licenseforge-oidc
```

The server discovers the provider at start, so the NetworkPolicy then also
allows egress to it on `oidc.egress.port` (443), to any address by default.
Narrow `oidc.egress.to` to the provider's CIDRs, or to a namespace/pod selector
for an in-cluster Keycloak. Rendering fails if OIDC is on without the issuer,
client ID or redirect URL.

## Notes

- **NetworkPolicy**: ingress on 8080, egress to DNS and the database port only
  (plus the OIDC provider when `oidc.enabled`),
  for the server and (as a hook policy, so it applies from the first install)
  the migration Job. It needs a CNI that enforces policies. Narrow
  `networkPolicy.ingressFrom` to your ingress controller and
  `networkPolicy.databaseTo` to the database (an `ipBlock`, or selectors for an
  in-cluster database). On OpenShift set `networkPolicy.dns.ports: [5353]`.
  The migration policy is a hook resource: `helm uninstall` leaves it behind
  (it selects only migration pods); delete it with the release's namespace.
- **Shutdown**: on SIGTERM the server fails readiness and keeps serving for
  `drainSeconds`, then shuts down gracefully (up to 15s). Keep
  `terminationGracePeriodSeconds` above the sum.
- **Autoscaling**: turning `autoscaling.enabled` on in an upgrade briefly
  drops the Deployment to one replica until the HPA scales it.
- Not in the chart yet: Ingress, optional Keycloak and PostgreSQL subcharts.
