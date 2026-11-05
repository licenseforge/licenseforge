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
helm upgrade licenseforge deploy/helm/licenseforge --reset-then-reuse-values \
  --set oidc.enabled=true --set oidc.issuer=https://idp.example/realms/acme \
  --set oidc.clientID=licenseforge --set oidc.redirectURL=https://licenseforge.example/auth/callback \
  --set oidc.clientSecret.secretName=licenseforge-oidc
```

`--reset-then-reuse-values` (Helm 3.14+) keeps your values and takes this
chart's defaults for keys your release doesn't have yet; plain `--reuse-values`
would leave `oidc.*` without its defaults on a release installed before it.

The server discovers the provider at start, so the NetworkPolicy then also
allows egress to it on `oidc.egress.port` (443) and that port only. By default
that is to any destination, like the DNS and database rules: an external IdP's
addresses are rarely fixed, and a port-scoped rule keeps the rest of egress
closed. "Any destination" includes in-cluster pods, nodes and the Kubernetes
API server on that port; in production narrow it. Narrow `oidc.egress.to` to the provider's CIDRs, or to a
namespace/pod selector for an in-cluster Keycloak. With a selector, the port
is the provider's **pod** port, because policies apply after the Service's
DNAT: Keycloak listens on 8443 (or 8080 over plain HTTP), not the Service's
443. Rendering fails if OIDC is on without the issuer, client ID or redirect
URL, or without a port.

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
- **Audit export** (ADR-0036): set `audit.export.syslog.host` to send every
  audit entry to your SIEM as RFC 5424 syslog over TLS (RFC 5425, port 6514 by
  default, TLS 1.2+, certificate verification always on). `caSecret` names a
  Secret with `ca.crt` (otherwise system roots); `clientSecret` a
  `kubernetes.io/tls` Secret for mTLS. Delivery is at-least-once: deduplicate
  on the entry `id`, and alert when a chain's `seq` doesn't follow on or
  `prev_hash` isn't the previous `hash`. The collector must answer the
  sender's TLS `close_notify` with its own (RFC 5425 §5.3): a batch counts as
  delivered only then. Narrow the egress with `audit.export.syslog.to`.
- **Metrics**: Prometheus `/metrics` on its own port (`metrics.port`, 9090),
  never on the http port, and without auth: the NetworkPolicy lets only
  `metrics.scrapeFrom` reach it (default: pods in the `monitoring` namespace;
  empty: nobody). A separate, always-ClusterIP Service `<release>-metrics`
  exposes it as port `metrics`, so a LoadBalancer or NodePort `service.type`
  never publishes it. Set `metrics.serviceMonitor.enabled` for the Prometheus
  Operator, with `metrics.serviceMonitor.labels` matching your Prometheus, and
  keep `metrics.scrapeFrom` matching where that Prometheus runs: with an empty
  `scrapeFrom` the ServiceMonitor exists but every scrape is blocked. Labels carry route
  patterns and outcomes only, never tenants, users or license keys.
- **Shutdown**: on SIGTERM the server fails readiness and keeps serving for
  `drainSeconds`, then shuts down gracefully (up to 15s). Keep
  `terminationGracePeriodSeconds` above the sum.
- **Autoscaling**: turning `autoscaling.enabled` on in an upgrade briefly
  drops the Deployment to one replica until the HPA scales it.
- Not in the chart yet: Ingress, optional Keycloak and PostgreSQL subcharts.
