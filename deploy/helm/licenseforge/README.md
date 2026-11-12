# LicenseForge Helm chart

Runs the LicenseForge server on Kubernetes (ADR-0005): a stateless Deployment,
a pre-install/pre-upgrade Job for database migrations, a Service, a
PodDisruptionBudget, a NetworkPolicy and an optional HorizontalPodAutoscaler.
Pods meet the Pod Security Standard **restricted**.

## Before installing

1. PostgreSQL 17 or newer with the logins from
   [`deploy/database-setup.sql`](../../database-setup.sql) (ADR-0009).
   **Upgrading from a release before audit retention (ADR-0036):** create the
   group role first, as a database admin, or the migration Job stops with an
   error: `CREATE ROLE licenseforge_retention NOLOGIN;`
   **Every database URL must verify the server** (`sslmode=verify-full`, or
   `verify-ca` with `sslrootcert`) unless the host is local: otherwise the
   migration Job, the server and audit retention refuse to start (SC-8).
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

Install a release's chart, which runs that release's image ([verify it first](../../../docs/verifying-releases.md)):

```sh
helm install licenseforge oci://ghcr.io/licenseforge/charts/licenseforge --version <version> \
  --set secrets.server=licenseforge-server \
  --set secrets.migrate=licenseforge-migrate
```

From a checkout (`deploy/helm/licenseforge`), the image tag defaults to the chart's `appVersion`, which is no published image: set `image.tag` (and `image.repository` for your own build). Chart and image must come from the same release.

Without OIDC there is no dashboard login, and the first tenant's owner can't accept the invitation: set up [OIDC](#dashboard-login-oidc) before onboarding anyone.

Upgrades run `licenseforge migrate` first; the rollout starts only if it
succeeds. The Job's deadline (`migrate.activeDeadlineSeconds`, 280s) is below
Helm's default `--timeout` of 5m; raise both together for long migrations. Set `image.digest` to pin the exact (signed) image, and
`image.tag=<version>-fips` for the FIPS build.

The Secrets can come from a secret manager (External Secrets Operator, Secrets Store CSI Driver): see [Secret managers](../../../docs/secret-managers.md).

## Dashboard login (OIDC)

Register a client in your IdP first: Authorization Code with PKCE, redirect URI `https://<host>/auth/callback`, scopes `openid email profile` ([Secure Configuration Guide](../../../compliance/secure-configuration-guide.md#oidc)).

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
API server on that port; in production narrow it. Rules add up: while webhook
delivery is on, egress on 443 is open to any destination for webhooks (narrow
`webhooks.egress.to`), so narrowing `oidc.egress.to` alone doesn't close 443. Narrow `oidc.egress.to` to the provider's CIDRs, or to a
namespace/pod selector for an in-cluster Keycloak. With a selector, the port
is the provider's **pod** port, because policies apply after the Service's
DNAT: Keycloak listens on 8443 (or 8080 over plain HTTP), not the Service's
443. Rendering fails if OIDC is on without the issuer, client ID or redirect
URL, or without a port.

## Webhooks

Every server pod delivers tenants' webhooks (ADR-0044; receivers: [Webhooks](../../../docs/webhooks.md)); `webhooks.workers` (default 8, `0` for none) sets how many at once per pod. The server refuses internal, link-local and cloud metadata addresses whatever the NetworkPolicy allows, and connects only on `webhooks.ports` (443). The NetworkPolicy allows egress on those ports to any destination (on upgrade too: this widens a release's egress); narrow it with `webhooks.egress.to`, or set `webhooks.workers: 0` to deliver none and add no rule. For a self-hosted, single-vendor install with receivers on a private network, list their ranges in `webhooks.allowCIDRs` (every tenant can then reach them; loopback, link-local and metadata addresses stay refused). On an IPv6-only cluster with an operator-chosen NAT64 prefix, add the prefix to `webhooks.denyCIDRs`.

## The first tenant
A platform admin creates tenants on the dashboard's **Tenants** screen (`/platform`; a platform admin without tenants lands there), or with `POST /api/v1/platform/tenants` (ADR-0042). Name the first platform admin with `bootstrapAdmin` (`issuer|subject`, or an email your IdP marks verified): that user becomes platform admin at their first login, while there is none. Without a platform admin yet, or without a browser, create a tenant from a server pod, which already has the platform login:

```sh
kubectl -n licenseforge exec deploy/licenseforge -- /licenseforge tenant create \
  --slug acme --name "Acme" --owner-email owner@acme.example
```

It prints the invite path once (`/invite#token=…`). Send `https://<host>` plus that path to the owner, who signs in with that email (verified by your IdP) and accepts. The platform admin or operator never becomes a member of the tenant.

Run it with `kubectl exec`, not as a Job: the invite token goes to your terminal, and a Job would keep it in the pod logs. The audit entry names the system with `via: cli` (every exec runs as the same container user), so who ran it is in your Kubernetes API audit log of the `exec`.

## Platform and session settings

| Value | Server setting | Default |
|---|---|---|
| `apiHost` | `LICENSEFORGE_API_HOST`: the host that serves the API alone (API tokens and license keys only there, sessions only elsewhere) | one host for both |
| `bootstrapAdmin` | `LICENSEFORGE_BOOTSTRAP_ADMIN`: the first platform admin (ADR-0031) | none |
| `platformMFAPolicy` | `LICENSEFORGE_PLATFORM_MFA_POLICY`: `none`, `mfa` or `phishing_resistant` for platform admins' sessions (ADR-0038). Set `mfa` or stronger in production | `none` |
| `loginBanner` | `LICENSEFORGE_LOGIN_BANNER`: shown before login (AC-8) | none |
| `session.idleTimeout`, `session.maxAge` | `LICENSEFORGE_SESSION_IDLE_TIMEOUT`, `_MAX_AGE` (AC-12) | `1h`, `12h` |

The [Secure Configuration Guide](../../../compliance/secure-configuration-guide.md) describes each. Your customers' apps call `https://<host>/api/v1/activation/...` (or `apiHost`'s): expose it through your ingress with TLS.

## Notes

- **A private CA** (internal or enterprise PKI) for the OIDC provider or the database: put the CA's PEM in a Secret and set `extraCA.secretName` (and `extraCA.key`, `ca.crt` by default). The server, the migration Job and the audit-prune CronJob trust it in addition to the image's bundle; a SIEM sink with its own `caSecret` trusts only that. Restart the pods after changing the Secret.
- **A development cluster** whose database has no TLS: set `databaseAllowPlaintext: true` (the server, the migration Job and the audit-prune CronJob then accept any database URL, and the server logs a warning at every start). Never in production.
- **Behind an ingress**, set `trustedProxies` to the ingress controller's addresses (CIDRs): the server then takes the client from `X-Forwarded-For` for its per-address rate limit and audit entries. Unset, every client counts as the ingress.

- **NetworkPolicy**: ingress on 8080, egress to DNS and the database port
  (plus the OIDC provider when `oidc.enabled`, SIEM collectors when configured,
  and webhook receivers on `webhooks.ports` while `webhooks.workers` > 0),
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
  delivered only then. A collector that closes without it gets every batch resent
  indefinitely; that shows as `licenseforge_audit_export_failures_total` and
  growing `licenseforge_audit_export_lag_seconds`. Certificates are re-read
  for every batch, so renewed Secrets apply without a restart. Messages over
  8 KB (RFC 5425's minimum) are sent but logged, as a collector may truncate them. Narrow the egress with `audit.export.syslog.to`.
- **OTLP export** (ADR-0036): `audit.export.otlp.endpoint` sends every audit
  entry as OTLP logs over HTTP with the JSON encoding (attributes `lf.audit.*`,
  including seq, prev_hash and hash). `caSecret`, `clientSecret` (mTLS) and
  `headersSecret` (key `headers`, e.g. `authorization=Bearer%20…`) are
  optional; the NetworkPolicy egress port is the endpoint's (443 if it names
  none). No HTTP proxy is used (as for syslog): allow the collector itself.
  A batch counts as delivered only on a 2xx response with an empty body or an
  OTLP JSON body that rejects no record; anything else is retried, visible as
  export failures and lag.
- **Audit retention** (ADR-0036): set `auditRetention.enabled` and
  `auditRetention.secret` (a Secret with `retention-database-url`, the
  `licenseforge_pruner` login) to run `licenseforge audit prune` on
  `auditRetention.schedule` (`concurrencyPolicy: Forbid`). Tenant owners set
  their own retention (365 to 36,500 days); `auditRetention.platformDays` sets
  the platform chain's (empty keeps everything). Nothing a registered SIEM
  sink hasn't received is pruned.
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
