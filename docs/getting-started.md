# Getting started

From an empty cluster to an app that checks its license. Every step links to the reference that covers it in full. Alpha: see the [README](../README.md) for what isn't released yet.

## 1. What you need

- **Kubernetes** with an ingress controller (or a load balancer) that terminates TLS for one public host, say `licenses.vendor.example`. Your customers' apps call it, as do you and your team.
- **PostgreSQL 17 or newer**, reachable with TLS (`sslmode=verify-full`).
- **An OIDC provider** (Keycloak, Entra ID, Okta, Google, …) for dashboard login. LicenseForge stores no passwords. Register a client:
  - Authorization Code with PKCE;
  - redirect URI `https://licenses.vendor.example/auth/callback`;
  - scopes `openid email profile`.

  See the [Secure Configuration Guide](../compliance/secure-configuration-guide.md#oidc).

## 2. Database and Secrets

Run [`deploy/database-setup.sql`](../deploy/database-setup.sql) once as a database admin, with your own passwords. Then create the two Secrets the chart reads, as in the [chart README](../deploy/helm/licenseforge/README.md#before-installing). The `master-keys` value encrypts license keys and signing keys at rest, and the database alone can't decrypt them. **Back up `master-keys` and the database together.** Losing either means:
- you lose your signing keys;
- every customer needs a build that trusts new keys;
- online leases stop renewing.

## 3. Install

```sh
kubectl create secret generic licenseforge-oidc --from-literal=client-secret='…'
helm install licenseforge oci://ghcr.io/licenseforge/charts/licenseforge --version <version> \
  --set secrets.server=licenseforge-server --set secrets.migrate=licenseforge-migrate \
  --set oidc.enabled=true --set oidc.issuer=https://idp.vendor.example/realms/main \
  --set oidc.clientID=licenseforge --set oidc.redirectURL=https://licenses.vendor.example/auth/callback \
  --set oidc.clientSecret.secretName=licenseforge-oidc \
  --set bootstrapAdmin=you@vendor.example \
  --set trustedProxies=<your ingress controller's CIDRs>
```

[Verify the release](verifying-releases.md) first. Route `licenses.vendor.example` to the `licenseforge` Service (port 80) through your ingress. The chart creates no Ingress, because its TLS and class are yours. `curl https://licenses.vendor.example/readyz` answers `ok` when the server is up.

`bootstrapAdmin` makes you the platform admin at your first login: `issuer|subject`, or an email your IdP marks verified. The [chart README](../deploy/helm/licenseforge/README.md#platform-and-session-settings) lists the other settings. Set `platformMFAPolicy` to `mfa` or stronger in production.

## 4. Your tenant

1. Sign in at `https://licenses.vendor.example`. As platform admin you land on **Tenants (platform)**.
2. Choose **New tenant**, with the email of the person who will own it (it can be you), then **Create and invite**.
3. The owner opens the invitation link, signs in with that email, and accepts. Platform admins don't become members of tenants.

There's no browser in reach, or no platform admin yet? Create the tenant from a server pod instead: `licenseforge tenant create` ([chart README](../deploy/helm/licenseforge/README.md#the-first-tenant)).

## 5. Before the first license

As the tenant's owner:

1. **Signing keys → Generate key.** Every license and lease is signed with it.
2. Copy the **trusted key set** (JSON, or Go source) and the **tenant ID** (`tnt_…`) from the same page. Your app's builds embed both. Plan key rotation now ([ADR-0026](adr/0026-signing-key-lifecycle.md)): a build trusts only the keys it was built with.

## 6. Catalog, customer, license

1. **Products → New product** (its slug, such as `acme-db`, goes in your app). On the product's page:
   - add **features**: on/off, or limits such as `seats`;
   - add **plans** (duration, max activations, lease and offline settings, machine or cluster binding);
   - fill in the feature × plan matrix.
2. **Customers → New customer.**
3. **Licenses → Issue license**: product, plan, customer. **The license key is shown once**: send it to your customer.

Everything here also works through the API (`api/openapi.yaml`) with an API token (**API tokens** page), or with `licenseforge api` ([CLI](cli.md)). Webhooks (**Webhooks** page, [docs](webhooks.md)) tell your other systems about activations and license changes.

## 7. Your app

Your app takes the license key from its user, activates once per machine or cluster, and then checks the signed lease before licensed work. The SDKs do all of it, retries and offline verification included:

- [Go](../sdk/go/README.md#online-activation)
- [TypeScript](../sdk/ts/README.md) (Node 22+)
- [Java](../sdk/java/README.md) (17+)

Each needs the server URL, the tenant ID, the product slug, the user's license key and the trusted key set. In Kubernetes, give the app's ServiceAccount the RBAC its README lists, so the lease is kept in a ConfigMap or Secret and the cluster is one seat.

**Air-gapped customers:**
1. Their app writes a request file.
2. You turn it into a license file in the **Offline** section of the **Licenses** page, or with `licenseforge offline`.
3. Their app installs that file.

To return the seat, their app writes a deactivation receipt. See the [CLI docs](cli.md) and each SDK README.

## 8. Running it

- **Metrics:** Prometheus on a separate port (`metrics.serviceMonitor.enabled`).
- **Audit:** a hash-chained audit log, viewable on the **Audit log** page and exportable to a SIEM (`audit.export`).
- **Retention:** `auditRetention`.
- **Upgrades:** they run the migrations first.

See the [chart README](../deploy/helm/licenseforge/README.md) and the [Secure Configuration Guide](../compliance/secure-configuration-guide.md).
