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

Run [`deploy/database-setup.sql`](../deploy/database-setup.sql) once as a database admin, with your own passwords. Then create the two Secrets the chart reads, as in the [chart README](../deploy/helm/licenseforge/README.md#before-installing). The `master-keys` value encrypts license keys and signing keys at rest, and the database alone can't decrypt them. **Back up both, stored apart** (anyone holding both can decrypt the keys), and keep the backups in step. Losing either means:
- you lose your signing keys;
- every customer needs a build that trusts new keys;
- online leases stop renewing.

## 3. Install

```sh
kubectl create namespace licenseforge   # the Secrets of step 2 go here too (-n licenseforge)
kubectl -n licenseforge create secret generic licenseforge-oidc --from-literal=client-secret='…'
helm install licenseforge oci://ghcr.io/licenseforge/charts/licenseforge --version <version> -n licenseforge \
  --set secrets.server=licenseforge-server --set secrets.migrate=licenseforge-migrate \
  --set oidc.enabled=true --set oidc.issuer=https://idp.vendor.example/realms/main \
  --set oidc.clientID=licenseforge --set oidc.redirectURL=https://licenses.vendor.example/auth/callback \
  --set oidc.clientSecret.secretName=licenseforge-oidc \
  --set bootstrapAdmin=you@vendor.example \
  --set-string trustedProxies='10.0.0.0/8\,fd00::/8'   # your ingress controller's CIDRs; escape commas for --set
```

[Verify the release](verifying-releases.md) first. Route `licenses.vendor.example` to the `licenseforge` Service (port 80) through your ingress. The chart creates no Ingress, because its TLS and class are yours. `curl https://licenses.vendor.example/readyz` answers `ok` when the server is up.

`bootstrapAdmin` makes you the platform admin at your first login: an email your IdP marks verified, or `'issuer|subject'` (quote it in the shell). The [chart README](../deploy/helm/licenseforge/README.md#platform-and-session-settings) lists the other settings. Set `platformMFAPolicy` to `mfa` or stronger in production.

## 4. Your tenant

1. Sign in at `https://licenses.vendor.example`. As platform admin you land on **Tenants (platform)**.
2. Choose **New tenant**: a slug (it can't change later, and it appears in API paths), a name, and the email of the person who will own it. Then choose **Create and invite**.
3. **Copy the invitation link now.** It is shown once, works once, and expires after 7 days. Send it to the owner. Lost it? Use **New owner invite** on the same screen, or `licenseforge tenant invite-owner` ([CLI](cli.md)).
4. The owner opens the link, signs in with that email, and accepts. To own the tenant yourself, invite your own email and accept: being platform admin doesn't make you a member of any tenant.

There's no browser in reach, or no platform admin yet? Create the tenant from a server pod instead: `licenseforge tenant create` ([chart README](../deploy/helm/licenseforge/README.md#the-first-tenant)).

## 5. Before the first activation or build

As the tenant's owner:

1. **Signing keys → Generate key.** Leases and offline license files are signed with it. You can issue licenses without one, but nothing activates until it exists (`503 no_signing_key`).
2. Copy the **trusted key set** (JSON, or Go source) and the **tenant ID** (`tnt_…`) from the same page. Your app's builds embed both. Plan key rotation now ([ADR-0026](adr/0026-signing-key-lifecycle.md)): a build trusts only the keys it was built with.

## 6. Catalog, customer, license

1. **Products → New product** (its slug, such as `acme-db`, goes in your app). On the product's page:
   - add **features**: on/off, or limits such as `seats`;
   - add **plans** (duration, max activations, lease and offline settings, machine or cluster binding). Plans with binding None, for site licenses, have no activations and no way yet to deliver their file to an app;
   - fill in the feature × plan matrix.
2. **Customers → New customer.**
3. **Licenses → Issue license**: product, plan, customer. **The license key is shown once**: send it to your customer.

Everything here also works through the API (`api/openapi.yaml`) with an API token (**API tokens** page), or with `licenseforge api` ([CLI](cli.md)). Webhooks (**Webhooks** page, [docs](webhooks.md)) tell your other systems about activations and license changes.

## 7. Your app

Your app takes the license key from its user, activates once per machine or cluster, and then checks the signed lease before licensed work. The SDKs do all of it, retries and offline verification included. **They aren't published yet** (alpha): the Go module isn't tagged, and the npm and Maven Central releases are pending. Until then, build them from this repository: each SDK's README says how.

- [Go](../sdk/go/README.md#online-activation)
- [TypeScript](../sdk/ts/README.md) (Node 22+)
- [Java](../sdk/java/README.md) (17+)

Each needs the server URL, the tenant ID, the product slug, the user's license key and the trusted key set. In Kubernetes, keep the lease in a ConfigMap or Secret so the cluster is one seat:
- create the object beforehand;
- give the app's ServiceAccount `get` and `update` on it by name, plus `get` on the `kube-system` namespace for the cluster fingerprint.

Each SDK's README has the details.

**Air-gapped customers:**
1. Their app writes a request file.
2. You open the license on the **Licenses** page, choose **Offline → Offline activation**, and paste or upload their `lfreq1…` request. Or use `licenseforge offline activate`.
3. Their app installs that file.

To return the seat, their app writes a deactivation receipt. See the [CLI docs](cli.md) and each SDK README.

## 8. Running it

- **Metrics:** Prometheus on a separate port (`metrics.serviceMonitor.enabled`).
- **Audit:** a hash-chained audit log, viewable on the **Audit log** page and exportable to a SIEM (`audit.export`).
- **Retention:** `auditRetention.enabled` and `auditRetention.secret` (the `licenseforge_pruner` login from the database setup); off by default.
- **Upgrades:** they run the migrations first.

See the [chart README](../deploy/helm/licenseforge/README.md) and the [Secure Configuration Guide](../compliance/secure-configuration-guide.md).
