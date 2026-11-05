# Secure Configuration Guide

For operators deploying the LicenseForge server. It follows the FedRAMP 20x Secure Configuration Guide idea (ADR-0024): the settings that matter for security, their safe values, and why. Status as of `main`, 2026-11-04; features marked *planned* aren't in the server yet.

The server is a stateless Go binary. All state lives in PostgreSQL 17+ and in one Secret, the master keys. Deploy it with the Helm chart ([`deploy/helm/licenseforge`](../deploy/helm/licenseforge/README.md)); `compose.yaml` is for local development only and uses public passwords.

## Environment variables

Read by [`cmd/licenseforge/main.go`](../cmd/licenseforge/main.go). The server refuses to start if a required one is missing or unsafe.

| Variable | Required | Default | Security notes |
|---|---|---|---|
| `LICENSEFORGE_DATABASE_URL` | yes (server) | – | Tenant pool, login `licenseforge_api`. Add `sslmode=verify-full` (the server doesn't enforce TLS; see [Database logins](#database-logins)). Secret |
| `LICENSEFORGE_PLATFORM_DATABASE_URL` | yes (server) | – | Platform pool, login `licenseforge_admin` (all tenants). Secret |
| `LICENSEFORGE_IDENTITY_DATABASE_URL` | yes (server) | – | Login-path pool, login `licenseforge_login` (ADR-0029). Secret |
| `LICENSEFORGE_OWNER_DATABASE_URL` | `migrate` only | – | Schema owner. **The server refuses to start if this is set.** Give it only to the migration Job. Secret |
| `LICENSEFORGE_MASTER_KEYS` | yes (server) | – | Keyring, `id=base64key[,…]`; parsed at start ([below](#secrets-and-the-keyring)). Secret |
| `LICENSEFORGE_ADDR` | no | `:8080` | Listen address (also `-addr`). Plain HTTP: put TLS in front ([TLS and ingress](#tls-and-ingress)). The chart's probes and NetworkPolicy assume 8080 |
| `LICENSEFORGE_DRAIN` | no | `5s` | How long the server keeps serving after SIGTERM while readiness fails. The chart sets it from `drainSeconds` |
| `LICENSEFORGE_OIDC_ISSUER` | no | unset = dashboard login off | Exactly the ID token's `iss`. Must be https (http only on localhost). Discovered at start: an unreachable provider stops the server |
| `LICENSEFORGE_OIDC_CLIENT_ID` | with the issuer | – | Also the required audience of ID tokens |
| `LICENSEFORGE_OIDC_CLIENT_SECRET` | no | empty = public client (PKCE only) | Prefer a confidential client. Secret: pass it with `secretKeyRef`, never as a literal |
| `LICENSEFORGE_OIDC_REDIRECT_URL` | with the issuer | – | `https://<public host>/auth/callback`. Its origin is the only trusted origin for unsafe requests (CSRF) |
| `LICENSEFORGE_SESSION_IDLE_TIMEOUT` | no | `1h` | Dashboard session idle timeout (AC-12): at least `5m`, at most the max age. Out of bounds stops the server |
| `LICENSEFORGE_SESSION_MAX_AGE` | no | `12h` | Dashboard session lifetime after login (AC-12, IA-11): `1h` to `24h` (the database cap) |
| `LICENSEFORGE_LOGIN_BANNER` | no | unset = no banner | System use notification shown on `/login` before sign-in (AC-8): plain text, at most 4 KB, newlines and tabs allowed, no other control, format or separator characters. Users must agree before login starts |
| `LICENSEFORGE_AUDIT_SYSLOG_ADDR` | no | unset = no SIEM export | `host:port` of the collector (RFC 5424 over TLS, RFC 5425; ADR-0036). TLS 1.2+, the certificate is always verified. Set it: the SIEM is the external anchor of the audit chains (AU-6, AU-9) |
| `LICENSEFORGE_AUDIT_SYSLOG_CA_FILE` | no | system roots | PEM roots for the collector's certificate (chart: `audit.export.syslog.caSecret`) |
| `LICENSEFORGE_AUDIT_SYSLOG_CERT_FILE`, `_KEY_FILE` | no | no client certificate | mTLS client certificate and key, both or neither (chart: `audit.export.syslog.clientSecret`) |
| `LICENSEFORGE_AUDIT_SYSLOG_SERVER_NAME` | no | the address's host | Name the collector's certificate must carry |
| `LICENSEFORGE_AUDIT_VERIFY_INTERVAL` | no | `15m` | How often one replica verifies every audit chain from the head it last verified and writes an `audit.checkpoint` entry ([below](#audit-verification-and-alerts)). `0` turns it off |
| `LICENSEFORGE_AUDIT_VERIFY_FULL_INTERVAL` | no | `168h` | How often the verification starts from each chain's anchor instead (a full check) |
| `LICENSEFORGE_AUDIT_SYSLOG_SD_ID` | no | `licenseforge@32473` | RFC 5424 structured data ID, `name@PEN`. 32473 is the documentation PEN; set your own if your SIEM rules key on it |
| `LICENSEFORGE_AUDIT_OTLP_ENDPOINT` | no | unset = no OTLP export | OTLP/HTTP logs URL with the JSON encoding, `https://…/v1/logs` (http only on loopback; ADR-0036). TLS 1.2+, verified. A batch is delivered only on a 2xx with an empty body or an OTLP JSON body rejecting no record. No HTTP proxy is used |
| `LICENSEFORGE_AUDIT_OTLP_CA_FILE`, `_CERT_FILE`, `_KEY_FILE` | no | system roots, no client certificate | As for syslog (chart: `audit.export.otlp.caSecret`, `clientSecret`) |
| `LICENSEFORGE_AUDIT_OTLP_HEADERS` | no | none | Request headers `k=v,k2=v2`, values %-encoded (e.g. an API key). Secret: pass it with `secretKeyRef` (chart: `headersSecret`) |
| `LICENSEFORGE_TRUSTED_PROXIES` | no | unset = no proxy trusted | Comma-separated CIDRs or addresses of your ingress/load balancer. Only their `X-Forwarded-For` is believed, read from the right: the client is the right-most hop that isn't a trusted proxy. List proxies only, never client networks. Prefixes broader than /8 (IPv4) or /32 (IPv6) are refused at start |
| `LICENSEFORGE_RATE_LIMIT_ACTIVATION` | no | `1200` | Requests per client address per minute, per replica, on `/api/v1/activation/` (`0` = off). Many installs can share a customer's egress address; each license key is limited separately (60/min) |
| `LICENSEFORGE_RATE_LIMIT_MANAGEMENT` | no | `600` | The same for the rest of `/api/v1` and `/auth/` except login |
| `LICENSEFORGE_RATE_LIMIT_LOGIN` | no | `60` | The same for `/auth/login` and `/auth/callback` |

`LICENSEFORGE_BOOTSTRAP_ADMIN` (ADR-0003, ADR-0031): `issuer|subject` (recommended) or a verified email. The matching user becomes the first platform admin at login, only while there is none, recorded on the platform audit chain. Read at start. Unset after the first admin exists if you like: it never grants again while any admin exists.

## Audit verification and alerts

ADR-0036. One replica leads the verification: the first to take a session advisory lock on the platform pool keeps it, with its database connection, for its lifetime, and checks that connection before each run; the others try again every interval and take over only once the leader's session is gone (pod stopped, connection dropped; the lock's connection uses TCP keepalives, so a dead leader is noticed in about 90 seconds). The platform pool's `LICENSEFORGE_PLATFORM_DATABASE_URL` must therefore be a direct connection or go through a session-pooling proxy: a transaction-pooling proxy (PgBouncer `pool_mode = transaction`) would hand the lock's session to other clients. Every `LICENSEFORGE_AUDIT_VERIFY_INTERVAL` (Helm `auditVerify.intervalMinutes`) the leader verifies every tenant chain and the platform chain from the head it verified last, held in its memory only, and from each chain's anchor at start and every `LICENSEFORGE_AUDIT_VERIFY_FULL_INTERVAL` (`auditVerify.fullIntervalHours`). An incremental run is cut off after one interval. The full pass may take several runs: each may take `FullInterval / 4`, and the chains a run finished stay done, so the next run continues with the rest. Each run appends `audit.checkpoint` entries to the platform chain: `details.heads` lists `{tenant_id, seq, hash, anchor: {seq, hash}}` (the anchor is where the chain starts after retention; seq 0 while nothing was pruned), up to 200 per entry (`batch` of `batches`), and `details.mode` is `incremental` or `full`. Incremental runs list only chains whose head or anchor moved; the full pass lists every chain. A broken chain makes the entry's outcome `failure` and is listed in `details.broken`; its last good head is kept, and every following run verifies it from the anchor and checks that head is still there unchanged (so a removed tail is caught too), counting it in `licenseforge_audit_verify_failures_total` again until it is repaired. Every verified chain sets `licenseforge_audit_verify_last_success_timestamp_seconds`, so a long full pass still shows progress.

**Alerts.** With the Prometheus Operator's CRDs present and `metrics.serviceMonitor.enabled` on, the chart installs a `PrometheusRule` (`metrics.alerts.*`; set `metrics.alerts.labels` to match your Prometheus's rule selector). Without the ServiceMonitor nothing would scrape the metrics the rules watch, so they aren't installed and the install notes say so; then write equivalent rules for your monitoring:

| Alert | Fires when | Severity |
|---|---|---|
| `LicenseForgeAuditWriteFailures` | an audit entry couldn't be written (its action was rolled back) | critical |
| `LicenseForgeAuditExportLag` | a sink is more than `metrics.alerts.exportLagSeconds` (15 min) behind, for 5 min | warning |
| `LicenseForgeAuditVerifyFailed` | a chain didn't verify in the last hour | critical |
| `LicenseForgeAuditVerifyStalled` | no chain was verified for two intervals (across a leader handover too), or the metric is missing (a stuck, failing or absent verifier) | critical |
| `LicenseForgeRateLimitTableFull` | the per-address rate limit let new addresses through untracked | warning |

Route the critical alerts to whoever is responsible for the audit log (AU-5): the security or compliance owner, not only on-call operations.

**SIEM correlation rule** (the SIEM is the verifier of record). Every exported event carries `id`, `tenant_id`, `seq`, `prev_hash` and `hash`. Delivery is at least once, so first deduplicate on `id`. Then, per `tenant_id`, ordered by `seq`:

```text
for each event e (after dedup on e.id), grouped by e.tenant_id, ordered by e.seq:
  p = previous event of the same tenant_id
  if p exists and (e.seq != p.seq + 1 or e.prev_hash != p.hash):
      alert "audit chain gap or rewrite", tenant_id, p.seq, e.seq
  # the first event of a chain in the SIEM may start at any seq (retention, a sink added later)
```

Also compare the heads in `audit.checkpoint` events (`details.heads[].seq` and `.hash`) with the events you hold for those chains: a checkpoint head you never received means events were lost on the way; a head below what you hold means the chain was truncated in the database.

## Database logins

Create them with [`deploy/database-setup.sql`](../deploy/database-setup.sql) as a database admin (ADR-0009, ADR-0029, ADR-0036). There are four group roles and five logins, and none is shared. Replace the script's placeholder passwords (`change-me-*`) before running it:

| Login | Group | Used by | Can |
|---|---|---|---|
| `licenseforge_owner` | – | `licenseforge migrate` (the Helm pre-install/pre-upgrade Job) | Owns the schema. Its `migrator_all` policies show it every row, and as owner it can change or drop any policy |
| `licenseforge_api` | `licenseforge_app` | Every tenant request | Only rows of the tenant set for the transaction |
| `licenseforge_admin` | `licenseforge_platform` | Platform-admin work | All tenants, through explicit grants |
| `licenseforge_login` | `licenseforge_identity` | Login, sessions, invitation acceptance | Identity tables only; no licensing data |
| `licenseforge_pruner` | `licenseforge_retention` | Audit retention only (ADR-0036) | The only login that deletes audit entries. The database lets it delete only entries at least 365 days old and at or below its chain's newest anchor, and lets it anchor only on a real entry that is at least 365 days old and not the chain's last. That the deleted entries form a prefix is checked by the job's count check (a mismatch rolls the batch back) and detected by Verify and the SIEM's continuity check if bypassed, not enforced by the database. No other table. Upgrading: create the group before `licenseforge migrate` |

**Upgrading to audit retention (ADR-0036).** Before running `licenseforge migrate` (the Helm migration Job) on an install that predates it, create the group role as a database admin: `CREATE ROLE licenseforge_retention NOLOGIN;`, then the pruner login (`deploy/database-setup.sql`). The migration stops with that message otherwise. Retention runs as `licenseforge audit prune` (the chart's `auditRetention` CronJob) with `LICENSEFORGE_RETENTION_DATABASE_URL`; `LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS` (365 to 36,500, unset keeps everything) sets the platform chain's retention, and tenant owners set their own chain's (365 to 36,500 days, audited). Every cut is recorded in the chain as an `audit.retention` entry with the retention period in force (AU-11), and nothing a registered SIEM sink hasn't received is pruned.

**Why the server must never hold the owner login.** Tenant isolation is enforced by forced row-level security, and RLS is a backstop only if the serving process can't turn it off. The owner sees every row, can alter or drop policies and switch RLS off, and can rewrite the audit chain. A serving pod with the owner login would turn any bug or compromise in the internet-facing process into full access to every tenant. So:

- the server exits if `LICENSEFORGE_OWNER_DATABASE_URL` or `LICENSEFORGE_RETENTION_DATABASE_URL` is set, and the chart gives the owner URL only to the migration Job, from its own Secret;
- `store.Open` refuses a serving login that has SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION (directly or through its group), belongs to any role other than its own group, owns the database, schema or any table, can create temporary tables or objects, switched role in the connection string, or has `app.tenant_id` preset. Don't "fix" a refusal by granting more.

Also:
- `REVOKE CONNECT` and `REVOKE TEMPORARY ... FROM PUBLIC` (in the script) keep other logins out and stop temp-table shadowing.
- On Cloud SQL, create the logins with SQL. Console-created users are members of `cloudsqlsuperuser`, which the server refuses.
- **Use TLS with `sslmode=verify-full` in every URL.** The server doesn't enforce database TLS, and the driver (pgx) defaults to `sslmode=prefer`, which falls back to plaintext and doesn't verify the server certificate.
- Use strong unique passwords or IAM authentication, and rotate them like any secret.
- Encrypt the database disk and backups (a deployment requirement, ADR-0024).

## TLS and ingress

The server speaks plain HTTP on 8080 and has no TLS settings. The chart creates a `ClusterIP` Service and no Ingress.

- Terminate TLS at your ingress controller, gateway or service mesh, with TLS 1.2 or newer (1.3 preferred) and a certificate for the public host. For FIPS deployments, the terminating proxy must use a FIPS-validated TLS module. FIPS-only suites in the server are *planned* (Roadmap v0.1).
- Set HSTS at the ingress. Login cookies use the `__Host-` prefix and `Secure`, so login works only over https (or on localhost).
- Route only what users need: `/auth/*` and, later, the API and dashboard. `/healthz` and `/readyz` are for the kubelet. They reveal nothing, but needn't be public.
- **Set `LICENSEFORGE_TRUSTED_PROXIES` to your ingress's addresses** (e.g. the pod CIDR of the ingress controller). Otherwise every client counts as the proxy for the rate limit and in audit entries. The server logs one warning naming the peer the first time it ignores an `X-Forwarded-For`, and counts every ignored header in `licenseforge_forwarded_headers_ignored_total`; the Helm chart's install notes warn while `trustedProxies` is empty. Health checks and the dashboard's static files aren't limited.
- IPv6 clients are counted per /64. A client holding a larger block gets one bucket per /64 in it (a /48 is 65,536 buckets), so the per-address limit doesn't bound an attacker with a large IPv6 allocation; the address table's bound (fail open past it) and the ingress do.
- The server's per-address limit is per replica and fails open for new addresses once 100,000 are tracked in a minute (`licenseforge_rate_limit_untracked_requests_total`); `licenseforge_rate_limited_requests_total` counts 429s by surface. Keep volumetric and connection limits at the ingress. Request bodies are limited to 1 MB; the server cuts requests that take over 30 s to send and responses over 60 s.
- If the proxy rewrites `Host`, keep the browser-facing origin equal to `LICENSEFORGE_OIDC_REDIRECT_URL`'s.

## Secrets and the keyring

`LICENSEFORGE_MASTER_KEYS` encrypts license keys and signing private keys (AES-256-GCM) and keys the license-key lookup hash (ADR-0025).

- Format: `id=base64key[,id=base64key…]`. The id is `[a-z0-9-]{1,32}`; each key is exactly 32 random bytes in padded standard base64: `echo "k1=$(openssl rand -base64 32)"`.
- The **first** key encrypts; every listed key decrypts. To rotate, prepend a new key and keep the old ones: `k2=…,k1=…`. No re-encryption job exists yet (ADR-0025), so **never remove an old key** while data encrypted with it remains.
- Rotate the active key well before 2³² encryptions (random-nonce GCM limit, SP 800-38D).
- Keep secrets out of Helm values. Create the two Secrets yourself or with External Secrets / Secrets Store CSI (ADR-0011): `secrets.server` holds `database-url`, `platform-database-url`, `identity-database-url` and `master-keys`; `secrets.migrate` holds `owner-database-url`. The chart maps explicit keys (never `envFrom`), so the owner URL can't leak into serving pods.
- Restrict who can read these Secrets (RBAC). Anyone with the master keys and a database copy can decrypt license and signing keys.
- **Back up the master keys separately from the database** ([Backups](#backups)).

## OIDC

Login is delegated to your IdP (ADR-0003); LicenseForge stores no passwords.

- Register a client for the Authorization Code flow with PKCE (S256), redirect URI `https://<host>/auth/callback`, scopes `openid email profile`. A confidential client (with `LICENSEFORGE_OIDC_CLIENT_SECRET`) is preferred; a public client works with PKCE alone.
- The server verifies the ID token's signature, issuer, audience, `azp`, expiry and nonce, and bounds every IdP call to 10 s.
- **Enforce MFA in the IdP**, phishing-resistant where required (passkeys, PIV/CAC). LicenseForge records what the IdP asserts in the ID token (`amr`, `acr`, Entra's `acrs`) as each session's assurance, and owners can set a per-tenant MFA policy (ADR-0038), checked on every tenant request from a session (a member short of it gets `403 mfa_required`; API tokens are exempt at use, and creating one needs a qualifying session). **Enforcement is only as strong as the IdP's assertions**: configure the IdP to emit them.
  - Defaults (RFC 8176): `amr` `hwk`, `sc` or `pop` is phishing-resistant; `mfa`, `otp` or `swk` is MFA; `pwd`, `sms` and `tel` never count. Change the sets with `LICENSEFORGE_OIDC_MFA_AMR` and `LICENSEFORGE_OIDC_PHISHING_RESISTANT_AMR`, and add IdP-specific `acr` values with `LICENSEFORGE_OIDC_MFA_ACR` and `LICENSEFORGE_OIDC_PHISHING_RESISTANT_ACR` (comma lists, checked at start; `pwd`, `sms`, `tel` are refused in any case; `none` alone in an AMR variable disables `amr` counting for that level).
  - Okta: `acr` `phr` / `phrh` for phishing-resistant. Entra ID: a Conditional Access authentication context that requires the *Phishing-resistant MFA* strength, returned in `acrs`, the signal of record: set `LICENSEFORGE_OIDC_MFA_AMR=none` and `LICENSEFORGE_OIDC_PHISHING_RESISTANT_AMR=none` (`none` alone disables `amr` counting) and list the contexts in the `_ACR` variables, so only configured `acrs` values count. Keycloak: the "Authentication Method Reference" mapper with a reference value per authenticator (`hwk` for WebAuthn, `sc` for X.509/PIV), or LoA levels as `acr`. Support for each IdP is claimed only after an integration test.
- An email counts only when the IdP sends `email_verified: true`, and invitations are accepted by verified email. A verified email is only as trustworthy as its IdP, so configure only IdPs that verify emails.
- Sessions last 1 hour idle (activity is recorded at most once a minute) and 12 hours at most by default; set `LICENSEFORGE_SESSION_IDLE_TIMEOUT` and `LICENSEFORGE_SESSION_MAX_AGE` to your policy (for example `15m` idle). Changing them needs a restart.
- Set `LICENSEFORGE_LOGIN_BANNER` where a system use notification is required (AC-8). Each completed login logs `login banner acknowledged` with the user and banner ID.
- With the chart in `main`, pass the OIDC variables through `extraEnv`. `values.yaml` says `extraEnv` is not for secrets, meaning no literal secret values; give the client secret as a `valueFrom.secretKeyRef` entry. Also allow egress to the IdP: the chart's NetworkPolicy allows only DNS and the database ([NetworkPolicies](#networkpolicies)). Once PR #49 is merged, use its first-class `oidc.*` values instead (they add the IdP egress rule).

## FIPS image

- Build: `docker build --build-arg GOFIPS140=certified -t licenseforge:<version>-fips .` This uses the Go Cryptographic Module v1.0.0 (CMVP certificate #5247). The binary runs in FIPS 140-3 mode by default; don't set `GODEBUG=fips140=off`.
- Published `-fips` images come with the release pipeline (*planned*); then set `image.tag: <version>-fips` or, better, the digest.
- Every algorithm the server uses is approved in that module: Ed25519, AES-256-GCM, HMAC-SHA256, HKDF-SHA256, SHA-256. CI runs the full test suite with `GODEBUG=fips140=only` on every PR.
- FIPS covers the crypto inside the binary only. TLS at your ingress and PostgreSQL's own crypto need their own validated modules.

## Helm values

From [`values.yaml`](../deploy/helm/licenseforge/values.yaml). Pod security isn't configurable: pods always run as UID 65532, non-root, with a read-only root filesystem, all capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp and no service account token (Pod Security Standard *restricted*).

| Value | Default | Security relevance |
|---|---|---|
| `image.digest` | `""` | Set it in production: signatures cover digests, and tags can move |
| `image.tag` | appVersion | `-fips` suffix for the FIPS build |
| `secrets.server` | required | Secret with the three serving URLs and the master keys; never put the owner URL here |
| `secrets.migrate` | required with `migrate.enabled` | Secret with only `owner-database-url`; read only by the migration Job |
| `migrate.enabled` | `true` | Migrations as a hook Job. Turned off, you must migrate with the owner login elsewhere, never from a serving pod |
| `replicaCount`, `podDisruptionBudget.*`, `autoscaling.*` | 2, on, off | Availability (CP, SC-5) |
| `drainSeconds`, `terminationGracePeriodSeconds` | 5, 30 | No dropped requests on rollout; checked at render |
| `extraEnv` | `[]` | Non-secret settings (OIDC until `oidc.*` lands, PR #49); a secret only as `valueFrom.secretKeyRef`, never a literal. Never add `LICENSEFORGE_OWNER_DATABASE_URL` (the server would refuse to start) |
| `resources` | 100m / 64Mi, limit 256Mi | Bounds a runaway pod |
| `service.type` | `ClusterIP` | Keep it; expose through a TLS ingress, not `LoadBalancer`/`NodePort` |
| `networkPolicy.enabled` | `true` | Keep it on (needs a CNI that enforces policies) |
| `networkPolicy.ingressFrom` | `[]` = any pod | Narrow to your ingress controller's namespace |
| `networkPolicy.databaseTo` | `[]` = any destination on the port | Narrow to the database's CIDR or pods |
| `networkPolicy.databasePort` | `5432` | Only this port is open for egress, besides DNS |
| `networkPolicy.dns.ports` / `.to` | `[53]` / any | Narrow `to` to your DNS pods; OpenShift uses 5353 |
| `podLabels` | `{}` | The chart's own labels can't be overridden (they select NetworkPolicy targets) |

## NetworkPolicies

The chart ships two policies ([`networkpolicy.yaml`](../deploy/helm/licenseforge/templates/networkpolicy.yaml)):
- **Server**: ingress TCP 8080 only, from `ingressFrom`; egress to DNS and the database port only.
- **Migration Job**: no ingress; the same egress. It is a Helm hook, so it exists before the Job runs on the first install. `helm uninstall` leaves it behind (it selects only migration pods).

Policies are additive. To enable OIDC login, add a policy that allows egress from the server pods to the IdP on 443 instead of disabling the chart's:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: licenseforge-idp-egress}
spec:
  podSelector:
    matchLabels: {app.kubernetes.io/name: licenseforge, app.kubernetes.io/instance: <release>, app.kubernetes.io/component: server}
  policyTypes: [Egress]
  egress:
    - to: [{ipBlock: {cidr: <IdP CIDR>}}]   # or a selector for an in-cluster Keycloak
      ports: [{port: 443, protocol: TCP}]
```

## Backups

- **Database**: use your platform's encrypted backups with point-in-time recovery, run by a database admin, not by a LicenseForge login. Test restores. Licenses, keys, members and the audit log all live here.
- **Master keys**: back up the Secret value separately from the database, in a different system with different access. Without the keys, stored license keys and signing keys can't be decrypted (licenses already issued still verify; new ones can't be signed with the old keys). The two together expose them.
- **After a restore**: run `licenseforge migrate` with the same or a newer version. It refuses a database whose migrations were changed or are newer than the binary. The server itself doesn't check the schema version at start, so don't skip this step.
- **Signing key retirement isn't destruction**: a retired key's ciphertext remains in older backups and WAL until the master key it was encrypted with is rotated out of the keyring and those backups expire (ADR-0026).
- **Audit log**: kept in full until the retention job ships (*planned*). The `audit.checkpoint` entries exported to the SIEM carry each chain's verified head; compare them after a restore to see what the restored database lacks.
