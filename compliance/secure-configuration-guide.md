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

`LICENSEFORGE_BOOTSTRAP_ADMIN` (ADR-0003, ADR-0031): `issuer|subject` (recommended) or a verified email. The matching user becomes the first platform admin at login, only while there is none, recorded on the platform audit chain. Read at start. Unset after the first admin exists if you like: it never grants again while any admin exists.

## Database logins

Create them with [`deploy/database-setup.sql`](../deploy/database-setup.sql) as a database admin (ADR-0009, ADR-0029). There are three group roles and four logins, and none is shared. Replace the script's placeholder passwords (`change-me-*`) before running it:

| Login | Group | Used by | Can |
|---|---|---|---|
| `licenseforge_owner` | – | `licenseforge migrate` (the Helm pre-install/pre-upgrade Job) | Owns the schema. Its `migrator_all` policies show it every row, and as owner it can change or drop any policy |
| `licenseforge_api` | `licenseforge_app` | Every tenant request | Only rows of the tenant set for the transaction |
| `licenseforge_admin` | `licenseforge_platform` | Platform-admin work | All tenants, through explicit grants |
| `licenseforge_login` | `licenseforge_identity` | Login, sessions, invitation acceptance | Identity tables only; no licensing data |

**Why the server must never hold the owner login.** Tenant isolation is enforced by forced row-level security, and RLS is a backstop only if the serving process can't turn it off. The owner sees every row, can alter or drop policies and switch RLS off, and can rewrite the audit chain. A serving pod with the owner login would turn any bug or compromise in the internet-facing process into full access to every tenant. So:

- the server exits if `LICENSEFORGE_OWNER_DATABASE_URL` is set, and the chart gives the owner URL only to the migration Job, from its own Secret;
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
- Rate-limit and size-limit requests at the ingress: the server has timeouts but no rate limiting.
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
- **Enforce MFA in the IdP**, phishing-resistant where required (passkeys, PIV/CAC). Per-tenant enforcement through `acr`/`amr` is *planned* (Roadmap v0.1).
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
- **Audit log**: kept in full until the retention job ships (*planned*). Export the chain head regularly to detect truncation once SIEM export exists (*planned*).
