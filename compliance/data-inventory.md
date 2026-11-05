# Data inventory

What LicenseForge stores, where, and how it is protected. It covers the GDPR records of processing (ADR-0021), the HIPAA PHI-free claim (ADR-0024) and NIST PT/SI-12. Schema source: [`internal/store/schema`](../internal/store/schema/user.go) and the [migrations](../internal/store/migrations/20261102191308_init.sql) (`*_security.sql` holds grants and policies). Status as of `main`, 2026-11-04.

**PHI-free by design.** No column needs health data. Free-text fields (customer `name`, `external_refs`, token names, audit `details`) must not carry PHI or secrets. Audit `details` must not carry emails either (ADR-0029).

## Protection that applies everywhere

- **Tenant isolation**: every tenant table has forced row-level security. The tenant login sees only rows of the tenant set for the transaction (ADR-0009), and composite `*_same_tenant` keys stop cross-tenant references.
- **Logins**: four database logins with separate grants ([Secure Configuration Guide](secure-configuration-guide.md#database-logins)). The login path (`licenseforge_login`) can't read licensing tables.
- **At rest**: secrets are encrypted in the application (AES-256-GCM, keyring `LICENSEFORGE_MASTER_KEYS`, ADR-0025) or stored only as hashes. Disk and backup encryption are the operator's.
- **Logs**: the server logs JSON to stdout. ent marks secret columns `Sensitive`, so they never appear in printed rows. Keyring errors never contain key material.

## Global tables (no tenant)

| Table.column | Data | Personal or sensitive | Protection | Retention and erasure |
|---|---|---|---|---|
| `users.issuer`, `users.subject` | IdP identity of a person | Personal (pseudonymous ID) | Login path: read and create. Platform: read and update. Tenants: none | Kept until erased. `licenseforge user erase` (ADR-0029) is **planned**: today erasure is a manual owner-login operation |
| `users.email`, `users.name` | From verified ID token claims (email only if `email_verified`) | Personal | Tenants see `id`, `email`, `name` of **their own members only** (column grant + policy) | As above |
| `users.email_verified`, `users.last_login_at`, `users.disabled_at` | Verified-email flag, timestamps | Personal (activity) | Not visible to tenants | As above |
| `sessions.token_hash` | SHA-256 of the 256-bit session cookie | Secret (hash only) | Login path and platform only; tenants never see sessions | Deleted on logout, on a new login with that cookie, and when the user is suspended. Expired rows are not swept yet (they no longer authenticate) |
| `sessions.user_id`, `created_at`, `last_seen_at`, `expires_at` | Session activity | Personal (activity) | As above | As above; at most 1 day per session |
| `platform_admins.user_id`, `granted_by` | Who is a platform admin | Personal (role) | Platform: manage. Login path: read. Tenants: none | Removed by `RemovePlatformAdmin`; the last admin can't be removed |

## Tenant tables (forced RLS)

| Table.column | Data | Personal or sensitive | Protection | Retention and erasure |
|---|---|---|---|---|
| `tenants.slug`, `tenants.name` | The vendor | Business | A tenant reads only its own row | Tenant purge (`licenseforge tenant purge`, ADR-0009) is **planned** |
| `customers.name`, `customers.email`, `customers.external_refs` | The vendor's customer; order/CRM/ERP IDs | Personal if the customer is a person | RLS; serving logins can't DELETE (archived instead) | Kept with the tenant; erasure with tenant purge (planned) |
| `licenses.key_ciphertext` | License key | Secret | AES-256-GCM, bound to purpose, tenant and row (ADR-0025); a CHECK refuses plaintext | Licenses are never deleted (revoked instead) |
| `licenses.key_lookup` | HMAC-SHA256 of the normalised key (keyed by the keyring) | Secret-derived | Unique per tenant; useless without the master key | As above |
| `licenses.key_hint` | Last 6 characters of the key (of 26) | Low | Shown in lists | As above |
| `licenses.customer_id` | Which customer holds the license | Personal if the customer is a person | RLS; same-tenant key | As above |
| `licenses.entitlements` | Features and limits sold | Business | RLS; CHECK-validated | As above |
| `licenses.external_refs` | Order/CRM IDs | Business | RLS | As above |
| `activations.fingerprint` | Machine or cluster ID, hashed by the SDK on the machine: `sha256:` over tenant, product and raw ID (ADR-0017) | Pseudonymous device ID | Hash only; the server never receives the raw ID; a CHECK enforces the hash format | Deactivated, never deleted (rehost history) |
| `activations.hostname` | Optional hostname reported by the SDK | Personal if it names a person | RLS | As above. The per-tenant setting to turn hostname capture off (ADR-0021) is **planned**. IP addresses are not stored on activations |
| `activations.app_version`, `sdk_version`, `first_seen_at`, `last_seen_at` | Usage metadata | Low | RLS | As above |
| `invitations.email`, `issuer`, `invited_by`, `accepted_by`, `expires_at`, `accepted_at`, `revoked_at` | Invitee and inviter, and when it was sent, accepted or revoked | Personal | Tenant: read, create, revoke. Login path: read, accept | Kept after acceptance (the membership references it); unaccepted ones are deleted by `user erase` (planned) |
| `invitations.token_hash` | SHA-256 of the invite link's token | Secret (hash only) | As above; single use; 32-byte length CHECK | As above |
| `memberships.user_id`, `role`, `scope_all`; `membership_products` | Who belongs to the tenant, with which rights | Personal (role) | Created only by accepting an invitation (database-enforced); tenant admins change or remove | Deleted on member removal |
| `api_tokens.token_hash` | SHA-256 of the 256-bit token | Secret (hash only) | The login path has no access; the hash is unique per tenant | Kept after revocation or expiry (audit trail) |
| `api_tokens.name`, `display`, `created_by`, `last_used_at` | Label, prefix (40 of 256 bits), creator, last use | Low / personal (creator) | RLS | `created_by` is nulled on user erasure (planned) |
| `signing_keys.private_key_ciphertext` | Ed25519 seed | Secret | AES-256-GCM, bound to tenant and kid (ADR-0026) | Set to NULL on retirement; it survives in WAL and backups until the master key is rotated out |
| `signing_keys.public_key` | Ed25519 public key | Public | – | Kept (old files must verify) |
| `audit_events.actor_id`, `object_id`, `source_ip`, `user_agent` | Who acted, on what (`object_id` can be a user ID), from where | Personal | Append-only (INSERT and SELECT only), hash-chained, RLS per tenant | Kept; the per-tenant retention job (AU-11) is **planned**. Erasure requests are refused for audit entries and met by retention (ADR-0027) |
| `audit_events.action`, `object_type`, `outcome`, `details` | What happened | Low; `details` has no secrets, PHI or emails | As above | As above |
| `products`, `features`, `plans`, `plan_features` | Catalog | Business | RLS; archived, never deleted | With the tenant |

## Outside the database

| Where | Data | Protection |
|---|---|---|
| Kubernetes Secrets | Database URLs (five logins), `LICENSEFORGE_MASTER_KEYS`, OIDC client secret | Operator's secret manager ([Secure Configuration Guide](secure-configuration-guide.md#secrets-and-the-keyring)) |
| Browser cookie `__Host-lf_session` | Session secret | `HttpOnly; Secure; SameSite=Lax`, `__Host-` prefix, 12 h |
| Browser cookie `__Host-lf_login` | OIDC state, nonce, PKCE verifier | Same flags, 10 minutes, single use |
| License files (`lf1`) | Customer **ID** only by default, product, entitlements, expiry | Signed with Ed25519 (no personal data unless the vendor adds it) |
| Server logs (stdout) | Errors, login failure reasons, token IDs | No secrets; the operator's log retention applies |
