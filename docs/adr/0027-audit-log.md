# ADR-0027 Audit log

*Status: proposed · Date: 2026-11-02*

> [!WARNING]
> **Proposed (drafted overnight 2026-11-02). Needs maintainer acceptance before the implementation merges.**

## Context
[ADR-0021 Certification readiness](0021-certification-readiness.md) and [ADR-0024 HIPAA, NIST and FedRAMP readiness from day 1](0024-hipaa-nist-and-fedramp-readiness-from-day-1.md) require an append-only, hash-chained audit log: who, what, when, where, outcome, tenant and object (AU-2, AU-3, AU-8, AU-9), with configurable retention (AU-11) and SIEM export (AU-6). They don't say how the chain is scoped, serialized or hashed.

## Decision
- **One chain per tenant.** Every entry belongs to a tenant, including platform-admin actions on that tenant (impersonation, support access), so the tenant sees them. Tenants read only their own chain (canonical RLS, [ADR-0009 Multi-tenancy](0009-multi-tenancy.md)); a tenant export carries a chain it can verify on its own.
- **Entry**: `seq` (1, 2, … per tenant), `occurred_at` (UTC, microseconds, **from the database clock** so entries from several server instances agree with `seq` order, AU-8), actor (type `user` / `token` / `platform` / `system`, ID), action (e.g. `signing_key.promote`), object (type, ID), outcome (`success` / `failure` / `denied`), source IP and user agent (optional, AU-3), `details` (a JSON object, no secrets, no PHI), `prev_hash`, `hash`.
- **Client-supplied text** (user agent) is cleaned, not rejected: valid UTF-8, no NUL, truncated to the column. A hostile header must not be able to make an action, or the record of a denied attempt, fail.
- **Hash** = SHA-256 over `prev_hash` and every field including the row ID, each length-prefixed (like the keyring's binding encoding), so no field can be read two ways. The first entry's `prev_hash` is 32 zero bytes. Timestamps are hashed at microsecond precision, the precision PostgreSQL stores.
- **Atomic with the action**: a successful action's entry is written in the same transaction as the change it records. If either fails, both roll back, so no action happens unrecorded. **Failed and denied attempts** (AU-2, SOC 2 CC6/CC7) roll their action back, so their entries are written in a transaction of their own afterwards.
- **Serialized per tenant**: a transaction-scoped advisory lock on the tenant takes the chain head, so concurrent writers never fork the chain. A unique `(tenant_id, seq)` backs it up. Writers must use READ COMMITTED (the default; checked), where the head is read after the lock.
- **Append-only in the database**: the app roles get INSERT and SELECT only. No UPDATE, no DELETE.
- **Verification**: recompute the chain from seq 1 (after retention: from an exported anchor) and report the first broken `seq`. It detects changed, reordered and removed entries, including a removed first entry, and returns the head. **Removing the last entries (truncation) can't be detected from the table alone**: compare the head with an exported one.
- **Reading** the log is a privileged permission in the authz layer ([ADR-0019 Authorization model](0019-authorization-model.md)), not every member; exports of the log are themselves audited.
- **Retention**: per-tenant setting. Deletion removes only a prefix of the chain, and only through the retention job (a later PR, with its own role). Default: keep everything.
- **Tamper evidence against the database owner**: an attacker with owner access could rewrite the whole chain. **SIEM export of each entry's hash** (syslog / OTel, later PR) anchors the chain outside the database. Documented as the residual risk until then.

## Open questions (for acceptance)
- [ ] **Events without a tenant** (failed logins for unknown accounts, platform-admin login, platform settings): a separate platform chain (`tenant_id` NULL or a reserved platform tenant)? Proposed: a platform chain, same format.
- [ ] **GDPR erasure vs hash chain**: actor ID, IP and user agent are personal data, and the hash makes erasing them break the chain. Proposed: keep them, with retention as the erasure path, and document it as a legal-basis (legitimate interest / legal obligation) retention; alternative is a separate erasable table with a hashed commitment in the chain.
- [ ] **Database-enforced linking**: any code with INSERT can append a badly linked row, after which the chain fails to verify forever (no UPDATE/DELETE to repair). A BEFORE INSERT trigger enforcing `seq = head+1`, `prev_hash = head.hash` and `occurred_at = now()` would prevent it, but the project avoids triggers so far.
- [ ] **Tenant offboarding**: the tenant FK blocks deleting a tenant with audit entries until export + retention exist.

## Consequences
- Writes that are audited serialize per tenant. That's fine for admin actions; high-volume events (every activation or validation) stay in metrics and logs, not the audit chain, unless a tenant opts in later.
- An insert failure fails the action (AU-5, fail closed); the failure is visible in metrics.
