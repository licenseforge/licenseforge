-- Per-tenant MFA policy and session assurance (ADR-0038): privileges and
-- row-level security.
--
-- The login path records how each session was authenticated (immutable:
-- no UPDATE grant on these columns).
GRANT INSERT ("assurance", "amr", "acr", "acrs", "auth_time") ON "sessions" TO licenseforge_identity;
-- The tenant pool may also change its own tenant's MFA policy (the own-row
-- UPDATE policy tenant_settings comes from the audit retention migration);
-- internal/tenants allows it to owners only, audited.
GRANT UPDATE ("mfa_policy") ON "tenants" TO licenseforge_app;
