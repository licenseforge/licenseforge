-- Per-tenant MFA policy and session assurance (ADR-0038): privileges and
-- row-level security.
--
-- The login path records how each session was authenticated (immutable:
-- no UPDATE grant on these columns).
GRANT INSERT ("assurance", "amr", "acr", "acrs", "auth_time") ON "sessions" TO licenseforge_identity;
-- The tenant pool may change its own tenant's MFA policy, and nothing else
-- of the tenant row; internal/tenants allows it to owners only, audited.
GRANT UPDATE ("mfa_policy", "updated_at") ON "tenants" TO licenseforge_app;
CREATE POLICY tenant_update ON "tenants" FOR UPDATE TO licenseforge_app
  USING ("id" = app_tenant_id()) WITH CHECK ("id" = app_tenant_id());
