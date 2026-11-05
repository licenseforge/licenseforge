-- Audit retention settings (ADR-0036): a tenant's owner sets its own chain's
-- retention (the tenant pool may change that column of its own row, nothing
-- else); the retention login reads it for every tenant. The 365-day minimum
-- is the column's CHECK; the delete floor is enforced on audit_events.
GRANT UPDATE ("audit_retention_days", "updated_at") ON "tenants" TO licenseforge_app;
CREATE POLICY tenant_settings ON "tenants" FOR UPDATE TO licenseforge_app
  USING ("id" = app_tenant_id()) WITH CHECK ("id" = app_tenant_id());
GRANT SELECT ("id", "audit_retention_days") ON "tenants" TO licenseforge_retention;
CREATE POLICY retention_read ON "tenants" FOR SELECT TO licenseforge_retention USING (true);
