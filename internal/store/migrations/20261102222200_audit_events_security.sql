-- Audit log: privileges and row-level security (ADR-0009, ADR-0027).
-- Append-only: no UPDATE, no DELETE for the app roles. Retention (deleting a
-- prefix of a chain) gets its own role later.
GRANT SELECT, INSERT ON "audit_events" TO licenseforge_app, licenseforge_platform;

ALTER TABLE "audit_events" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "audit_events" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "audit_events" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "audit_events" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "audit_events" TO CURRENT_USER USING (true) WITH CHECK (true);
