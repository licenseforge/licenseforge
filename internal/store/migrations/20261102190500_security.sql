-- Privileges and row-level security (ADR-0009). Hand-written: Atlas does not
-- manage grants or policies.
--
-- Roles (created once by the operator, see deploy/database-setup.sql):
--   owner (runs this)      owns the schema; migrations only, never serves traffic
--   licenseforge_app       group of the login serving tenant requests
--   licenseforge_platform  group of a separate login for platform-admin work
-- The tenant login is not a member of licenseforge_platform, so a SQL bug in a
-- tenant request can't reach other tenants (store.Open enforces this).
--
-- Tenant requests set app.tenant_id per transaction (store.DB.WithTenant).
-- Unset → no tenant rows, no writes (fail closed).
--
-- Every relation must follow this pattern exactly;
-- TestEveryRelationHasCanonicalRLS enforces it.

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO licenseforge_app, licenseforge_platform;

-- pg_catalog-qualified so a malicious search_path can't swap current_setting.
CREATE FUNCTION app_tenant_id() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(pg_catalog.current_setting('app.tenant_id', true), '') $$;

-- tenants: a tenant may read its own row; only the platform writes.
GRANT SELECT ON "tenants" TO licenseforge_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON "tenants" TO licenseforge_platform;
ALTER TABLE "tenants" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "tenants" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON "tenants" FOR SELECT TO licenseforge_app USING ("id" = app_tenant_id());
CREATE POLICY platform_all ON "tenants" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "tenants" TO CURRENT_USER USING (true) WITH CHECK (true);

-- products: tenant-scoped.
GRANT SELECT, INSERT, UPDATE, DELETE ON "products" TO licenseforge_app, licenseforge_platform;
ALTER TABLE "products" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "products" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "products" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "products" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "products" TO CURRENT_USER USING (true) WITH CHECK (true);
