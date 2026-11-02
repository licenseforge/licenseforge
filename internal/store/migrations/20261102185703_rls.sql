-- Row-level security (ADR-0009). Hand-written; Atlas does not manage policies.
--
-- The application sets, per transaction (store.WithTenant / store.WithPlatform):
--   app.tenant_id  the tenant whose rows are visible
--   app.scope      'platform' for platform-admin operations (all tenants)
-- With neither set, no tenant rows are visible and no writes pass (fail closed).
-- FORCE applies the policies to the table owner too; the application role
-- must not be a superuser or have BYPASSRLS (store.Open refuses those).
--
-- Every table with a tenant_id column needs the same three statements;
-- TestEveryTenantTableHasRLS enforces it.

CREATE FUNCTION app_tenant_id() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '') $$;

CREATE FUNCTION app_is_platform() RETURNS boolean LANGUAGE sql STABLE
  AS $$ SELECT COALESCE(current_setting('app.scope', true), '') = 'platform' $$;

ALTER TABLE "tenants" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "tenants" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "tenants"
  USING (app_is_platform() OR "id" = app_tenant_id())
  WITH CHECK (app_is_platform() OR "id" = app_tenant_id());

ALTER TABLE "products" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "products" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "products"
  USING (app_is_platform() OR "tenant_id" = app_tenant_id())
  WITH CHECK (app_is_platform() OR "tenant_id" = app_tenant_id());
