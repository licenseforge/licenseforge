-- The reserved platform tenant (ADR-0027, ADR-0029): the row that holds the
-- platform audit chain (events without a tenant: logins, platform-admin
-- changes). It is not a real tenant. Its fixed ID is audit.PlatformTenant.
-- Only the platform pool writes its chain, and that pool sees it as a chain,
-- never as a tenant. The tenant FK and the canonical policies stay unchanged:
--   * app_tenant_id() never returns it, so the tenant pool (api login) and the
--     identity pool can't read or write any of its rows through any policy,
--     today's or a future table's, even when app.tenant_id is set to its ID.
--   * Tenant listings and slug resolution never see it: the identity and
--     platform policies on tenants exclude it, and the platform pool can't
--     change, delete or recreate it. Foreign-key checks from audit_events
--     bypass row-level security, so platform-chain entries still reference it.
-- Its slug, "platform", is taken for real tenants.
INSERT INTO "tenants" ("id", "slug", "name", "created_at", "updated_at")
  VALUES ('tnt_platformaaaaaaaaaaaaaaaaaa', 'platform', 'Platform (reserved)', now(), now());

CREATE OR REPLACE FUNCTION app_tenant_id() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(NULLIF(pg_catalog.current_setting('app.tenant_id', true), ''), 'tnt_platformaaaaaaaaaaaaaaaaaa') $$;

ALTER POLICY identity_read ON "tenants" USING ("id" <> 'tnt_platformaaaaaaaaaaaaaaaaaa');
DROP POLICY platform_all ON "tenants";
CREATE POLICY platform_real_tenants ON "tenants" TO licenseforge_platform
  USING ("id" <> 'tnt_platformaaaaaaaaaaaaaaaaaa') WITH CHECK ("id" <> 'tnt_platformaaaaaaaaaaaaaaaaaa');
