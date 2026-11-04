-- Platform admins: privileges and row-level security (ADR-0029, ADR-0031).
-- Global table: the platform pool manages it, the login path reads it,
-- tenants never see it.
GRANT SELECT, INSERT, DELETE ON "platform_admins" TO licenseforge_platform;
GRANT SELECT ON "platform_admins" TO licenseforge_identity;
ALTER TABLE "platform_admins" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "platform_admins" FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_all ON "platform_admins" TO licenseforge_platform USING (true) WITH CHECK (true);
-- A grant is a bootstrap only while there is no admin; otherwise an existing
-- admin grants it.
CREATE POLICY grant_shape ON "platform_admins" AS RESTRICTIVE FOR INSERT TO licenseforge_platform
  WITH CHECK (("bootstrap" AND NOT EXISTS (SELECT 1 FROM "platform_admins" p))
    OR (NOT "bootstrap" AND EXISTS (SELECT 1 FROM "platform_admins" p WHERE p."user_id" = "platform_admins"."granted_by")));
-- The last admin can't be removed (an empty table would reopen bootstrap).
-- Backstop: concurrent removals are serialized by DB.RemovePlatformAdmin.
CREATE POLICY keep_one ON "platform_admins" AS RESTRICTIVE FOR DELETE TO licenseforge_platform
  USING (EXISTS (SELECT 1 FROM "platform_admins" p WHERE p."id" <> "platform_admins"."id"));
CREATE POLICY identity_read ON "platform_admins" FOR SELECT TO licenseforge_identity USING (true);
CREATE POLICY migrator_all ON "platform_admins" TO CURRENT_USER USING (true) WITH CHECK (true);
