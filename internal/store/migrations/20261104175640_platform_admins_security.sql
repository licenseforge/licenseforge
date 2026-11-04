-- Platform admins: privileges and row-level security (ADR-0029). Global table:
-- the platform pool manages it, the login path reads it, tenants never see it.
GRANT SELECT, INSERT, DELETE ON "platform_admins" TO licenseforge_platform;
GRANT SELECT ON "platform_admins" TO licenseforge_identity;
ALTER TABLE "platform_admins" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "platform_admins" FORCE ROW LEVEL SECURITY;
CREATE POLICY platform_all ON "platform_admins" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY identity_read ON "platform_admins" FOR SELECT TO licenseforge_identity USING (true);
CREATE POLICY migrator_all ON "platform_admins" TO CURRENT_USER USING (true) WITH CHECK (true);
