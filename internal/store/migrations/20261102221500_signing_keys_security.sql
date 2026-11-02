-- Signing keys: privileges and row-level security (ADR-0009, ADR-0026).
-- Same pattern as the licenses security migration.

-- Keys are never deleted; alg, public key and owner never change. Lifecycle
-- rules that need the old value (pending -> active -> retired, never back; a
-- destroyed private key is never set again) are enforced by the signing service
-- and recorded in the audit log.
GRANT SELECT, INSERT ON "signing_keys" TO licenseforge_app, licenseforge_platform;
GRANT UPDATE ("status", "private_key_ciphertext", "activated_at", "retired_at", "updated_at")
  ON "signing_keys" TO licenseforge_app, licenseforge_platform;

ALTER TABLE "signing_keys" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "signing_keys" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "signing_keys" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "signing_keys" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "signing_keys" TO CURRENT_USER USING (true) WITH CHECK (true);
