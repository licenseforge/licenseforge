-- Signing keys: privileges and row-level security (ADR-0009, ADR-0026).
-- Same pattern as the licenses security migration.

-- Keys are never deleted; alg, public key and owner never change. Lifecycle
-- rules that need the old value (pending -> active -> retired, never back; a
-- destroyed private key is never set again) are enforced by the signing service
-- and recorded in the audit log.
-- Key operations are tenant-scoped (WithTenant). The platform pool may only
-- read keys and rewrap private keys after a master-key rotation (ADR-0025).
GRANT SELECT, INSERT ON "signing_keys" TO licenseforge_app;
GRANT UPDATE ("status", "private_key_ciphertext", "activated_at", "retired_at", "updated_at")
  ON "signing_keys" TO licenseforge_app;
GRANT SELECT ON "signing_keys" TO licenseforge_platform;
GRANT UPDATE ("private_key_ciphertext", "updated_at") ON "signing_keys" TO licenseforge_platform;

ALTER TABLE "signing_keys" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "signing_keys" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "signing_keys" TO licenseforge_app
  USING ("tenant_id" = app_tenant_id()) WITH CHECK ("tenant_id" = app_tenant_id());
CREATE POLICY platform_all ON "signing_keys" TO licenseforge_platform USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON "signing_keys" TO CURRENT_USER USING (true) WITH CHECK (true);
