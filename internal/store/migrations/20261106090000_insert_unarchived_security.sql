-- One-way states start unset (archive_once and the license transitions only
-- set them later, and audit it): the serving pools can't insert a row that
-- is already archived, suspended or revoked, which would skip the service,
-- its rights checks and its audit entry (ADR-0015, ADR-0013, ADR-0027).
-- The migrator stays exempt (migrator_all). No triggers (ADR-0009).
CREATE POLICY insert_unarchived ON "products" AS RESTRICTIVE FOR INSERT TO licenseforge_app, licenseforge_platform
  WITH CHECK ("archived_at" IS NULL);
CREATE POLICY insert_unarchived ON "features" AS RESTRICTIVE FOR INSERT TO licenseforge_app, licenseforge_platform
  WITH CHECK ("archived_at" IS NULL);
CREATE POLICY insert_unarchived ON "plans" AS RESTRICTIVE FOR INSERT TO licenseforge_app, licenseforge_platform
  WITH CHECK ("archived_at" IS NULL);
CREATE POLICY insert_unarchived ON "customers" AS RESTRICTIVE FOR INSERT TO licenseforge_app, licenseforge_platform
  WITH CHECK ("archived_at" IS NULL);
-- A license starts active (licenses_suspended_at / licenses_revoked_at tie
-- the status to these columns, so this also means status = 'active').
CREATE POLICY insert_active ON "licenses" AS RESTRICTIVE FOR INSERT TO licenseforge_app, licenseforge_platform
  WITH CHECK ("suspended_at" IS NULL AND "revoked_at" IS NULL);
