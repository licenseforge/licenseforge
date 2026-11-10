-- Modify "licenses" table
ALTER TABLE "licenses" ADD CONSTRAINT "licenses_updates_after_issue" CHECK ((updates_until IS NULL) OR (updates_until > issued_at));
-- Modify "plans" table
ALTER TABLE "plans" ADD CONSTRAINT "plans_updates_months" CHECK ((updates_months IS NULL) OR ((updates_months >= 1) AND (updates_months <= 1200))), ADD COLUMN "updates_months" bigint NULL;
-- Maintenance term (ADR-0045): editable like the plan's other terms.
GRANT UPDATE ("updates_months") ON "plans" TO licenseforge_app, licenseforge_platform;
