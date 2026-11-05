-- Modify "tenants" table
ALTER TABLE "tenants" ADD CONSTRAINT "tenants_audit_retention" CHECK ((audit_retention_days IS NULL) OR ((audit_retention_days >= 365) AND (audit_retention_days <= 36500))), ADD COLUMN "audit_retention_days" bigint NULL;
