-- Upgrade guard (ADR-0036): the next migration grants to this role, which
-- only a database admin can create; stop before anything is applied.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'licenseforge_retention') THEN
    RAISE EXCEPTION 'create role licenseforge_retention NOLOGIN before migrating (as a database admin; see deploy/database-setup.sql, ADR-0036)';
  END IF;
END $$;

-- Create "audit_anchors" table
CREATE TABLE "audit_anchors" ("id" character varying(40) NOT NULL, "seq" bigint NOT NULL, "hash" bytea NOT NULL, "cut_at" timestamptz NOT NULL, "tenant_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "audit_anchors_tenants_audit_anchors" FOREIGN KEY ("tenant_id") REFERENCES "tenants" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "audit_anchors_hash_len" CHECK (length(hash) = 32), CONSTRAINT "audit_anchors_id_format" CHECK ((id)::text ~ '^anc_[a-z2-7]{26}$'::text), CONSTRAINT "audit_anchors_seq" CHECK (seq > 0));
-- Create index "auditanchor_tenant_id_seq" to table: "audit_anchors"
CREATE UNIQUE INDEX "auditanchor_tenant_id_seq" ON "audit_anchors" ("tenant_id", "seq");
