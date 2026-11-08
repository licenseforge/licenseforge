-- lf:no-transaction
-- License lists, newest first with the (created_at, id) keyset cursor, per
-- tenant; built concurrently so license writes continue while it builds.
CREATE INDEX CONCURRENTLY "license_tenant_id_created_at_id" ON "licenses" ("tenant_id", "created_at", "id");
