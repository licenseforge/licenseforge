-- lf:no-transaction
-- Summary counts by status and product-filtered license lists, per tenant;
-- built concurrently so license writes continue while it builds.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "license_tenant_id_product_id_status" ON "licenses" ("tenant_id", "product_id", "status");
