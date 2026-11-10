-- lf:no-transaction
-- The daily metrics series (ADR-0046): activations by day, per tenant;
-- built concurrently so activations and refreshes continue while it builds.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "activation_tenant_id_first_seen_at" ON "activations" ("tenant_id", "first_seen_at");
