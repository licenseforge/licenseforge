-- lf:no-transaction
-- The daily metrics series (ADR-0046): deactivations by day, per tenant.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "activation_tenant_id_deactivated_at" ON "activations" ("tenant_id", "deactivated_at") WHERE (deactivated_at IS NOT NULL);
