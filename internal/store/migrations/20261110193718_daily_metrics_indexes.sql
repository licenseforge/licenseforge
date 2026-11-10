-- Create index "activation_tenant_id_deactivated_at" to table: "activations"
CREATE INDEX "activation_tenant_id_deactivated_at" ON "activations" ("tenant_id", "deactivated_at") WHERE (deactivated_at IS NOT NULL);
-- Create index "activation_tenant_id_first_seen_at" to table: "activations"
CREATE INDEX "activation_tenant_id_first_seen_at" ON "activations" ("tenant_id", "first_seen_at");
