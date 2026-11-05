-- Create index "activation_history" to table: "activations"
CREATE INDEX "activation_history" ON "activations" ("license_id", "fingerprint");
-- Modify "idempotency_keys" table: licenses are credentials too (activation API)
ALTER TABLE "idempotency_keys" DROP CONSTRAINT "idempotency_keys_credential", ADD CONSTRAINT "idempotency_keys_credential" CHECK ((credential)::text ~ '^(tok|usr|lic)_[a-z2-7]{26}$'::text);
