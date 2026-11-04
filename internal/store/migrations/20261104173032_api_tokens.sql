-- Create "api_tokens" table
CREATE TABLE "api_tokens" ("id" character varying(40) NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "name" character varying(200) NOT NULL, "role" character varying NOT NULL, "scope_all" boolean NOT NULL, "token_hash" bytea NOT NULL, "display" character varying(40) NOT NULL, "expires_at" timestamptz NOT NULL, "last_used_at" timestamptz NULL, "revoked_at" timestamptz NULL, "tenant_id" character varying(40) NOT NULL, "created_by" character varying(40) NULL, PRIMARY KEY ("id"), CONSTRAINT "api_tokens_tenants_api_tokens" FOREIGN KEY ("tenant_id") REFERENCES "tenants" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "api_tokens_users_api_tokens" FOREIGN KEY ("created_by") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "api_tokens_display" CHECK ((display)::text ~ '^lf_live_[a-z2-7]{8}…$'::text), CONSTRAINT "api_tokens_expiry" CHECK ((expires_at > created_at) AND (expires_at <= (created_at + '1 year'::interval))), CONSTRAINT "api_tokens_hash_len" CHECK (length(token_hash) = 32), CONSTRAINT "api_tokens_id_format" CHECK ((id)::text ~ '^tok_[a-z2-7]{26}$'::text), CONSTRAINT "api_tokens_no_empty" CHECK (btrim((name)::text) <> ''::text), CONSTRAINT "api_tokens_role_valid" CHECK ((role)::text = ANY (ARRAY['owner'::text, 'admin'::text, 'manager'::text, 'support'::text, 'viewer'::text, 'sdk'::text])));
-- Create index "apitoken_tenant_id" to table: "api_tokens"
CREATE INDEX "apitoken_tenant_id" ON "api_tokens" ("tenant_id");
-- Create index "apitoken_tenant_id_id" to table: "api_tokens"
CREATE UNIQUE INDEX "apitoken_tenant_id_id" ON "api_tokens" ("tenant_id", "id");
-- Create index "apitoken_tenant_id_id_scope_all" to table: "api_tokens"
CREATE UNIQUE INDEX "apitoken_tenant_id_id_scope_all" ON "api_tokens" ("tenant_id", "id", "scope_all");
-- Create index "apitoken_tenant_id_token_hash" to table: "api_tokens"
CREATE UNIQUE INDEX "apitoken_tenant_id_token_hash" ON "api_tokens" ("tenant_id", "token_hash");
-- Create "api_token_products" table
CREATE TABLE "api_token_products" ("id" character varying(40) NOT NULL, "tenant_id" character varying(40) NOT NULL, "product_id" character varying(40) NOT NULL, "scope_all" boolean NOT NULL DEFAULT false, "api_token_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "api_token_products_api_tokens_products" FOREIGN KEY ("api_token_id") REFERENCES "api_tokens" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "api_token_products_id_format" CHECK ((id)::text ~ '^tkp_[a-z2-7]{26}$'::text), CONSTRAINT "api_token_products_scoped" CHECK (NOT scope_all));
-- Create index "apitokenproduct_api_token_id_product_id" to table: "api_token_products"
CREATE UNIQUE INDEX "apitokenproduct_api_token_id_product_id" ON "api_token_products" ("api_token_id", "product_id");
-- Create index "apitokenproduct_tenant_id" to table: "api_token_products"
CREATE INDEX "apitokenproduct_tenant_id" ON "api_token_products" ("tenant_id");
