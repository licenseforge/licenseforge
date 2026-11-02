-- Create index "product_tenant_id_id" to table: "products"
CREATE UNIQUE INDEX "product_tenant_id_id" ON "products" ("tenant_id", "id");
-- Create "features" table
CREATE TABLE "features" ("id" character varying(40) NOT NULL, "tenant_id" character varying(40) NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "key" character varying(63) NOT NULL, "name" character varying(200) NOT NULL, "description" character varying(2000) NULL, "type" character varying NOT NULL, "unit" character varying(40) NULL, "archived_at" timestamptz NULL, "product_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "features_products_features" FOREIGN KEY ("product_id") REFERENCES "products" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "features_id_format" CHECK ((id)::text ~ '^ftr_[a-z2-7]{26}$'::text), CONSTRAINT "features_key_format" CHECK ((key)::text ~ '^[a-z][a-z0-9]*(_[a-z0-9]+)*$'::text), CONSTRAINT "features_name_set" CHECK ((name)::text <> ''::text), CONSTRAINT "features_type_valid" CHECK ((type)::text = ANY ((ARRAY['boolean'::character varying, 'limit'::character varying])::text[])));
-- Create index "feature_product_id_id" to table: "features"
CREATE UNIQUE INDEX "feature_product_id_id" ON "features" ("product_id", "id");
-- Create index "feature_product_id_key" to table: "features"
CREATE UNIQUE INDEX "feature_product_id_key" ON "features" ("product_id", "key");
-- Create index "feature_tenant_id" to table: "features"
CREATE INDEX "feature_tenant_id" ON "features" ("tenant_id");
-- Create index "feature_tenant_id_id" to table: "features"
CREATE UNIQUE INDEX "feature_tenant_id_id" ON "features" ("tenant_id", "id");
-- Create "plans" table
CREATE TABLE "plans" ("id" character varying(40) NOT NULL, "tenant_id" character varying(40) NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "slug" character varying(63) NOT NULL, "name" character varying(200) NOT NULL, "duration_seconds" bigint NULL, "expiry_basis" character varying NOT NULL DEFAULT 'from_issue', "max_activations" bigint NULL, "max_rehosts" bigint NULL, "offline_allowed" boolean NOT NULL DEFAULT false, "lease_seconds" bigint NOT NULL DEFAULT 604800, "max_offline_seconds" bigint NULL, "grace_seconds" bigint NOT NULL DEFAULT 0, "archived_at" timestamptz NULL, "product_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "plans_products_plans" FOREIGN KEY ("product_id") REFERENCES "products" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "plans_activations_pos" CHECK ((max_activations IS NULL) OR (max_activations > 0)), CONSTRAINT "plans_duration_range" CHECK ((duration_seconds IS NULL) OR ((duration_seconds > 0) AND (duration_seconds <= '3153600000'::bigint))), CONSTRAINT "plans_expiry_valid" CHECK ((expiry_basis)::text = ANY ((ARRAY['from_issue'::character varying, 'from_first_activation'::character varying])::text[])), CONSTRAINT "plans_grace_range" CHECK ((grace_seconds >= 0) AND (grace_seconds <= '3153600000'::bigint)), CONSTRAINT "plans_id_format" CHECK ((id)::text ~ '^pln_[a-z2-7]{26}$'::text), CONSTRAINT "plans_lease_range" CHECK ((lease_seconds > 0) AND (lease_seconds <= '3153600000'::bigint)), CONSTRAINT "plans_max_offline_rng" CHECK ((max_offline_seconds IS NULL) OR ((max_offline_seconds >= 0) AND (max_offline_seconds <= '3153600000'::bigint))), CONSTRAINT "plans_name_set" CHECK ((name)::text <> ''::text), CONSTRAINT "plans_rehosts_nonneg" CHECK ((max_rehosts IS NULL) OR (max_rehosts >= 0)), CONSTRAINT "plans_slug_format" CHECK ((slug)::text ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'::text));
-- Create index "plan_product_id_id" to table: "plans"
CREATE UNIQUE INDEX "plan_product_id_id" ON "plans" ("product_id", "id");
-- Create index "plan_product_id_slug" to table: "plans"
CREATE UNIQUE INDEX "plan_product_id_slug" ON "plans" ("product_id", "slug");
-- Create index "plan_tenant_id" to table: "plans"
CREATE INDEX "plan_tenant_id" ON "plans" ("tenant_id");
-- Create index "plan_tenant_id_id" to table: "plans"
CREATE UNIQUE INDEX "plan_tenant_id_id" ON "plans" ("tenant_id", "id");
-- Create "plan_features" table
CREATE TABLE "plan_features" ("id" character varying(40) NOT NULL, "tenant_id" character varying(40) NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "product_id" character varying(40) NOT NULL, "limit_value" bigint NULL, "feature_id" character varying(40) NOT NULL, "plan_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "plan_features_features_plan_features" FOREIGN KEY ("feature_id") REFERENCES "features" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "plan_features_plans_plan_features" FOREIGN KEY ("plan_id") REFERENCES "plans" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "plan_features_id_format" CHECK ((id)::text ~ '^plf_[a-z2-7]{26}$'::text), CONSTRAINT "plan_features_limit_range" CHECK ((limit_value IS NULL) OR ((limit_value >= '-1'::integer) AND (limit_value <= '9007199254740991'::bigint))));
-- Create index "planfeature_plan_id_feature_id" to table: "plan_features"
CREATE UNIQUE INDEX "planfeature_plan_id_feature_id" ON "plan_features" ("plan_id", "feature_id");
-- Create index "planfeature_tenant_id" to table: "plan_features"
CREATE INDEX "planfeature_tenant_id" ON "plan_features" ("tenant_id");
