-- Create "tenants" table
CREATE TABLE "tenants" ("id" character varying(40) NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "slug" character varying(63) NOT NULL, "name" character varying(200) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "tenants_id_format" CHECK ((id)::text ~ '^tnt_[a-z2-7]{26}$'::text), CONSTRAINT "tenants_slug_format" CHECK ((slug)::text ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'::text));
-- Create index "tenants_slug_key" to table: "tenants"
CREATE UNIQUE INDEX "tenants_slug_key" ON "tenants" ("slug");
-- Create "products" table
CREATE TABLE "products" ("id" character varying(40) NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "slug" character varying(63) NOT NULL, "name" character varying(200) NOT NULL, "tenant_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "products_tenants_products" FOREIGN KEY ("tenant_id") REFERENCES "tenants" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "products_id_format" CHECK ((id)::text ~ '^prd_[a-z2-7]{26}$'::text), CONSTRAINT "products_slug_format" CHECK ((slug)::text ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'::text));
-- Create index "product_tenant_id" to table: "products"
CREATE INDEX "product_tenant_id" ON "products" ("tenant_id");
-- Create index "product_tenant_id_slug" to table: "products"
CREATE UNIQUE INDEX "product_tenant_id_slug" ON "products" ("tenant_id", "slug");
