-- Create "tenants" table
CREATE TABLE "tenants" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "slug" character varying NOT NULL, "name" character varying NOT NULL, PRIMARY KEY ("id"));
-- Create index "tenants_slug_key" to table: "tenants"
CREATE UNIQUE INDEX "tenants_slug_key" ON "tenants" ("slug");
-- Create "products" table
CREATE TABLE "products" ("id" character varying NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "slug" character varying NOT NULL, "name" character varying NOT NULL, "tenant_id" character varying NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "products_tenants_products" FOREIGN KEY ("tenant_id") REFERENCES "tenants" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "product_tenant_id" to table: "products"
CREATE INDEX "product_tenant_id" ON "products" ("tenant_id");
-- Create index "product_tenant_id_slug" to table: "products"
CREATE UNIQUE INDEX "product_tenant_id_slug" ON "products" ("tenant_id", "slug");
