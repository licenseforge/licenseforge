-- Create "users" table
CREATE TABLE "users" ("id" character varying(40) NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "issuer" character varying(500) NOT NULL, "subject" character varying(255) NOT NULL, "email" character varying(320) NULL, "email_verified" boolean NOT NULL DEFAULT false, "name" character varying(200) NULL, "last_login_at" timestamptz NULL, "disabled_at" timestamptz NULL, PRIMARY KEY ("id"), CONSTRAINT "users_id_format" CHECK ((id)::text ~ '^usr_[a-z2-7]{26}$'::text), CONSTRAINT "users_no_empty" CHECK ((btrim((issuer)::text) <> ''::text) AND (btrim((subject)::text) <> ''::text) AND ((email IS NULL) OR (btrim((email)::text) <> ''::text)) AND ((name IS NULL) OR (btrim((name)::text) <> ''::text))), CONSTRAINT "users_verified_email" CHECK ((email IS NOT NULL) OR (NOT email_verified)));
-- Create index "user_issuer_subject" to table: "users"
CREATE UNIQUE INDEX "user_issuer_subject" ON "users" ("issuer", "subject");
-- Create "invitations" table
CREATE TABLE "invitations" ("id" character varying(40) NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "email" character varying(320) NOT NULL, "role" character varying NOT NULL, "scope_all" boolean NOT NULL, "issuer" character varying(500) NULL, "token_hash" bytea NOT NULL, "expires_at" timestamptz NOT NULL, "accepted_at" timestamptz NULL, "revoked_at" timestamptz NULL, "tenant_id" character varying(40) NOT NULL, "invited_by" character varying(40) NULL, "accepted_by" character varying(40) NULL, PRIMARY KEY ("id"), CONSTRAINT "invitations_tenants_invitations" FOREIGN KEY ("tenant_id") REFERENCES "tenants" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "invitations_users_invitations_accepted" FOREIGN KEY ("accepted_by") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "invitations_users_invitations_sent" FOREIGN KEY ("invited_by") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, CONSTRAINT "invitations_accepted" CHECK ((accepted_at IS NULL) = (accepted_by IS NULL)), CONSTRAINT "invitations_expiry" CHECK (expires_at > created_at), CONSTRAINT "invitations_id_format" CHECK ((id)::text ~ '^inv_[a-z2-7]{26}$'::text), CONSTRAINT "invitations_no_empty" CHECK ((btrim((email)::text) <> ''::text) AND ((issuer IS NULL) OR (btrim((issuer)::text) <> ''::text))), CONSTRAINT "invitations_one_outcome" CHECK ((accepted_at IS NULL) OR (revoked_at IS NULL)), CONSTRAINT "invitations_role_valid" CHECK ((role)::text = ANY (ARRAY['owner'::text, 'admin'::text, 'manager'::text, 'support'::text, 'viewer'::text])), CONSTRAINT "invitations_token_len" CHECK (length(token_hash) = 32));
-- Create index "invitation_tenant_id" to table: "invitations"
CREATE INDEX "invitation_tenant_id" ON "invitations" ("tenant_id");
-- Create index "invitation_tenant_id_id" to table: "invitations"
CREATE UNIQUE INDEX "invitation_tenant_id_id" ON "invitations" ("tenant_id", "id");
-- Create index "invitation_tenant_id_id_scope_all" to table: "invitations"
CREATE UNIQUE INDEX "invitation_tenant_id_id_scope_all" ON "invitations" ("tenant_id", "id", "scope_all");
-- Create index "invitation_token_hash" to table: "invitations"
CREATE UNIQUE INDEX "invitation_token_hash" ON "invitations" ("token_hash");
-- Create "invitation_products" table
CREATE TABLE "invitation_products" ("id" character varying(40) NOT NULL, "tenant_id" character varying(40) NOT NULL, "product_id" character varying(40) NOT NULL, "scope_all" boolean NOT NULL DEFAULT false, "invitation_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "invitation_products_invitations_products" FOREIGN KEY ("invitation_id") REFERENCES "invitations" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "invitation_products_id_format" CHECK ((id)::text ~ '^ivp_[a-z2-7]{26}$'::text), CONSTRAINT "invitation_products_scoped" CHECK (NOT scope_all));
-- Create index "invitationproduct_invitation_id_product_id" to table: "invitation_products"
CREATE UNIQUE INDEX "invitationproduct_invitation_id_product_id" ON "invitation_products" ("invitation_id", "product_id");
-- Create index "invitationproduct_tenant_id" to table: "invitation_products"
CREATE INDEX "invitationproduct_tenant_id" ON "invitation_products" ("tenant_id");
-- Create "memberships" table
CREATE TABLE "memberships" ("id" character varying(40) NOT NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "role" character varying NOT NULL, "scope_all" boolean NOT NULL, "invitation_id" character varying(40) NOT NULL, "tenant_id" character varying(40) NOT NULL, "user_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "memberships_tenants_memberships" FOREIGN KEY ("tenant_id") REFERENCES "tenants" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "memberships_users_memberships" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "memberships_id_format" CHECK ((id)::text ~ '^mem_[a-z2-7]{26}$'::text), CONSTRAINT "memberships_role_valid" CHECK ((role)::text = ANY (ARRAY['owner'::text, 'admin'::text, 'manager'::text, 'support'::text, 'viewer'::text])));
-- Create index "membership_invitation_id" to table: "memberships"
CREATE UNIQUE INDEX "membership_invitation_id" ON "memberships" ("invitation_id");
-- Create index "membership_tenant_id" to table: "memberships"
CREATE INDEX "membership_tenant_id" ON "memberships" ("tenant_id");
-- Create index "membership_tenant_id_id" to table: "memberships"
CREATE UNIQUE INDEX "membership_tenant_id_id" ON "memberships" ("tenant_id", "id");
-- Create index "membership_tenant_id_id_scope_all" to table: "memberships"
CREATE UNIQUE INDEX "membership_tenant_id_id_scope_all" ON "memberships" ("tenant_id", "id", "scope_all");
-- Create index "membership_tenant_id_user_id" to table: "memberships"
CREATE UNIQUE INDEX "membership_tenant_id_user_id" ON "memberships" ("tenant_id", "user_id");
-- Create "membership_products" table
CREATE TABLE "membership_products" ("id" character varying(40) NOT NULL, "tenant_id" character varying(40) NOT NULL, "product_id" character varying(40) NOT NULL, "scope_all" boolean NOT NULL DEFAULT false, "membership_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "membership_products_memberships_products" FOREIGN KEY ("membership_id") REFERENCES "memberships" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "membership_products_id_format" CHECK ((id)::text ~ '^mbp_[a-z2-7]{26}$'::text), CONSTRAINT "membership_products_scoped" CHECK (NOT scope_all));
-- Create index "membershipproduct_membership_id_product_id" to table: "membership_products"
CREATE UNIQUE INDEX "membershipproduct_membership_id_product_id" ON "membership_products" ("membership_id", "product_id");
-- Create index "membershipproduct_tenant_id" to table: "membership_products"
CREATE INDEX "membershipproduct_tenant_id" ON "membership_products" ("tenant_id");
