-- Create "platform_admins" table
CREATE TABLE "platform_admins" ("id" character varying(40) NOT NULL, "bootstrap" boolean NOT NULL DEFAULT false, "granted_by" character varying(40) NULL, "created_at" timestamptz NOT NULL, "user_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "platform_admins_users_platform_admin" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "platform_admins_grant" CHECK ((bootstrap AND (granted_by IS NULL)) OR ((NOT bootstrap) AND (granted_by IS NOT NULL) AND ((granted_by)::text ~ '^usr_[a-z2-7]{26}$'::text))), CONSTRAINT "platform_admins_id_format" CHECK ((id)::text ~ '^pad_[a-z2-7]{26}$'::text));
-- Create index "platform_admins_user_id_key" to table: "platform_admins"
CREATE UNIQUE INDEX "platform_admins_user_id_key" ON "platform_admins" ("user_id");
-- Create index "platformadmin_bootstrap" to table: "platform_admins"
CREATE UNIQUE INDEX "platformadmin_bootstrap" ON "platform_admins" ("bootstrap") WHERE bootstrap;
