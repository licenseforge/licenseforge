-- Create "sessions" table
CREATE TABLE "sessions" ("id" character varying(40) NOT NULL, "token_hash" bytea NOT NULL, "created_at" timestamptz NOT NULL, "expires_at" timestamptz NOT NULL, "last_seen_at" timestamptz NOT NULL, "user_id" character varying(40) NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "sessions_users_sessions" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "sessions_expiry" CHECK ((expires_at > created_at) AND (expires_at <= (created_at + '1 day'::interval))), CONSTRAINT "sessions_hash_len" CHECK (length(token_hash) = 32), CONSTRAINT "sessions_id_format" CHECK ((id)::text ~ '^ses_[a-z2-7]{26}$'::text));
-- Create index "session_token_hash" to table: "sessions"
CREATE UNIQUE INDEX "session_token_hash" ON "sessions" ("token_hash");
-- Create index "session_user_id" to table: "sessions"
CREATE INDEX "session_user_id" ON "sessions" ("user_id");
