-- Modify "activations" table
ALTER TABLE "activations" ADD CONSTRAINT "activations_offline_file" CHECK ((offline_file_sha256 IS NULL) OR (offline_file_sha256 ~ '^[0-9a-f]{64}$'::text)), ADD COLUMN "offline_file_sha256" character(64) NULL;
