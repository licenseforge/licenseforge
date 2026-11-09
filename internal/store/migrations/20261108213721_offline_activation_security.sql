-- Offline activation (ADR-0043): the serving pools record the token hash of
-- the offline file they issue for a seat, which a deactivation receipt must
-- name. Inserts already may set it (table-level INSERT); renewals update it.
GRANT UPDATE ("offline_file_sha256") ON "activations" TO licenseforge_app, licenseforge_platform;
