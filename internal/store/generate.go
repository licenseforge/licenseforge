// Package store is LicenseForge's PostgreSQL data layer: ent client, versioned
// migrations and tenant isolation (ADR-0008, ADR-0009).
package store

// Features: sql/lock for SELECT ... FOR UPDATE (activation counting),
// sql/execquery for set_config (tenant scope), sql/versioned-migration for
// the migration diff tool.
//go:generate go tool ent generate --feature sql/lock,sql/execquery,sql/versioned-migration --target ./ent ./schema
