// Package store is LicenseForge's PostgreSQL data layer: ent client, versioned
// migrations and tenant isolation (ADR-0008, ADR-0009).
package store

//go:generate go run -mod=mod entc.go
