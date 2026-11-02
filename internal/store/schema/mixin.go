// Package schema holds the ent schemas (ADR-0008). Generated code lives in
// internal/store/ent; regenerate with `go generate ./internal/store`.
package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// Column types enforced by the database too, not only by ent's validators.
var (
	idType   = map[string]string{dialect.Postgres: "varchar(40)"}
	slugType = map[string]string{dialect.Postgres: "varchar(63)"}
	nameType = map[string]string{dialect.Postgres: "varchar(200)"}
)

// Slug and ID rules, shared by ent validators and database CHECK constraints.
const (
	slugPattern = `^[a-z][a-z0-9]*(-[a-z0-9]+)*$` // lowercase words joined by single dashes
	idChars     = `[a-z2-7]{26}`
)

// prefixedID is a text primary key with a type prefix, e.g. "prd_…".
func prefixedID(newID func() string) ent.Field {
	return field.String("id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType).DefaultFunc(newID)
}

// Timestamps adds created_at and updated_at.
type Timestamps struct{ mixin.Schema }

func (Timestamps) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// TenantScoped adds the tenant_id column every tenant-owned table carries.
// Row-level security policies (migrations) filter on it; see ADR-0009.
type TenantScoped struct{ mixin.Schema }

func (TenantScoped) Fields() []ent.Field {
	return []ent.Field{field.String("tenant_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType)}
}

func (TenantScoped) Indexes() []ent.Index {
	return []ent.Index{index.Fields("tenant_id")}
}
