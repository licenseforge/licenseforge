package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"

	"licenseforge.io/licenseforge/internal/store/ids"
)

// Tenant is a vendor using LicenseForge (ADR-0009).
type Tenant struct{ ent.Schema }

func (Tenant) Mixin() []ent.Mixin { return []ent.Mixin{Timestamps{}} }

func (Tenant) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Tenant),
		field.String("slug").Unique().NotEmpty().MaxLen(63).Match(slugRE).SchemaType(slugType),
		field.String("name").NotEmpty().MaxLen(200).SchemaType(nameType),
	}
}

func (Tenant) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"tenants_id_format":   `id ~ '^tnt_` + idChars + `$'`,
		"tenants_slug_format": `slug ~ '` + slugPattern + `'`,
	}}}
}

func (Tenant) Edges() []ent.Edge {
	return []ent.Edge{edge.To("products", Product.Type)}
}
