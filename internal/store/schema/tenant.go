package schema

import (
	"entgo.io/ent"
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
		field.String("slug").Unique().NotEmpty().MaxLen(63).Match(slugRE),
		field.String("name").NotEmpty().MaxLen(200),
	}
}

func (Tenant) Edges() []ent.Edge {
	return []ent.Edge{edge.To("products", Product.Type)}
}
