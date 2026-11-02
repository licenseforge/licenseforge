package schema

import (
	"regexp"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"licenseforge.io/licenseforge/internal/store/ids"
)

// slugRE: lowercase letters, digits and dashes, starting with a letter.
var slugRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Product is something a tenant sells (ADR-0015). Its slug is the `product`
// claim in licenses.
type Product struct{ ent.Schema }

func (Product) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (Product) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Product),
		field.String("slug").Immutable().NotEmpty().MaxLen(63).Match(slugRE),
		field.String("name").NotEmpty().MaxLen(200),
	}
}

func (Product) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("products").Field("tenant_id").Unique().Required().Immutable(),
	}
}

func (Product) Indexes() []ent.Index {
	return []ent.Index{index.Fields("tenant_id", "slug").Unique()}
}
