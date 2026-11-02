package schema

import (
	"regexp"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"licenseforge.io/licenseforge/internal/store/ids"
)

var slugRE = regexp.MustCompile(slugPattern)

// Product is something a tenant sells (ADR-0015). Its slug is the `product`
// claim in licenses.
type Product struct{ ent.Schema }

func (Product) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (Product) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Product),
		field.String("slug").Immutable().NotEmpty().MaxLen(63).Match(slugRE).SchemaType(slugType),
		field.String("name").NotEmpty().MaxLen(200).Validate(notBlank).SchemaType(nameType),
	}
}

func (Product) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("products").Field("tenant_id").Unique().Required().Immutable(),
		edge.To("features", Feature.Type),
		edge.To("plans", Plan.Type),
		edge.To("licenses", License.Type),
	}
}

func (Product) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"products_id_format":      `id ~ '^prd_` + idChars + `$'`,
		"products_slug_format":    `slug ~ '` + slugPattern + `'`,
		"products_name_not_blank": `btrim(name) <> ''`,
	}}}
}

func (Product) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "slug").Unique(),
		index.Fields("tenant_id", "id").Unique(), // target of same-tenant foreign keys
	}
}
