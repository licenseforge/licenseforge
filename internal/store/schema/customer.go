package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"licenseforge.io/licenseforge/internal/store/ids"
)

// Customer is a vendor's end customer, who holds licenses. external_refs maps
// to order, CRM or ERP IDs (ADR-0013), e.g. {"stripe": "cus_123"}. Customers
// are archived, never deleted; GDPR erasure anonymises name and email.
type Customer struct{ ent.Schema }

func (Customer) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (Customer) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Customer),
		field.String("name").NotEmpty().MaxLen(200).Validate(notBlank).SchemaType(nameType),
		field.String("email").Optional().Nillable().MaxLen(320).SchemaType(map[string]string{"postgres": "varchar(320)"}),
		field.JSON("external_refs", map[string]string{}).Default(map[string]string{}),
		field.Time("archived_at").Optional().Nillable(),
	}
}

func (Customer) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("customers").Field("tenant_id").Unique().Required().Immutable(),
		edge.To("licenses", License.Type),
	}
}

func (Customer) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"customers_id_format":      `id ~ '^cus_` + idChars + `$'`,
		"customers_name_not_blank": `btrim(name) <> ''`,
		"customers_email_format":   `email IS NULL OR email ~ '^[^@[:space:]]+@[^@[:space:]]+$'`,
		"customers_refs_object":    `jsonb_typeof(external_refs) = 'object'`,
	}}}
}

func (Customer) Indexes() []ent.Index {
	return []ent.Index{index.Fields("tenant_id", "id").Unique()}
}
