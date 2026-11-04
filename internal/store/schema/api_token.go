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

// tokenRoles: membership roles plus sdk (activation API only), ADR-0019.
var tokenRoles = append(append([]string{}, memberRoles...), "sdk")

// APIToken is a tenant's API token (ADR-0019, ADR-0029): opaque, stored as
// its SHA-256 (internal/apitoken), with a role, an explicit product scope
// and a required expiry of at most one year. It belongs to the tenant, not
// its creator; it is revoked, never deleted or edited.
type APIToken struct{ ent.Schema }

func (APIToken) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (APIToken) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.APIToken),
		field.String("name").Immutable().NotEmpty().MaxLen(200).SchemaType(nameType),
		field.Enum("role").Values(tokenRoles...).Immutable(),
		field.Bool("scope_all").Immutable(),
		field.Bytes("token_hash").Immutable().NotEmpty().Sensitive(),
		field.String("display").Immutable().NotEmpty().MaxLen(40).SchemaType(map[string]string{"postgres": "varchar(40)"}),
		field.String("created_by").Optional().Nillable().SchemaType(idType),
		field.Time("expires_at").Immutable(),
		field.Time("last_used_at").Optional().Nillable(),
		field.Time("revoked_at").Optional().Nillable(),
	}
}

func (APIToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("api_tokens").Field("tenant_id").Unique().Required().Immutable(),
		edge.From("creator", User.Type).Ref("api_tokens").Field("created_by").Unique(),
		edge.To("products", APITokenProduct.Type),
	}
}

func (APIToken) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"api_tokens_id_format":  `id ~ '^tok_` + idChars + `$'`,
		"api_tokens_role_valid": enumCheck("role", tokenRoles),
		"api_tokens_hash_len":   `length(token_hash) = 32`,
		"api_tokens_no_empty":   `btrim((name)::text) <> ''::text`,
		"api_tokens_display":    `(display)::text ~ '^lf_live_[a-z2-7]{8}…$'::text`,
		// Required expiry, at most a year: a forgotten token stops working.
		"api_tokens_expiry": `expires_at > created_at AND expires_at <= (created_at + '1 year'::interval)`,
	}}}
}

func (APIToken) Indexes() []ent.Index {
	return []ent.Index{
		// Per tenant, not global: an insert conflict can't reveal another
		// tenant's token. Lookups run under the URL's tenant (ADR-0029).
		index.Fields("tenant_id", "token_hash").Unique(),
		index.Fields("tenant_id", "id").Unique(),
		index.Fields("tenant_id", "id", "scope_all").Unique(), // target of the products' same-tenant key
	}
}

// APITokenProduct limits a token with scope_all = false to a product.
type APITokenProduct struct{ ent.Schema }

func (APITokenProduct) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}} }

func (APITokenProduct) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.APITokenProduct),
		field.String("api_token_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("product_id").Immutable().NotEmpty().SchemaType(idType),
		field.Bool("scope_all").Immutable().Default(false), // see InvitationProduct
	}
}

func (APITokenProduct) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("api_token", APIToken.Type).Ref("products").Field("api_token_id").Unique().Required().Immutable(),
	}
}

func (APITokenProduct) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"api_token_products_id_format": `id ~ '^tkp_` + idChars + `$'`,
		"api_token_products_scoped":    `NOT scope_all`,
	}}}
}

func (APITokenProduct) Indexes() []ent.Index {
	return []ent.Index{index.Fields("api_token_id", "product_id").Unique()}
}
