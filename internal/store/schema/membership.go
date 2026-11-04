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

// Membership gives a user a role in a tenant, for every product or the listed
// ones (ADR-0019, ADR-0029). It is created only by accepting its invitation,
// which the database enforces (identity_accept policy, same-tenant key and
// unique invitation_id); tenant admins change role and scope, or remove it.
type Membership struct{ ent.Schema }

func (Membership) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (Membership) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Membership),
		field.String("user_id").Immutable().NotEmpty().SchemaType(idType),
		field.Enum("role").Values(memberRoles...),
		field.Bool("scope_all"),
		field.String("invitation_id").Immutable().NotEmpty().SchemaType(idType),
	}
}

func (Membership) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("memberships").Field("tenant_id").Unique().Required().Immutable(),
		edge.From("user", User.Type).Ref("memberships").Field("user_id").Unique().Required().Immutable(),
		edge.To("products", MembershipProduct.Type),
	}
}

func (Membership) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"memberships_id_format":  `id ~ '^mem_` + idChars + `$'`,
		"memberships_role_valid": enumCheck("role", memberRoles),
	}}}
}

func (Membership) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "user_id").Unique(),
		index.Fields("invitation_id").Unique(), // an invitation is used once
		index.Fields("tenant_id", "id").Unique(),
		index.Fields("tenant_id", "id", "scope_all").Unique(), // target of the products' same-tenant key
	}
}

// MembershipProduct limits a membership with scope_all = false to a product.
type MembershipProduct struct{ ent.Schema }

func (MembershipProduct) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}} }

func (MembershipProduct) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.MembershipProduct),
		field.String("membership_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("product_id").Immutable().NotEmpty().SchemaType(idType),
		field.Bool("scope_all").Immutable().Default(false), // see InvitationProduct
	}
}

func (MembershipProduct) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("membership", Membership.Type).Ref("products").Field("membership_id").Unique().Required().Immutable(),
	}
}

func (MembershipProduct) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"membership_products_id_format": `id ~ '^mbp_` + idChars + `$'`,
		"membership_products_scoped":    `NOT scope_all`,
	}}}
}

func (MembershipProduct) Indexes() []ent.Index {
	return []ent.Index{index.Fields("membership_id", "product_id").Unique()}
}
