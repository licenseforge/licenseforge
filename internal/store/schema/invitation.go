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

// Invitation asks an email address to join a tenant with a role and scope
// (ADR-0029). It is accepted once, explicitly, by a user whose verified email
// matches, with the invite link's token (stored as SHA-256). Role, scope,
// email and token never change; it is revoked, never edited.
type Invitation struct{ ent.Schema }

func (Invitation) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (Invitation) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Invitation),
		field.String("email").Immutable().NotEmpty().MaxLen(320).SchemaType(emailType),
		field.Enum("role").Values(memberRoles...).Immutable(),
		field.Bool("scope_all").Immutable(),
		field.String("issuer").Optional().Nillable().Immutable().MaxLen(500).SchemaType(issuerType),
		field.String("invited_by").Optional().Nillable().SchemaType(idType),
		field.Bytes("token_hash").Immutable().NotEmpty().Sensitive(),
		field.Time("expires_at").Immutable(),
		field.Time("accepted_at").Optional().Nillable(),
		field.String("accepted_by").Optional().Nillable().SchemaType(idType),
		field.Time("revoked_at").Optional().Nillable(),
	}
}

func (Invitation) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("invitations").Field("tenant_id").Unique().Required().Immutable(),
		edge.To("products", InvitationProduct.Type),
		edge.From("inviter", User.Type).Ref("invitations_sent").Field("invited_by").Unique(),
		edge.From("acceptor", User.Type).Ref("invitations_accepted").Field("accepted_by").Unique(),
	}
}

func (Invitation) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"invitations_id_format":   `id ~ '^inv_` + idChars + `$'`,
		"invitations_role_valid":  enumCheck("role", memberRoles),
		"invitations_token_len":   `length(token_hash) = 32`,
		"invitations_no_empty":    `btrim((email)::text) <> ''::text AND (issuer IS NULL OR btrim((issuer)::text) <> ''::text)`,
		"invitations_accepted":    `(accepted_at IS NULL) = (accepted_by IS NULL)`,
		"invitations_one_outcome": `accepted_at IS NULL OR revoked_at IS NULL`,
		"invitations_expiry":      `expires_at > created_at`,
	}}}
}

func (Invitation) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("token_hash").Unique(), // acceptance looks the invitation up by token
		index.Fields("tenant_id", "id").Unique(),
		index.Fields("tenant_id", "id", "scope_all").Unique(),   // target of the products' same-tenant key
		index.Fields("tenant_id", "id", "accepted_by").Unique(), // target of the memberships' key
	}
}

// InvitationProduct limits an invitation with scope_all = false to a product.
type InvitationProduct struct{ ent.Schema }

func (InvitationProduct) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}} }

func (InvitationProduct) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.InvitationProduct),
		field.String("invitation_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("product_id").Immutable().NotEmpty().SchemaType(idType),
		// Always false: the same-tenant key on (tenant_id, invitation_id, scope_all)
		// makes product rows impossible on an all-products invitation.
		field.Bool("scope_all").Immutable().Default(false),
	}
}

func (InvitationProduct) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("invitation", Invitation.Type).Ref("products").Field("invitation_id").Unique().Required().Immutable(),
	}
}

func (InvitationProduct) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"invitation_products_id_format": `id ~ '^ivp_` + idChars + `$'`,
		"invitation_products_scoped":    `NOT scope_all`,
	}}}
}

func (InvitationProduct) Indexes() []ent.Index {
	return []ent.Index{index.Fields("invitation_id", "product_id").Unique()}
}
