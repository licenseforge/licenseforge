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

// Membership roles (ADR-0019); sdk is for API tokens only. Kept equal to
// authz.Role values (TestMemberRolesMatchAuthz).
var memberRoles = []string{"owner", "admin", "manager", "support", "viewer"}

var (
	emailType  = map[string]string{"postgres": "varchar(320)"}
	issuerType = map[string]string{"postgres": "varchar(500)"}
)

// User is a person, identified by their IdP's (issuer, subject) (ADR-0003,
// ADR-0029). Users belong to no tenant; tenants see them only through
// memberships. email is not unique and never a lookup key; email_verified
// is set only from a true email_verified claim.
type User struct{ ent.Schema }

func (User) Mixin() []ent.Mixin { return []ent.Mixin{Timestamps{}} }

func (User) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.User),
		field.String("issuer").Immutable().NotEmpty().MaxLen(500).SchemaType(issuerType),
		field.String("subject").Immutable().NotEmpty().MaxLen(255).SchemaType(map[string]string{"postgres": "varchar(255)"}),
		field.String("email").Optional().Nillable().MaxLen(320).SchemaType(emailType),
		field.Bool("email_verified").Default(false),
		field.String("name").Optional().Nillable().MaxLen(200).SchemaType(nameType),
		field.Time("last_login_at").Optional().Nillable(),
		field.Time("disabled_at").Optional().Nillable(),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("memberships", Membership.Type),
		// Erasure (ADR-0029) nulls invited_by; it deletes accepted invitations first.
		edge.To("invitations_sent", Invitation.Type).Annotations(entsql.OnDelete(entsql.SetNull)),
		edge.To("invitations_accepted", Invitation.Type).Annotations(entsql.OnDelete(entsql.NoAction)),
		// Tokens belong to the tenant and outlive their creator (ADR-0029).
		edge.To("api_tokens", APIToken.Type).Annotations(entsql.OnDelete(entsql.SetNull)),
	}
}

func (User) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"users_id_format":      `id ~ '^usr_` + idChars + `$'`,
		"users_no_empty":       `btrim((issuer)::text) <> ''::text AND btrim((subject)::text) <> ''::text AND (email IS NULL OR btrim((email)::text) <> ''::text) AND (name IS NULL OR btrim((name)::text) <> ''::text)`,
		"users_verified_email": `email IS NOT NULL OR NOT email_verified`,
	}}}
}

func (User) Indexes() []ent.Index {
	return []ent.Index{index.Fields("issuer", "subject").Unique()}
}
