package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"licenseforge.io/licenseforge/internal/store/ids"
)

// PlatformAdmin marks a user as an operator of the whole installation
// (ADR-0019, ADR-0029): list and suspend tenants, support access. Global (no
// tenant). Managed only on the platform pool; the login path reads it. The
// first one comes from LICENSEFORGE_BOOTSTRAP_ADMIN (DB.BootstrapPlatformAdmin).
type PlatformAdmin struct{ ent.Schema }

func (PlatformAdmin) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.PlatformAdmin),
		field.String("user_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("granted_by").Optional().Nillable().Immutable().SchemaType(idType), // nil: bootstrap
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

func (PlatformAdmin) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("platform_admin").Field("user_id").Unique().Required().Immutable(),
	}
}

func (PlatformAdmin) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"platform_admins_id_format": `id ~ '^pad_` + idChars + `$'`,
	}}}
}

func (PlatformAdmin) Indexes() []ent.Index {
	return []ent.Index{index.Fields("user_id").Unique()}
}
