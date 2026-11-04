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
// first one comes from LICENSEFORGE_BOOTSTRAP_ADMIN (DB.BootstrapPlatformAdmin);
// the last one can't be removed (ADR-0031).
type PlatformAdmin struct{ ent.Schema }

func (PlatformAdmin) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.PlatformAdmin),
		field.String("user_id").Immutable().NotEmpty().SchemaType(idType),
		// How the role was granted (ADR-0031): bootstrap (granted_by nil), or by
		// an existing admin. granted_by keeps the granter's opaque ID even after
		// erasure (no foreign key), like audit entries.
		field.Bool("bootstrap").Immutable().Default(false),
		field.String("granted_by").Optional().Nillable().Immutable().SchemaType(idType),
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
		"platform_admins_grant":     `(bootstrap AND granted_by IS NULL) OR (NOT bootstrap AND granted_by IS NOT NULL AND (granted_by)::text ~ '^usr_` + idChars + `$'::text)`,
	}}}
}

func (PlatformAdmin) Indexes() []ent.Index {
	// At most one bootstrap grant, ever: no snapshot race can add a second.
	return []ent.Index{index.Fields("bootstrap").Unique().Annotations(entsql.IndexWhere("bootstrap"))}
}
