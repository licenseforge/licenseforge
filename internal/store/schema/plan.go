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

// Plan is one way of selling a product ("Pro yearly", "Trial 14d"): its
// license terms and, via plan features, which features it grants (ADR-0015).
// Licenses copy these terms when issued (ADR-0013), so editing a plan never
// changes licenses already sold. Durations are whole seconds.
type Plan struct{ ent.Schema }

func (Plan) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (Plan) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Plan),
		field.String("product_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("slug").NotEmpty().MaxLen(63).Match(slugRE).SchemaType(slugType),
		field.String("name").NotEmpty().MaxLen(200).SchemaType(nameType),
		field.Int64("duration_seconds").Optional().Nillable().Positive().Comment("nil = perpetual"),
		field.Enum("expiry_basis").Values("from_issue", "from_first_activation").Default("from_issue"),
		field.Int("max_activations").Optional().Nillable().Positive().Comment("nil = unlimited"),
		field.Int("max_rehosts").Optional().Nillable().NonNegative().Comment("nil = unlimited"),
		field.Bool("offline_allowed").Default(false),
		field.Int64("lease_seconds").Default(7 * 24 * 3600).Positive(),
		field.Int64("max_offline_seconds").Optional().Nillable().NonNegative(),
		field.Int64("grace_seconds").Default(0).NonNegative(),
		field.Time("archived_at").Optional().Nillable(),
	}
}

func (Plan) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("product", Product.Type).Ref("plans").Field("product_id").Unique().Required().Immutable(),
		edge.To("plan_features", PlanFeature.Type),
	}
}

func (Plan) Annotations() []schema.Annotation {
	const maxSeconds = "3153600000" // 36,500 days, the license format's duration limit
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"plans_id_format":       `id ~ '^pln_` + idChars + `$'`,
		"plans_slug_format":     `slug ~ '` + slugPattern + `'`,
		"plans_name_set":        `name <> ''`,
		"plans_expiry_valid":    `expiry_basis IN ('from_issue', 'from_first_activation')`,
		"plans_duration_range":  `duration_seconds IS NULL OR (duration_seconds > 0 AND duration_seconds <= ` + maxSeconds + `)`,
		"plans_activations_pos": `max_activations IS NULL OR max_activations > 0`,
		"plans_rehosts_nonneg":  `max_rehosts IS NULL OR max_rehosts >= 0`,
		"plans_lease_range":     `lease_seconds > 0 AND lease_seconds <= ` + maxSeconds,
		"plans_max_offline_rng": `max_offline_seconds IS NULL OR (max_offline_seconds >= 0 AND max_offline_seconds <= ` + maxSeconds + `)`,
		"plans_grace_range":     `grace_seconds >= 0 AND grace_seconds <= ` + maxSeconds,
	}}}
}

func (Plan) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("product_id", "slug").Unique(),
		index.Fields("tenant_id", "id").Unique(),
		index.Fields("product_id", "id").Unique(), // target of plan_features' same-product key
	}
}
