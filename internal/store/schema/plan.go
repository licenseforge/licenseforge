package schema

import (
	"strconv"

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
// changes licenses already sold. The term is either calendar months (monthly,
// yearly billing) or whole seconds (trials, fixed periods); neither means
// perpetual. Other durations are whole seconds, as the license format needs.
// The slug goes into licenses, so it is immutable.
type Plan struct{ ent.Schema }

func (Plan) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (Plan) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Plan),
		field.String("product_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("slug").Immutable().NotEmpty().MaxLen(63).Match(slugRE).SchemaType(slugType),
		field.String("name").NotEmpty().MaxLen(200).Validate(notBlank).SchemaType(nameType),
		field.Int("duration_months").Optional().Nillable().Range(1, 1200),
		field.Int64("duration_seconds").Optional().Nillable().Range(1, maxSeconds),
		field.Enum("expiry_basis").Values(expiryBases...).Default("from_issue"),
		field.Int("max_activations").Optional().Nillable().Range(1, 1_000_000).Comment("nil = unlimited"),
		field.Int("max_rehosts").Optional().Nillable().Range(0, 1_000_000).Comment("nil = unlimited"),
		field.Bool("offline_allowed").Default(false),
		field.Int64("lease_seconds").Default(7*24*3600).Range(1, maxSeconds),
		field.Int64("max_offline_seconds").Optional().Nillable().Range(0, maxSeconds),
		field.Int64("grace_seconds").Default(0).Range(0, maxSeconds),
		field.Time("archived_at").Optional().Nillable(),
	}
}

func (Plan) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("product", Product.Type).Ref("plans").Field("product_id").Unique().Required().Immutable(),
		edge.To("plan_features", PlanFeature.Type),
		edge.To("licenses", License.Type),
	}
}

func (Plan) Annotations() []schema.Annotation {
	maxS := strconv.Itoa(maxSeconds)
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"plans_id_format":       `id ~ '^pln_` + idChars + `$'`,
		"plans_slug_format":     `slug ~ '` + slugPattern + `'`,
		"plans_name_not_blank":  `btrim(name) <> ''`,
		"plans_expiry_valid":    enumCheck("expiry_basis", expiryBases),
		"plans_duration_secs":   `duration_seconds IS NULL OR (duration_seconds >= 1 AND duration_seconds <= ` + maxS + `)`,
		"plans_duration_months": `duration_months IS NULL OR (duration_months >= 1 AND duration_months <= 1200)`,
		"plans_one_duration":    `num_nonnulls(duration_months, duration_seconds) <= 1`,
		"plans_activations_rng": `max_activations IS NULL OR (max_activations >= 1 AND max_activations <= 1000000)`,
		"plans_rehosts_rng":     `max_rehosts IS NULL OR (max_rehosts >= 0 AND max_rehosts <= 1000000)`,
		"plans_lease_range":     `lease_seconds >= 1 AND lease_seconds <= ` + maxS,
		"plans_max_offline_rng": `max_offline_seconds IS NULL OR (max_offline_seconds >= 0 AND max_offline_seconds <= ` + maxS + `)`,
		"plans_grace_range":     `grace_seconds >= 0 AND grace_seconds <= ` + maxS,
	}}}
}

func (Plan) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("product_id", "slug").Unique(),
		index.Fields("tenant_id", "id").Unique(),
		index.Fields("tenant_id", "product_id", "id").Unique(), // target of plan_features' same-tenant key
	}
}
