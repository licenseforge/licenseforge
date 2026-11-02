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

// PlanFeature grants a feature in a plan (ADR-0015). A row grants a boolean
// feature; limit features also carry limit_value (-1 = unlimited). product_id
// lets composite foreign keys guarantee plan and feature belong to the same
// product (and that product to the same tenant).
type PlanFeature struct{ ent.Schema }

func (PlanFeature) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (PlanFeature) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.PlanFeature),
		field.String("product_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("plan_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("feature_id").Immutable().NotEmpty().SchemaType(idType),
		field.Int64("limit_value").Optional().Nillable().Min(-1).Max(1<<53 - 1),
	}
}

func (PlanFeature) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("plan", Plan.Type).Ref("plan_features").Field("plan_id").Unique().Required().Immutable(),
		edge.From("feature", Feature.Type).Ref("plan_features").Field("feature_id").Unique().Required().Immutable(),
	}
}

func (PlanFeature) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"plan_features_id_format":   `id ~ '^plf_` + idChars + `$'`,
		"plan_features_limit_range": `limit_value IS NULL OR (limit_value >= -1 AND limit_value <= ` + maxSafeInt + `)`,
	}}}
}

func (PlanFeature) Indexes() []ent.Index {
	return []ent.Index{index.Fields("plan_id", "feature_id").Unique()}
}
