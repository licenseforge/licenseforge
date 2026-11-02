package schema

import (
	"regexp"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"licenseforge.io/licenseforge/internal/store/ids"
)

var keyRE = regexp.MustCompile(keyPattern)

// Feature is a capability of a product that licenses switch on (boolean) or
// limit (ADR-0015). Its key is what apps check (HasFeature, Limit), so it is
// immutable, and features are archived, never deleted, so a key is never reused.
type Feature struct{ ent.Schema }

func (Feature) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (Feature) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Feature),
		field.String("product_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("key").Immutable().NotEmpty().MaxLen(63).Match(keyRE).SchemaType(slugType),
		field.String("name").NotEmpty().MaxLen(200).Validate(notBlank).SchemaType(nameType),
		field.String("description").Optional().Nillable().MaxLen(2000).Validate(notBlank).SchemaType(map[string]string{"postgres": "varchar(2000)"}),
		field.Enum("type").Values(featureTypes...).Immutable(),
		field.String("unit").Optional().Nillable().MaxLen(40).Validate(notBlank).SchemaType(map[string]string{"postgres": "varchar(40)"}),
		field.Time("archived_at").Optional().Nillable(),
	}
}

func (Feature) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("product", Product.Type).Ref("features").Field("product_id").Unique().Required().Immutable(),
		edge.To("plan_features", PlanFeature.Type),
	}
}

func (Feature) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"features_id_format":      `id ~ '^ftr_` + idChars + `$'`,
		"features_key_format":     `key ~ '` + keyPattern + `'`,
		"features_name_not_blank": `btrim(name) <> ''`,
		"features_type_valid":     enumCheck("type", featureTypes),
		"features_desc_set":       `description IS NULL OR btrim(description) <> ''`,
		"features_unit_set":       `unit IS NULL OR btrim(unit) <> ''`,
	}}}
}

func (Feature) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("product_id", "key").Unique(), // keys are never reused, archived or not
		index.Fields("tenant_id", "id").Unique(),
		index.Fields("tenant_id", "product_id", "id", "type").Unique(), // target of plan_features' same-tenant key
	}
}
