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

// Activation binds a license to a machine or cluster fingerprint (ADR-0017).
// One active activation per fingerprint per license; deactivated, never
// deleted, so rehosts and history stay auditable.
type Activation struct{ ent.Schema }

func (Activation) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (Activation) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Activation),
		field.String("license_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("fingerprint").Immutable().NotEmpty().SchemaType(map[string]string{"postgres": "varchar(71)"}),
		field.Enum("fp_source").Values(fpSources...).Immutable(),
		field.Enum("binding").Values(bindTypes...).Immutable(),
		field.Enum("mode").Values(modes...).Immutable(),
		field.String("hostname").Optional().Nillable().MaxLen(253).SchemaType(map[string]string{"postgres": "varchar(253)"}),
		field.String("app_version").Optional().Nillable().MaxLen(64).SchemaType(map[string]string{"postgres": "varchar(64)"}),
		field.String("sdk_version").Optional().Nillable().MaxLen(64).SchemaType(map[string]string{"postgres": "varchar(64)"}),
		field.Time("first_seen_at").Immutable(),
		field.Time("last_seen_at"),
		field.Time("deactivated_at").Optional().Nillable(),
		// The token hash of the last offline file issued for this seat
		// (ADR-0043): a deactivation receipt must name it.
		field.String("offline_file_sha256").Optional().Nillable().SchemaType(map[string]string{"postgres": "char(64)"}),
	}
}

func (Activation) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("license", License.Type).Ref("activations").Field("license_id").Unique().Required().Immutable(),
	}
}

func (Activation) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"activations_id_format":   `id ~ '^act_` + idChars + `$'`,
		"activations_fingerprint": `fingerprint ~ '^sha256:[0-9a-f]{64}$'`,
		"activations_source":      enumCheck("fp_source", fpSources),
		"activations_binding":     enumCheck("binding", bindTypes),
		"activations_mode":        enumCheck("mode", modes),
		"activations_seen_order":  `last_seen_at >= first_seen_at`,
		"activations_deactivated": `deactivated_at IS NULL OR deactivated_at >= first_seen_at`,
		// The SDK binds Kubernetes fingerprints to the cluster, all others to the machine.
		"activations_source_binding": `((fp_source)::text = 'kubernetes'::text) = ((binding)::text = 'cluster'::text)`,
		"activations_offline_file":   `offline_file_sha256 IS NULL OR offline_file_sha256 ~ '^[0-9a-f]{64}$'`,
		// Only offline seats carry a file (ADR-0043): an online seat never turns offline.
		"activations_offline_mode": `offline_file_sha256 IS NULL OR (mode)::text = 'offline'::text`,
	}}}
}

func (Activation) Indexes() []ent.Index {
	return []ent.Index{
		// One active activation per machine per license.
		index.Fields("license_id", "fingerprint").Unique().Annotations(entsql.IndexWhere("deactivated_at IS NULL")),
		// Every activation ever, deactivated included: the seat-move history
		// (ADR-0034: was this machine seen, how many machines).
		index.Fields("license_id", "fingerprint").StorageKey("activation_history"),
	}
}
