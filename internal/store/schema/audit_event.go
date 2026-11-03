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

var (
	actorTypes = []string{"user", "token", "platform", "system"}
	outcomes   = []string{"success", "failure", "denied"}
)

// AuditEvent is one entry of a tenant's hash-chained audit log (ADR-0027).
// Append-only: the app roles may only insert and read. hash covers every
// field and prev_hash (package audit), so a changed, removed or reordered
// entry breaks the chain. details is json, not jsonb, so the stored text is
// exactly the hashed text.
type AuditEvent struct{ ent.Schema }

func (AuditEvent) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}} }

func (AuditEvent) Fields() []ent.Field {
	opt := func(name string, n int) ent.Field {
		return field.String(name).Optional().Nillable().Immutable().MaxLen(n).
			SchemaType(map[string]string{"postgres": "varchar(" + strconv.Itoa(n) + ")"})
	}
	return []ent.Field{
		prefixedID(ids.AuditEvent),
		field.Int64("seq").Immutable().Positive(),
		field.Time("occurred_at").Immutable(),
		field.Enum("actor_type").Values(actorTypes...).Immutable(),
		opt("actor_id", 100),
		field.String("action").Immutable().NotEmpty().MaxLen(100).SchemaType(map[string]string{"postgres": "varchar(100)"}),
		opt("object_type", 63),
		opt("object_id", 100),
		field.Enum("outcome").Values(outcomes...).Immutable(),
		opt("source_ip", 45),
		opt("user_agent", 512),
		field.String("details").Immutable().Default("{}").SchemaType(map[string]string{"postgres": "json"}),
		field.Bytes("prev_hash").Immutable(),
		field.Bytes("hash").Immutable(),
	}
}

func (AuditEvent) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("audit_events").Field("tenant_id").Unique().Required().Immutable(),
	}
}

func (AuditEvent) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"audit_events_id_format":     `id ~ '^aud_` + idChars + `$'`,
		"audit_events_actor_valid":   enumCheck("actor_type", actorTypes),
		"audit_events_outcome_valid": enumCheck("outcome", outcomes),
		"audit_events_seq_positive":  `seq > 0`,
		// e.g. signing_key.promote: dot-separated snake_case words.
		"audit_events_action_format": `action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'`,
		"audit_events_object_type":   `object_type IS NULL OR object_type ~ '` + keyPattern + `'`,
		// Optional fields are NULL or non-empty, so the hash encodes NULL as "".
		"audit_events_no_empty":   `actor_id <> '' AND object_id <> '' AND source_ip <> '' AND user_agent <> ''`,
		"audit_events_details":    `json_typeof(details) = 'object'`,
		"audit_events_hash_len":   `length(prev_hash) = 32 AND length(hash) = 32`,
		"audit_events_first_prev": `seq <> 1 OR prev_hash = '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea`,
	}}}
}

func (AuditEvent) Indexes() []ent.Index {
	return []ent.Index{index.Fields("tenant_id", "seq").Unique()}
}
