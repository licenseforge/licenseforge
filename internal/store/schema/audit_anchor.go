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

// AuditAnchor records a retention cut (ADR-0036): the seq and hash of the
// last entry pruned from a chain. The chain's effective anchor is its highest
// seq; Verify starts after it. Insert-only: only the retention login inserts,
// and only an anchor that matches a real entry and moves the chain's start
// forward; nobody updates or deletes anchors (tenant purge, owner login, does).
type AuditAnchor struct{ ent.Schema }

// No TenantScoped mixin: its tenant_id index would duplicate the prefix of
// the unique (tenant_id, seq) index.
func (AuditAnchor) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.AuditAnchor),
		field.String("tenant_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType),
		field.Int64("seq").Immutable().Positive(),
		field.Bytes("hash").Immutable(),
		field.Time("cut_at").Immutable().Default(time.Now),
	}
}

func (AuditAnchor) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("audit_anchors").Field("tenant_id").Unique().Required().Immutable(),
	}
}

func (AuditAnchor) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"audit_anchors_id_format": `(id)::text ~ '^anc_` + idChars + `$'::text`,
		"audit_anchors_seq":       `seq > 0`,
		"audit_anchors_hash_len":  `length(hash) = 32`,
	}}}
}

func (AuditAnchor) Indexes() []ent.Index {
	return []ent.Index{index.Fields("tenant_id", "seq").Unique()}
}
