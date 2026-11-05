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

// AuditExportSink is a SIEM sink a serving pod is configured with (ADR-0036),
// registered at start. Retention never prunes past a registered sink's
// cursors. Global, platform pool only; removed only by the documented
// removal step (owner login), which removes its cursors.
type AuditExportSink struct{ ent.Schema }

func (AuditExportSink) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").Immutable().NotEmpty().MaxLen(32).SchemaType(map[string]string{"postgres": "varchar(32)"}).Comment("sink name, e.g. syslog"),
		field.Time("created_at").Immutable().Default(time.Now),
	}
}

func (AuditExportSink) Edges() []ent.Edge {
	return []ent.Edge{edge.To("cursors", AuditExportCursor.Type).Annotations(entsql.OnDelete(entsql.Cascade))}
}

func (AuditExportSink) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"audit_export_sinks_id_format": `(id)::text ~ '^[a-z][a-z0-9-]{0,31}$'::text`,
	}}}
}

// AuditExportCursor is how far one sink has exported one chain (ADR-0036):
// seq is the last entry delivered. A replica leases it (claimed_by,
// claimed_until) to send the next batch, and advances it only while it still
// holds the lease and seq is unchanged. Per-chain seq is gap-free in commit
// order, so a cursor never skips an entry.
type AuditExportCursor struct{ ent.Schema }

// No TenantScoped mixin: its tenant_id index would duplicate the prefix of
// the unique (tenant_id, sink_id) index.
func (AuditExportCursor) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.AuditExportCursor),
		field.String("tenant_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType),
		field.String("sink_id").Immutable().NotEmpty().MaxLen(32).SchemaType(map[string]string{"postgres": "varchar(32)"}),
		field.Int64("seq").Default(0).NonNegative(),
		field.String("claimed_by").Optional().Nillable().MaxLen(100).SchemaType(map[string]string{"postgres": "varchar(100)"}),
		field.Time("claimed_until").Optional().Nillable(),
	}
}

func (AuditExportCursor) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("audit_export_cursors").Field("tenant_id").Unique().Required().Immutable(),
		edge.From("sink", AuditExportSink.Type).Ref("cursors").Field("sink_id").Unique().Required().Immutable(),
	}
}

func (AuditExportCursor) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"audit_export_cursors_id_format": `(id)::text ~ '^aec_` + idChars + `$'::text`,
		"audit_export_cursors_claim":     `(claimed_by IS NULL) = (claimed_until IS NULL)`,
		"audit_export_cursors_seq":       `seq >= 0`,
	}}}
}

func (AuditExportCursor) Indexes() []ent.Index {
	return []ent.Index{index.Fields("tenant_id", "sink_id").Unique()}
}
