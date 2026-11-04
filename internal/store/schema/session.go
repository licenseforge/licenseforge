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

// Session is a dashboard login (ADR-0020, ADR-0029): the browser holds only
// an opaque cookie; the server keeps its SHA-256 here. Global (per user, not
// per tenant). It ends at logout, when idle for too long, at its absolute
// expiry, or when the user is suspended or erased.
type Session struct{ ent.Schema }

func (Session) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Session),
		field.String("user_id").Immutable().NotEmpty().SchemaType(idType),
		field.Bytes("token_hash").Immutable().NotEmpty().Sensitive(),
		field.Time("created_at").Immutable().Default(time.Now),
		field.Time("expires_at").Immutable(),
		field.Time("last_seen_at").Default(time.Now),
	}
}

func (Session) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("sessions").Field("user_id").Unique().Required().Immutable(),
	}
}

func (Session) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"sessions_id_format": `id ~ '^ses_` + idChars + `$'`,
		"sessions_hash_len":  `length(token_hash) = 32`,
		"sessions_expiry":    `expires_at > created_at AND expires_at <= (created_at + '1 day'::interval)`,
	}}}
}

func (Session) Indexes() []ent.Index {
	return []ent.Index{index.Fields("token_hash").Unique(), index.Fields("user_id")}
}
