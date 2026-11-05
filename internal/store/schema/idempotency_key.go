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

// IdempotencyKey is a client's Idempotency-Key and the outcome of the request
// it first came with (ADR-0032), scoped to (tenant, credential). The row is
// inserted in the operation's own transaction before the operation runs, so a
// concurrent request with the same key waits on it, and committed with the
// outcome (2xx or 4xx; never 5xx). Kept 24 hours (internal/idempotency).
type IdempotencyKey struct{ ent.Schema }

// No TenantScoped mixin: its tenant_id index would duplicate the prefix of
// the unique (tenant_id, credential, key) index.
func (IdempotencyKey) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.IdempotencyKey),
		field.String("tenant_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType),
		field.String("credential").Immutable().NotEmpty().SchemaType(idType).Comment("API token, user or license ID"),
		field.String("key").Immutable().NotEmpty().MaxLen(255).SchemaType(map[string]string{"postgres": "varchar(255)"}),
		field.Bytes("request_hash").Immutable().NotEmpty(),
		field.Int("status").Optional().Nillable().Comment("nil only inside the claiming transaction"),
		field.Bytes("body").Optional().Nillable().Sensitive().Comment("encrypted (secrets.PurposeIdempotencyResponse)"),
		field.Time("created_at").Immutable(),
	}
}

func (IdempotencyKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("idempotency_keys").Field("tenant_id").Unique().Required().Immutable(),
	}
}

func (IdempotencyKey) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"idempotency_keys_id_format":  `id ~ '^idk_` + idChars + `$'`,
		"idempotency_keys_credential": `credential ~ '^(tok|usr|lic)_` + idChars + `$'`, // API token, user, or license (activation API)
		"idempotency_keys_key":        `key ~ '^[ -~]{1,255}$'`,                         // printable ASCII
		"idempotency_keys_hash_len":   `length(request_hash) = 32`,
		"idempotency_keys_status":     `status IS NULL OR (status >= 200 AND status <= 299) OR (status >= 400 AND status <= 499)`,
		"idempotency_keys_outcome":    `(status IS NULL) = (body IS NULL)`,
	}}}
}

func (IdempotencyKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "credential", "key").Unique(),
		index.Fields("created_at"), // cleanup, across tenants
	}
}
