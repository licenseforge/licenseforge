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

var (
	keyAlgs     = []string{"ed25519"}
	keyStatuses = []string{"pending", "active", "retired"}
)

// SigningKey is one of a tenant's license signing keys (ADR-0026). The ID is
// the kid. pending keys are published but never sign, exactly one key per
// tenant is active, and retired keys have their private key destroyed (the
// ciphertext is NULL). Keys are never deleted.
type SigningKey struct{ ent.Schema }

func (SigningKey) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (SigningKey) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.SigningKey),
		field.Enum("alg").Values(keyAlgs...).Immutable(),
		field.Bytes("public_key").Immutable().NotEmpty(),
		field.Enum("status").Values(keyStatuses...),
		// Keyring ciphertext of the 32-byte Ed25519 seed, bound to purpose
		// signing_key, tenant and kid (ADR-0025).
		field.String("private_key_ciphertext").Optional().Nillable().Sensitive().
			SchemaType(map[string]string{"postgres": "varchar(200)"}),
		field.Time("activated_at").Optional().Nillable(),
		field.Time("retired_at").Optional().Nillable(),
	}
}

func (SigningKey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("signing_keys").Field("tenant_id").Unique().Required().Immutable(),
	}
}

func (SigningKey) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"signing_keys_id_format":    `id ~ '^sk_` + idChars + `$'`,
		"signing_keys_alg_valid":    enumCheck("alg", keyAlgs),
		"signing_keys_status_valid": enumCheck("status", keyStatuses),
		"signing_keys_ed25519_len":  `(alg)::text <> 'ed25519'::text OR length(public_key) = 32`,
		// 12-byte nonce + 16-byte tag + 32-byte seed = 60 bytes, 80 chars.
		"signing_keys_ciphertext": `private_key_ciphertext IS NULL OR private_key_ciphertext ~ '^v1\.[a-z0-9-]{1,32}\.[A-Za-z0-9_-]{80}$'`,
		// Only retired keys lack a private key.
		"signing_keys_retired_destroyed": `((status)::text = 'retired'::text) = (private_key_ciphertext IS NULL)`,
		// A pending key may be retired without ever being active (rotation abandoned).
		"signing_keys_activated_at": `((status)::text <> 'pending'::text OR activated_at IS NULL) AND ((status)::text <> 'active'::text OR activated_at IS NOT NULL)`,
		"signing_keys_retired_at":   `((status)::text = 'retired'::text) = (retired_at IS NOT NULL)`,
	}}}
}

func (SigningKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "id").Unique(),
		// One active and at most one pending key per tenant.
		index.Fields("tenant_id", "status").Unique().
			Annotations(entsql.IndexWhere(`(status)::text = ANY (ARRAY['active'::text, 'pending'::text])`)),
	}
}
