package schema

import (
	"encoding/json"
	"strconv"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"licenseforge.io/licenseforge/internal/store/ids"
)

// LicenseEntitlements is the resolved feature set a license grants: the
// plan's features with per-license overrides applied, copied at issue time
// (ADR-0013, ADR-0015). Same shape as the license file's entitlements claim.
type LicenseEntitlements struct {
	Features []string         `json:"features"`
	Limits   map[string]int64 `json:"limits"`
}

// MarshalJSON writes nil features and limits as [] and {}, the shape the
// database CHECK and the license format expect.
func (e LicenseEntitlements) MarshalJSON() ([]byte, error) {
	type plain LicenseEntitlements
	if e.Features == nil {
		e.Features = []string{}
	}
	if e.Limits == nil {
		e.Limits = map[string]int64{}
	}
	return json.Marshal(plain(e))
}

// License is a right granted to a customer under a plan. It carries a
// snapshot of the plan's terms and features, so editing a plan never changes
// licenses already sold; an explicit, audited upgrade rewrites the snapshot.
// The key is stored encrypted with a lookup hash (ADR-0025). "Expired" is not
// a status: it follows from expires_at. Licenses are revoked, never deleted.
type License struct{ ent.Schema }

func (License) Mixin() []ent.Mixin { return []ent.Mixin{TenantScoped{}, Timestamps{}} }

func (License) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.License),
		field.String("product_id").Immutable().NotEmpty().SchemaType(idType),
		field.String("plan_id").NotEmpty().SchemaType(idType),
		field.String("customer_id").Immutable().NotEmpty().SchemaType(idType),
		field.Enum("type").Values(licenseTypes...).Default("paid"),
		field.Enum("status").Values(statuses...).Default("active"),
		// Key (ADR-0025): ciphertext, lookup hash, and the last characters for display.
		field.String("key_ciphertext").NotEmpty().Sensitive().SchemaType(map[string]string{"postgres": "varchar(200)"}),
		field.String("key_lookup").NotEmpty().SchemaType(map[string]string{"postgres": "varchar(64)"}),
		field.String("key_hint").NotEmpty().SchemaType(map[string]string{"postgres": "varchar(6)"}),
		// Snapshot of the plan at issue (or at the last explicit upgrade).
		field.String("plan_slug").NotEmpty().MaxLen(63).Match(slugRE).SchemaType(slugType),
		field.Enum("expiry_basis").Values(expiryBases...),
		field.Int("duration_months").Optional().Nillable().Range(1, 1200),
		field.Int64("duration_seconds").Optional().Nillable().Range(1, maxSeconds),
		field.Int("max_activations").Optional().Nillable().Range(1, 1_000_000),
		field.Int("max_rehosts").Optional().Nillable().Range(0, 1_000_000),
		field.Enum("bind_type").Values(bindPolicies...),
		field.Bool("offline_allowed"),
		field.Int64("lease_seconds").Range(1, maxSeconds),
		field.Int64("max_offline_seconds").Optional().Nillable().Range(0, maxSeconds),
		field.Int64("grace_seconds").Range(0, maxSeconds),
		field.JSON("entitlements", LicenseEntitlements{}),
		// Lifecycle.
		field.Time("issued_at").Immutable(),
		field.Time("expires_at").Optional().Nillable().Comment("nil = perpetual, or not yet started (from_first_activation)"),
		field.Time("first_activated_at").Optional().Nillable(),
		field.Time("updates_until").Optional().Nillable(),
		field.Time("suspended_at").Optional().Nillable(),
		field.Time("revoked_at").Optional().Nillable(),
		field.Int("rehost_count").Default(0).NonNegative(),
		field.JSON("external_refs", map[string]string{}).Default(map[string]string{}),
	}
}

func (License) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("product", Product.Type).Ref("licenses").Field("product_id").Unique().Required().Immutable(),
		edge.From("plan", Plan.Type).Ref("licenses").Field("plan_id").Unique().Required(),
		edge.From("customer", Customer.Type).Ref("licenses").Field("customer_id").Unique().Required().Immutable(),
		edge.To("activations", Activation.Type),
	}
}

func (License) Annotations() []schema.Annotation {
	maxS := strconv.Itoa(maxSeconds)
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"licenses_id_format":       `id ~ '^lic_` + idChars + `$'`,
		"licenses_type_valid":      enumCheck("type", licenseTypes),
		"licenses_status_valid":    enumCheck("status", statuses),
		"licenses_expiry_valid":    enumCheck("expiry_basis", expiryBases),
		"licenses_key_ciphertext":  `key_ciphertext ~ '^v1\.[a-z0-9-]{1,32}\.[A-Za-z0-9_-]{60,}$'`, // 12-byte nonce + 16-byte tag + the 33-byte formatted key = 61 bytes, 82 chars
		"licenses_key_lookup":      `key_lookup ~ '^[0-9a-f]{64}$'`,
		"licenses_key_hint":        `key_hint ~ '^[A-Z2-7]{6}$'`,
		"licenses_plan_slug":       `plan_slug ~ '` + slugPattern + `'`,
		"licenses_one_duration":    `num_nonnulls(duration_months, duration_seconds) <= 1`,
		"licenses_duration_months": `duration_months IS NULL OR (duration_months >= 1 AND duration_months <= 1200)`,
		"licenses_duration_secs":   `duration_seconds IS NULL OR (duration_seconds >= 1 AND duration_seconds <= ` + maxS + `)`,
		"licenses_activations_rng": `max_activations IS NULL OR (max_activations >= 1 AND max_activations <= 1000000)`,
		"licenses_rehosts_rng":     `max_rehosts IS NULL OR (max_rehosts >= 0 AND max_rehosts <= 1000000)`,
		"licenses_lease_range":     `lease_seconds >= 1 AND lease_seconds <= ` + maxS,
		"licenses_max_offline_rng": `max_offline_seconds IS NULL OR (max_offline_seconds >= 0 AND max_offline_seconds <= ` + maxS + `)`,
		"licenses_grace_range":     `grace_seconds >= 0 AND grace_seconds <= ` + maxS,
		"licenses_rehosts_nonneg":  `rehost_count >= 0`,
		"licenses_entitlements":    `jsonb_typeof(entitlements) = 'object' AND jsonb_typeof(entitlements -> 'features') = 'array' AND jsonb_typeof(entitlements -> 'limits') = 'object'`,
		// Contents as the license format requires (spec: claim encoding rules):
		// feature keys are strings in the key format, limits integers in -1..2^53-1.
		"licenses_ent_features": `NOT jsonb_path_exists(entitlements, 'strict $."features"[*]?(@.type() != "string" || !(@ like_regex "` + keyPattern + `"))'::jsonpath)`,
		"licenses_ent_limits":   `NOT jsonb_path_exists(entitlements, 'strict $."limits".*?(@.type() != "number" || @ < -1 || @ > ` + maxSafeInt + ` || @ != @.floor())'::jsonpath)`,
		"licenses_refs_strings": stringMapCheck("external_refs"),
		"licenses_bind_valid":   enumCheck("bind_type", bindPolicies),
		// Expiry semantics.
		"licenses_expiry_after_issue":    `expires_at IS NULL OR expires_at > issued_at`,
		"licenses_activated_after_issue": `first_activated_at IS NULL OR first_activated_at >= issued_at`,
		"licenses_perpetual_no_expiry":   `num_nonnulls(duration_months, duration_seconds) > 0 OR expires_at IS NULL`,
		"licenses_unstarted_no_expiry":   `(expiry_basis)::text <> 'from_first_activation'::text OR first_activated_at IS NOT NULL OR expires_at IS NULL`,
		"licenses_started_has_expiry":    `num_nonnulls(duration_months, duration_seconds) = 0 OR (expiry_basis)::text <> 'from_first_activation'::text OR first_activated_at IS NULL OR expires_at IS NOT NULL`,
		"licenses_rehosts_within_limit":  `max_rehosts IS NULL OR rehost_count <= max_rehosts`,
		// A from_issue term license always has its expiry (else it would read as perpetual).
		"licenses_issued_has_expiry": `(expiry_basis)::text <> 'from_issue'::text OR num_nonnulls(duration_months, duration_seconds) = 0 OR expires_at IS NOT NULL`,
		// Site licenses have no activations, so their term can't start at first activation,
		// and an activation limit means nothing for them.
		"licenses_site_starts_at_issue":   `(bind_type)::text <> 'none'::text OR (expiry_basis)::text <> 'from_first_activation'::text`,
		"licenses_site_no_activation_max": `(bind_type)::text <> 'none'::text OR max_activations IS NULL`,
		// Limits are integers written without a fraction or exponent (1.0 is malformed in the spec
		// and doesn't decode into int64), and limit names are feature keys.
		"licenses_ent_limit_ints": `NOT jsonb_path_exists(entitlements, 'strict $."limits".*?(@.string() like_regex "[.eE]")'::jsonpath)`,
		"licenses_ent_limit_keys": `NOT jsonb_path_exists(entitlements, 'strict $."limits".keyvalue()?(!(@."key" like_regex "` + keyPattern + `"))'::jsonpath)`,
		// Status and its timestamps agree.
		"licenses_suspended_at": `(status = 'suspended') = (suspended_at IS NOT NULL)`,
		"licenses_revoked_at":   `(status = 'revoked') = (revoked_at IS NOT NULL)`,
	}}}
}

func (License) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "key_lookup").Unique(), // per tenant: a global index would reveal keys across tenants
		index.Fields("tenant_id", "id").Unique(),
		index.Fields("tenant_id", "id", "bind_type").Unique(), // activations: binding must match the license
		index.Fields("tenant_id", "customer_id"),
	}
}
