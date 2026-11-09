package schema

import (
	"strconv"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"

	"licenseforge.io/licenseforge/internal/store/ids"
)

// WebhookMaxAttempts bounds a cursor's failed attempts for its next event
// (ADR-0044: the first try and seven retries); the dispatcher disables the
// endpoint instead of going past it.
const WebhookMaxAttempts = 8

var (
	deliveryOutcomes = []string{"success", "failure"}
	// deliveryCategories are the only words a delivery log shows (ADR-0044):
	// never an address, so tenants can't probe the network. http carries the
	// status code; a blocked address is "connection".
	deliveryCategories = []string{"http", "timeout", "connection", "tls", "redirect"}
	// webhookEvents is the event catalog (ADR-0044).
	webhookEvents = []string{"license.issued", "license.revoked", "license.suspended", "license.reinstated",
		"activation.created", "activation.deactivated"}
)

// namedEvents pairs each event with a Go name: license.issued, LicenseIssued.
func namedEvents() []string {
	var out []string
	for _, e := range webhookEvents {
		name := ""
		for _, part := range strings.FieldsFunc(e, func(r rune) bool { return r == '.' }) {
			name += strings.ToUpper(part[:1]) + part[1:]
		}
		out = append(out, name, e)
	}
	return out
}

// jsonStringArray renders values as a jsonb array literal for CHECKs.
func jsonStringArray(values []string) string {
	return `'["` + strings.Join(values, `", "`) + `"]'::jsonb`
}

// WebhookEndpoint is where a tenant's events are sent (ADR-0044). The URL
// and the signing secrets are encrypted (secrets purposes); url_display is
// what reads and audit entries show (scheme, host and port only).
type WebhookEndpoint struct{ ent.Schema }

func (WebhookEndpoint) Mixin() []ent.Mixin { return []ent.Mixin{Timestamps{}} }

// No TenantScoped mixin: its tenant_id index would duplicate the prefix of
// the unique (tenant_id, id) index.
func (WebhookEndpoint) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.WebhookEndpoint),
		field.String("tenant_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType),
		field.Bytes("url_ciphertext").NotEmpty().Sensitive(),
		field.String("url_display").NotEmpty().MaxLen(300).SchemaType(map[string]string{"postgres": "varchar(300)"}),
		field.Strings("events"),
		field.Bytes("secret_ciphertext").NotEmpty().Sensitive(),
		field.Bytes("previous_secret_ciphertext").Optional().Nillable().Sensitive(),
		field.Time("previous_secret_until").Optional().Nillable(),
		field.Bool("enabled").Default(true),
		field.String("disabled_reason").Optional().Nillable().MaxLen(200).SchemaType(map[string]string{"postgres": "varchar(200)"}),
	}
}

func (WebhookEndpoint) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("webhook_endpoints").Field("tenant_id").Unique().Required().Immutable(),
	}
}

func (WebhookEndpoint) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"webhook_endpoints_id_format": `(id)::text ~ '^whe_` + idChars + `$'::text`,
		"webhook_endpoints_events":    `(jsonb_typeof(events) = 'array'::text) AND (jsonb_array_length(events) > 0) AND (events <@ ` + jsonStringArray(webhookEvents) + `)`,
		"webhook_endpoints_previous":  `(previous_secret_ciphertext IS NULL) = (previous_secret_until IS NULL)`,
		"webhook_endpoints_disabled":  `(enabled = (disabled_reason IS NULL)) AND ((disabled_reason IS NULL) OR (btrim((disabled_reason)::text) <> ''::text))`,
	}}}
}

func (WebhookEndpoint) Indexes() []ent.Index {
	return []ent.Index{index.Fields("tenant_id", "id").Unique()} // target of same-tenant foreign keys
}

// WebhookCursor is how far one endpoint has delivered its tenant's chain
// (ADR-0044): seq is the last entry passed. The dispatcher leases it
// (claimed_by, claimed_until) to send the next event, and writes the result
// only while it still holds the lease and seq and attempts are unchanged.
// Column grants and policies (migrations) split what each login may write:
// the tenant pool can't read claimed_by or insert attempts, so it writes
// cursors with explicit-column SQL, not ent's Create/Query.
type WebhookCursor struct{ ent.Schema }

// No TenantScoped mixin: the unique (tenant_id, endpoint_id) index covers it.
func (WebhookCursor) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.WebhookCursor),
		field.String("tenant_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType),
		field.String("endpoint_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType),
		field.Int64("seq").Default(0).NonNegative(),
		field.String("claimed_by").Optional().Nillable().MaxLen(100).SchemaType(map[string]string{"postgres": "varchar(100)"}),
		field.Time("claimed_until").Optional().Nillable(),
		field.Int("attempts").Default(0).Range(0, WebhookMaxAttempts),
		field.Time("next_attempt_at").Optional().Nillable(),
	}
}

func (WebhookCursor) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("webhook_cursors").Field("tenant_id").Unique().Required().Immutable(),
	}
}

func (WebhookCursor) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"webhook_cursors_id_format": `(id)::text ~ '^whc_` + idChars + `$'::text`,
		"webhook_cursors_claim":     `(claimed_by IS NULL) = (claimed_until IS NULL)`,
		"webhook_cursors_seq":       `seq >= 0`,
		"webhook_cursors_attempts":  `(attempts >= 0) AND (attempts <= ` + strconv.Itoa(WebhookMaxAttempts) + `)`,
	}}}
}

func (WebhookCursor) Indexes() []ent.Index {
	return []ent.Index{index.Fields("tenant_id", "endpoint_id").Unique()} // endpoint IDs are unique: one cursor per endpoint
}

// WebhookDelivery records one delivery attempt (ADR-0044), for the
// dashboard's delivery log; kept 7 days. category is a fixed word
// (deliveryCategories), never an address.
type WebhookDelivery struct{ ent.Schema }

func (WebhookDelivery) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.WebhookDelivery),
		field.String("tenant_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType),
		field.String("endpoint_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType),
		field.Int64("seq").Immutable().Positive(),
		field.String("event_id").Immutable().NotEmpty().MaxLen(40).SchemaType(idType).Comment("the audit entry: webhook-id"),
		field.Enum("event_type").NamedValues(namedEvents()...).Immutable(),
		field.Int("attempt").Immutable().Range(1, WebhookMaxAttempts),
		field.Enum("outcome").Values(deliveryOutcomes...).Immutable(),
		field.Enum("category").Values(deliveryCategories...).Immutable(),
		field.Int("status_code").Optional().Nillable().Immutable(),
		field.Int("duration_ms").Immutable().NonNegative(),
		field.Time("attempted_at").Immutable().Default(time.Now),
	}
}

func (WebhookDelivery) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).Ref("webhook_deliveries").Field("tenant_id").Unique().Required().Immutable(),
	}
}

func (WebhookDelivery) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"webhook_deliveries_id_format": `(id)::text ~ '^whd_` + idChars + `$'::text`,
		"webhook_deliveries_outcome":   enumCheck("outcome", deliveryOutcomes),
		"webhook_deliveries_attempt":   `(attempt >= 1) AND (attempt <= ` + strconv.Itoa(WebhookMaxAttempts) + `)`,
		"webhook_deliveries_status":    `(status_code IS NULL) OR ((status_code >= 100) AND (status_code <= 599))`,
		"webhook_deliveries_event":     enumCheck("event_type", webhookEvents),
		"webhook_deliveries_category":  enumCheck("category", deliveryCategories),
		"webhook_deliveries_http":      `((category)::text = 'http'::text) = (status_code IS NOT NULL)`,
		"webhook_deliveries_success":   `((outcome)::text <> 'success'::text) OR ((status_code >= 200) AND (status_code <= 299))`,
		"webhook_deliveries_seq":       `seq > 0`,
		"webhook_deliveries_event_id":  `(event_id)::text ~ '^aud_` + idChars + `$'::text`,
		"webhook_deliveries_duration":  `duration_ms >= 0`,
	}}}
}

func (WebhookDelivery) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "endpoint_id", "attempted_at"), // the delivery log, newest first
		index.Fields("attempted_at"),                             // pruning, across tenants
	}
}
