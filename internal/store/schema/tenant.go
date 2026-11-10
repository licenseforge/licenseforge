package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"

	"licenseforge.io/licenseforge/internal/store/ids"
)

// Tenant is a vendor using LicenseForge (ADR-0009).
type Tenant struct{ ent.Schema }

func (Tenant) Mixin() []ent.Mixin { return []ent.Mixin{Timestamps{}} }

func (Tenant) Fields() []ent.Field {
	return []ent.Field{
		prefixedID(ids.Tenant),
		field.String("slug").Unique().NotEmpty().MaxLen(63).Match(SlugRE).SchemaType(slugType),
		field.String("name").NotEmpty().MaxLen(200).Validate(notBlank).SchemaType(nameType),
		// Audit retention in days (ADR-0036); nil keeps everything. 365 (the
		// database's floor) to 36,500; set by owners only (retention.SetTenantRetention).
		field.Int("audit_retention_days").Optional().Nillable(),
		// The assurance a session needs to act in the tenant (ADR-0038).
		field.Enum("mfa_policy").Values(assuranceLevels...).Default("none"),
		// Test mode (ADR-0047): set at creation, never changed (a restrictive
		// policy for the platform pool; no grant to the serving login).
		field.Bool("test").Default(false).Immutable(),
	}
}

func (Tenant) Annotations() []schema.Annotation {
	return []schema.Annotation{entsql.Annotation{Checks: map[string]string{
		"tenants_id_format":       `id ~ '^tnt_` + idChars + `$'`,
		"tenants_slug_format":     `slug ~ '` + slugPattern + `'`,
		"tenants_name_not_blank":  `btrim(name) <> ''`,
		"tenants_audit_retention": `audit_retention_days IS NULL OR (audit_retention_days >= 365 AND audit_retention_days <= 36500)`,
		"tenants_mfa_policy":      enumCheck("mfa_policy", assuranceLevels),
	}}}
}

func (Tenant) Edges() []ent.Edge {
	return []ent.Edge{edge.To("products", Product.Type), edge.To("customers", Customer.Type), edge.To("signing_keys", SigningKey.Type),
		edge.To("audit_events", AuditEvent.Type), edge.To("invitations", Invitation.Type), edge.To("memberships", Membership.Type), edge.To("api_tokens", APIToken.Type),
		edge.To("idempotency_keys", IdempotencyKey.Type), edge.To("audit_export_cursors", AuditExportCursor.Type),
		edge.To("audit_anchors", AuditAnchor.Type), edge.To("webhook_endpoints", WebhookEndpoint.Type),
		edge.To("webhook_cursors", WebhookCursor.Type), edge.To("webhook_deliveries", WebhookDelivery.Type)}
}
