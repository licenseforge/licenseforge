-- lf:no-transaction
-- Create index "auditevent_platform_denied" to table: "audit_events",
-- concurrently so audited writes keep going while it builds (ADR-0042).
CREATE INDEX CONCURRENTLY "auditevent_platform_denied" ON "audit_events" ("tenant_id", "object_id") WHERE ((action)::text = 'session.platform_denied'::text);
