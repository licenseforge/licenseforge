-- Create index "auditevent_tenant_id_object_id" to table: "audit_events"
CREATE INDEX "auditevent_tenant_id_object_id" ON "audit_events" ("tenant_id", "object_id") WHERE ((action)::text = 'session.mfa_required'::text);
