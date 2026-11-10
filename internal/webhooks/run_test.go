package webhooks

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Run delivers with its workers, counts the attempt, and stops with ctx.
func TestRun(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	before := testutil.ToFloat64(metrics.WebhookDeliveries.WithLabelValues("success"))
	seq := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() { f.d.Run(ctx, 2); close(done) }()
	waitFor(t, "the delivery", func() bool { s, _, _, _ := f.cursor(t, c.ID); return s == seq })
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run didn't stop with its context")
	}
	if got := testutil.ToFloat64(metrics.WebhookDeliveries.WithLabelValues("success")); got != before+1 {
		t.Errorf("success counter %v, want %v", got, before+1)
	}
	// A failure counts as one.
	failed := testutil.ToFloat64(metrics.WebhookDeliveries.WithLabelValues("failure"))
	f.recv.status = 500
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.once(t)
	if got := testutil.ToFloat64(metrics.WebhookDeliveries.WithLabelValues("failure")); got != failed+1 {
		t.Errorf("failure counter %v, want %v", got, failed+1)
	}
}

// Delivery records older than DeliveryRetention go, in batches; newer ones
// stay.
func TestPrune(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	f.platformExec(t, `INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome, category, duration_ms, attempted_at)
		SELECT 'whd_' || translate(substr(md5(g::text), 1, 26), '0189', 'wxyz'), $1, $2, 1, $3, 'license.issued', 1, 'failure', 'timeout', 1, now() - interval '8 days'
		FROM generate_series(1, 5001) g`, f.a, c.ID, ids.AuditEvent())
	for _, age := range []string{"6 days", "1 minute"} {
		f.platformExec(t, `INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome, category, duration_ms, attempted_at)
			VALUES ($1, $2, $3, 1, $4, 'license.issued', 1, 'failure', 'timeout', 1, now() - $5::interval)`, ids.WebhookDelivery(), f.a, c.ID, ids.AuditEvent(), age)
	}
	if n, err := f.d.Prune(f.ctx); err != nil || n != 5001 {
		t.Fatalf("Prune = %d, %v", n, err)
	}
	if d := f.deliveries(t, c.ID); len(d) != 2 {
		t.Errorf("%d records left, want 2", len(d))
	}
}

// The lag gauges measure enabled endpoints only, from the oldest entry
// after the cursor; the disabled gauge counts the dispatcher's disables,
// not users'.
func TestGauges(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	seq := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.record(t, f.a, "license.revoke", auditevent.OutcomeSuccess, nil)
	_ = seq
	// Everything after the cursor (its own webhook.create entry, then two) an hour old.
	f.platformExecOwner(t, `UPDATE audit_events SET occurred_at = now() - interval '1 hour' WHERE tenant_id = $1 AND seq > $2`, f.a, c.Seq)
	f.platformExecOwner(t, `UPDATE audit_events SET occurred_at = now() - interval '2 hours' WHERE tenant_id = $1 AND seq = $2`, f.a, c.Seq+1) // the oldest pending
	if err := f.d.gauges(f.ctx); err != nil {
		t.Fatal(err)
	}
	if lag, behind := testutil.ToFloat64(metrics.WebhookLag), testutil.ToFloat64(metrics.WebhookLagEvents); lag < 7100 || behind != 3 {
		t.Errorf("lag %v s, %v entries; want about two hours (the oldest) and 3", lag, behind)
	}
	before := testutil.ToFloat64(metrics.WebhookDisabled)
	if _, err := f.s.Disable(f.ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.d.gauges(f.ctx); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(metrics.WebhookDisabled) != before {
		t.Error("a user's disable counted")
	}
	if lag := testutil.ToFloat64(metrics.WebhookLag); lag > 60 {
		t.Errorf("a disabled endpoint's backlog counted: %v", lag)
	}
	f.platformExec(t, `UPDATE webhook_endpoints SET disabled_reason = $2 WHERE id = $1`, c.ID, ReasonFailing)
	if err := f.d.gauges(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.WebhookDisabled); got != before+1 {
		t.Errorf("disabled gauge %v, want %v", got, before+1)
	}
}
