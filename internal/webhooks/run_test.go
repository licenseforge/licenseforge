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
}

// Delivery records older than DeliveryRetention go; newer ones stay. The
// gauges count disabled endpoints and the lag.
func TestPruneAndGauges(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	for _, age := range []string{"8 days", "6 days", "1 minute"} {
		f.platformExec(t, `INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome, category, duration_ms, attempted_at)
			VALUES ($1, $2, $3, 1, $4, 'license.issued', 1, 'failure', 'timeout', 1, now() - $5::interval)`, ids.WebhookDelivery(), f.a, c.ID, ids.AuditEvent(), age)
	}
	n, err := f.d.Prune(f.ctx)
	if err != nil || n < 1 {
		t.Fatalf("Prune = %d, %v", n, err)
	}
	if d := f.deliveries(t, c.ID); len(d) != 2 {
		t.Errorf("%d records left, want 2", len(d))
	}
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails) // pending: lag
	if err := f.d.gauges(f.ctx); err != nil {
		t.Fatal(err)
	}
	if lag := testutil.ToFloat64(metrics.WebhookLag); lag < 0 {
		t.Errorf("lag %v", lag)
	}
	disabledBefore := testutil.ToFloat64(metrics.WebhookDisabled)
	if _, err := f.s.Disable(f.ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.d.gauges(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.WebhookDisabled); got != disabledBefore+1 {
		t.Errorf("disabled gauge %v, want %v", got, disabledBefore+1)
	}
}
