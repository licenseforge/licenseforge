package webhooks

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store/ent"
)

// DeliveryRetention is how long delivery records are kept (ADR-0044).
const DeliveryRetention = 7 * 24 * time.Hour

// idle is how long a worker waits when nothing was due (or a round failed).
const idle = 2 * time.Second

// Run delivers with workers goroutines until ctx is done, and keeps the
// delivery log pruned and the gauges current. Errors are logged and counted;
// an endpoint's own failures are attempts, not errors.
func (d *Dispatcher) Run(ctx context.Context, workers int) {
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() { d.work(ctx) })
	}
	wg.Go(func() { d.housekeep(ctx) })
	wg.Wait()
}

func (d *Dispatcher) work(ctx context.Context) {
	for ctx.Err() == nil {
		worked, err := d.Once(ctx)
		if err != nil && ctx.Err() == nil {
			metrics.WebhookErrors.Inc()
			d.Log.Error("webhook dispatch", "err", err)
		}
		if worked && err == nil {
			continue
		}
		pause := idle + time.Duration(rand.Int64N(int64(idle))) // replicas drift apart
		select {
		case <-ctx.Done():
		case <-time.After(pause):
		}
	}
}

func (d *Dispatcher) housekeep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var lastPrune time.Time
	for {
		if time.Since(lastPrune) >= time.Hour {
			if n, err := d.Prune(ctx); err != nil && ctx.Err() == nil {
				d.Log.Error("webhook delivery log pruning", "err", err)
			} else if n > 0 {
				d.Log.Info("webhook delivery log pruned", "records", n)
			}
			lastPrune = time.Now()
		}
		if err := d.gauges(ctx); err != nil && ctx.Err() == nil {
			d.Log.Error("webhook metrics", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Prune deletes delivery records older than DeliveryRetention, in batches,
// and returns how many.
func (d *Dispatcher) Prune(ctx context.Context) (int64, error) {
	var total int64
	for {
		var n int64
		err := d.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
			res, err := tx.ExecContext(ctx, `DELETE FROM webhook_deliveries WHERE id IN (SELECT id FROM webhook_deliveries
				WHERE attempted_at < clock_timestamp() - make_interval(secs => $1) LIMIT 5000)`, DeliveryRetention.Seconds())
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		total += n
		if err != nil || n < 5000 {
			return total, err
		}
	}
}

// gauges sets the disabled-endpoint count and the maximum lag.
func (d *Dispatcher) gauges(ctx context.Context) error {
	return d.DB.ReadPlatform(ctx, false, func(tx *ent.Tx) error {
		var disabled int64
		var lag float64
		if _, err := scan(ctx, tx, `SELECT count(*) FROM webhook_endpoints WHERE NOT enabled`, nil, &disabled); err != nil {
			return err
		}
		if _, err := scan(ctx, tx, `SELECT COALESCE(max(EXTRACT(EPOCH FROM clock_timestamp() - e.occurred_at)), 0)::float8
			FROM webhook_cursors c JOIN webhook_endpoints w ON w.id = c.endpoint_id AND w.enabled
			JOIN audit_events e ON e.tenant_id = c.tenant_id AND e.seq = c.seq + 1`, nil, &lag); err != nil {
			return err
		}
		metrics.WebhookDisabled.Set(float64(disabled))
		metrics.WebhookLag.Set(lag)
		return nil
	})
}
