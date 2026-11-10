package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"time"

	crand "crypto/rand"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/schema"
)

// Delivery (ADR-0044). A dispatcher on every replica (platform pool) claims
// one due endpoint at a time, at random, at most 2 per tenant across the
// cluster; sends its next event outside any transaction; then writes the
// result only if it still holds the lease and the cursor's seq and attempts
// are what it claimed (a tenant's skip, re-enable or delete meanwhile makes
// it miss). At-least-once, in order per endpoint.

// schedule is the pause after the nth failure of an event (Svix's
// production schedule); the next failure after the last disables.
var schedule = []time.Duration{5 * time.Second, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 5 * time.Hour, 10 * time.Hour, 10 * time.Hour}

// Reasons a dispatcher disables an endpoint (fixed words: tenants see them).
const (
	ReasonFailing  = "deliveries failed for about 28 hours"
	ReasonGone     = "the receiver answered 410 Gone"
	ReasonSecret   = "the signing secret can't be read: rotate it"
	ReasonURL      = "the URL can't be read: update it"
	maxLeasesPerTn = 2
)

// Dispatcher delivers webhooks from one replica.
type Dispatcher struct {
	DB      *store.DB
	Keys    *secrets.Keyring
	Client  *http.Client
	Lease   time.Duration // a claim's lifetime: above the client's whole attempt
	Log     *slog.Logger
	replica string
}

// NewDispatcher returns a Dispatcher with ADR-0044's defaults.
func NewDispatcher(db *store.DB, keys *secrets.Keyring, client *http.Client, log *slog.Logger) *Dispatcher {
	host, _ := os.Hostname()
	return &Dispatcher{DB: db, Keys: keys, Client: client, Lease: 3 * Timeout, Log: log, replica: host + "/" + crand.Text()[:8]}
}

type claim struct {
	cursorID, tenantID, endpointID string
	seq                            int64 // the cursor as claimed: the result write is pinned to it
	attempts                       int
	event                          *ent.AuditEvent
	eventType                      string
	urlC, secretC, previousC       []byte
	claimedAt                      time.Time
}

// Once claims one due endpoint and delivers its next event. It reports
// whether there was anything to do (a claim, or a cursor moved past entries
// that aren't its events).
func (d *Dispatcher) Once(ctx context.Context) (bool, error) {
	c, worked, err := d.claim(ctx)
	if err != nil || c == nil {
		return worked, err
	}
	// The result is written even if ctx ends meanwhile, briefly.
	done, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	url, err := d.decrypt(secrets.PurposeWebhookURL, c, c.urlC)
	if err != nil {
		return true, d.disable(done, c, ReasonURL)
	}
	secs := make([]string, 0, 2)
	cur, err := d.decrypt(secrets.PurposeWebhookSecret, c, c.secretC)
	if err != nil {
		return true, d.disable(done, c, ReasonSecret)
	}
	secs = append(secs, cur)
	if c.previousC != nil {
		if prev, err := d.decrypt(secrets.PurposeWebhookPrevious, c, c.previousC); err == nil {
			secs = append(secs, prev)
		}
	}
	body, err := Payload(c.eventType, c.event)
	if err != nil {
		return true, errors.Join(err, d.release(done, c))
	}
	sendCtx, stop := context.WithDeadline(ctx, c.claimedAt.Add(d.Lease/2))
	a, err := Send(sendCtx, d.Client, url, c.event.ID, time.Now(), body, secs...)
	stop()
	if err != nil { // cancelled (shutting down): no attempt
		return true, errors.Join(err, d.release(done, c))
	}
	return true, d.result(done, c, a)
}

func (d *Dispatcher) decrypt(p secrets.Purpose, c *claim, ct []byte) (string, error) {
	b, err := d.Keys.Decrypt(string(ct), secrets.Binding{Purpose: p, TenantID: c.tenantID, RowID: c.endpointID})
	return string(b), err
}

// claim leases one due endpoint, after moving its cursor past entries that
// aren't its events (and past a retention cut). nil: nothing to send.
func (d *Dispatcher) claim(ctx context.Context) (out *claim, worked bool, err error) {
	start := time.Now()
	err = d.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		c := &claim{claimedAt: start}
		var events []string
		var eventsJSON string
		found, err := scan(ctx, tx, `SELECT c.id, c.tenant_id, c.endpoint_id, c.seq, c.attempts, e.events::text
			FROM webhook_cursors c JOIN webhook_endpoints e ON e.id = c.endpoint_id
			WHERE e.enabled AND (c.next_attempt_at IS NULL OR c.next_attempt_at <= clock_timestamp())
			  AND (c.claimed_until IS NULL OR c.claimed_until < clock_timestamp())
			  AND EXISTS (SELECT 1 FROM audit_events a WHERE a.tenant_id = c.tenant_id AND a.seq > c.seq)
			  AND (SELECT count(*) FROM webhook_cursors l WHERE l.tenant_id = c.tenant_id AND l.claimed_until > clock_timestamp()) < $1
			ORDER BY random() LIMIT 1 FOR UPDATE OF c SKIP LOCKED`, []any{maxLeasesPerTn},
			&c.cursorID, &c.tenantID, &c.endpointID, &c.seq, &c.attempts, &eventsJSON)
		if err != nil || !found {
			return err
		}
		if err := json.Unmarshal([]byte(eventsJSON), &events); err != nil {
			return err
		}
		// At most maxLeasesPerTn per tenant: concurrent claims take turns
		// here (its own key, not the audit lock's) before counting.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('licenseforge.webhook:' || $1, 0))`, c.tenantID); err != nil {
			return err
		}
		var leased int
		if _, err := scan(ctx, tx, `SELECT count(*) FROM webhook_cursors WHERE tenant_id = $1 AND claimed_until > clock_timestamp()`,
			[]any{c.tenantID}, &leased); err != nil || leased >= maxLeasesPerTn {
			return err
		}
		worked = true
		// Entries after the cursor pruned by retention: move to the cut, and
		// say so (which of them were events can't be known any more).
		var anchor int64
		if _, err := scan(ctx, tx, `SELECT COALESCE(max(seq), 0) FROM audit_anchors WHERE tenant_id = $1`, []any{c.tenantID}, &anchor); err != nil {
			return err
		}
		if anchor > c.seq {
			if err := move(ctx, tx, c, anchor); err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, c.tenantID, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "webhook.pruned_skip",
				ObjectType: "webhook_endpoint", ObjectID: c.endpointID, Outcome: auditevent.OutcomeSuccess,
				Details: map[string]any{"from_seq": c.seq, "to_seq": anchor}}); err != nil {
				return err
			}
			c.seq = anchor
		}
		next, err := nextEvent(ctx, tx, c.tenantID, c.seq, events)
		if err != nil {
			return err
		}
		if next == 0 { // nothing it subscribes to: pass everything so far
			var head int64
			if _, err := scan(ctx, tx, `SELECT COALESCE(max(seq), 0) FROM audit_events WHERE tenant_id = $1`, []any{c.tenantID}, &head); err != nil {
				return err
			}
			return move(ctx, tx, c, head)
		}
		if next-1 > c.seq {
			if err := move(ctx, tx, c, next-1); err != nil {
				return err
			}
			c.seq = next - 1
		}
		if _, err := tx.ExecContext(ctx, `UPDATE webhook_cursors SET claimed_by = $2, claimed_until = clock_timestamp() + make_interval(secs => $3)
			WHERE id = $1`, c.cursorID, d.replica, d.Lease.Seconds()); err != nil {
			return err
		}
		if c.event, err = tx.AuditEvent.Query().Where(auditevent.TenantID(c.tenantID), auditevent.Seq(next)).Only(ctx); err != nil {
			return err
		}
		c.eventType = EventType(c.event.Action, c.event.Details)
		var current bool // the previous secret still signs (within PreviousSecretTTL)
		if _, err := scan(ctx, tx, `SELECT url_ciphertext, secret_ciphertext, previous_secret_ciphertext,
			COALESCE(previous_secret_until > clock_timestamp(), false) FROM webhook_endpoints WHERE id = $1`,
			[]any{c.endpointID}, &c.urlC, &c.secretC, &c.previousC, &current); err != nil {
			return err
		}
		if !current {
			c.previousC = nil
		}
		out = c
		return nil
	})
	if err != nil {
		return nil, worked, err
	}
	return out, worked, nil
}

// move sets the cursor's seq forward (never back: the policy refuses).
func move(ctx context.Context, tx *ent.Tx, c *claim, seq int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE webhook_cursors SET seq = $2 WHERE id = $1`, c.cursorID, seq)
	return err
}

// pinned is the WHERE of every result write: this replica's lease, the
// cursor as claimed.
const pinned = `id = $1 AND claimed_by = $2 AND seq = $3 AND attempts = $4`

// result records an attempt: on success the cursor passes the event; on
// failure the retry state, and after the last failure (or a 410) the
// endpoint is disabled. Nothing is written if the claim was overtaken.
func (d *Dispatcher) result(ctx context.Context, c *claim, a Attempt) error {
	return d.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		var res interface{ RowsAffected() (int64, error) }
		var err error
		failed := c.attempts + 1
		disable := ""
		if a.OK() {
			res, err = tx.ExecContext(ctx, `UPDATE webhook_cursors SET seq = $5, attempts = 0, next_attempt_at = NULL, claimed_by = NULL, claimed_until = NULL
				WHERE `+pinned, c.cursorID, d.replica, c.seq, c.attempts, c.event.Seq)
		} else {
			if a.Category == "http" && a.Status == http.StatusGone {
				disable = ReasonGone
			} else if failed >= schema.WebhookMaxAttempts {
				disable = ReasonFailing
			}
			res, err = tx.ExecContext(ctx, `UPDATE webhook_cursors SET attempts = attempts + 1,
				next_attempt_at = clock_timestamp() + make_interval(secs => $5), claimed_by = NULL, claimed_until = NULL
				WHERE `+pinned, c.cursorID, d.replica, c.seq, c.attempts, retryDelay(failed, a.RetryAfter).Seconds())
		}
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return err // overtaken (a skip, re-enable or delete, or the lease ran out): nothing to record
		}
		outcome := "failure"
		if a.OK() {
			outcome = "success"
		}
		var status any
		if a.Category == "http" {
			status = a.Status
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome,
			category, status_code, duration_ms, attempted_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, clock_timestamp())`,
			ids.WebhookDelivery(), c.tenantID, c.endpointID, c.event.Seq, c.event.ID, c.eventType, failed, outcome,
			a.Category, status, a.Duration.Milliseconds()); err != nil {
			return err
		}
		if disable != "" {
			return disableTx(ctx, tx, c, disable)
		}
		return nil
	})
}

// retryDelay is the pause after the nth failure, with jitter (±10%), never
// sooner than the receiver's Retry-After.
func retryDelay(failed int, retryAfter time.Duration) time.Duration {
	base := schedule[min(failed, len(schedule))-1]
	jittered := base + time.Duration((rand.Float64()*0.2-0.1)*float64(base))
	return max(jittered, retryAfter)
}

// disable disables the endpoint (a claim it can't deliver at all).
func (d *Dispatcher) disable(ctx context.Context, c *claim, reason string) error {
	return d.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE webhook_cursors SET claimed_by = NULL, claimed_until = NULL WHERE `+pinned,
			c.cursorID, d.replica, c.seq, c.attempts)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return err
		}
		return disableTx(ctx, tx, c, reason)
	})
}

// disableTx disables an enabled endpoint (never overwriting a user's
// disable) and audits it on the tenant's chain.
func disableTx(ctx context.Context, tx *ent.Tx, c *claim, reason string) error {
	res, err := tx.ExecContext(ctx, `UPDATE webhook_endpoints SET enabled = false, disabled_reason = $2, updated_at = clock_timestamp()
		WHERE id = $1 AND enabled`, c.endpointID, reason)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return err
	}
	_, err = audit.Record(ctx, tx, c.tenantID, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "webhook.disable",
		ObjectType: "webhook_endpoint", ObjectID: c.endpointID, Outcome: auditevent.OutcomeSuccess,
		Details: map[string]any{"reason": reason, "seq": c.event.Seq}})
	return err
}

// release frees the claim without recording an attempt.
func (d *Dispatcher) release(ctx context.Context, c *claim) error {
	return d.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE webhook_cursors SET claimed_by = NULL, claimed_until = NULL WHERE `+pinned,
			c.cursorID, d.replica, c.seq, c.attempts)
		return err
	})
}

// scan runs a one-row query; false if there was no row.
func scan(ctx context.Context, tx *ent.Tx, q string, args []any, dst ...any) (bool, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return false, rows.Err()
	}
	return true, errors.Join(rows.Scan(dst...), rows.Err())
}

// Payload is an event's body (ADR-0044): type, the time it happened, and
// the event's documented fields, from the audit entry alone.
func Payload(eventType string, e *ent.AuditEvent) ([]byte, error) {
	var d map[string]any
	if err := json.Unmarshal([]byte(e.Details), &d); err != nil {
		return nil, err
	}
	obj := ""
	if e.ObjectID != nil {
		obj = *e.ObjectID
	}
	var data map[string]any
	switch eventType {
	case "license.issued", "license.revoked", "license.suspended", "license.reinstated":
		status := d["to"]
		if e.Action == "license.issue" {
			status = "active"
		}
		data = map[string]any{"license_id": obj, "product_id": d["product_id"], "customer_id": d["customer_id"],
			"plan": d["plan_slug"], "status": status, "expires_at": d["expires_at"]}
	case "activation.created", "activation.deactivated":
		data = map[string]any{"activation_id": obj, "license_id": d["license_id"], "product_id": d["product_id"],
			"customer_id": d["customer_id"], "fingerprint": d["fingerprint"], "binding": d["binding"], "mode": d["mode"]}
	default:
		return nil, fmt.Errorf("webhooks: no payload for %q", eventType)
	}
	return json.Marshal(map[string]any{"type": eventType, "timestamp": e.OccurredAt.UTC().Format(time.RFC3339Nano), "data": data})
}
