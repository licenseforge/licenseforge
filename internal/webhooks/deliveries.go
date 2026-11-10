package webhooks

import (
	"context"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/webhookdelivery"
	"licenseforge.io/licenseforge/internal/store/ent/webhookendpoint"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Delivery is one recorded attempt (the delivery log, kept DeliveryRetention).
type Delivery struct {
	ID          string
	Seq         int64
	EventID     string // the audit entry: webhook-id
	EventType   string
	Attempt     int
	Success     bool
	Category    string // http, timeout, connection, tls, redirect
	StatusCode  *int   // http only
	Duration    time.Duration
	AttemptedAt time.Time
}

// Deliveries returns up to limit of an endpoint's delivery records, newest
// first, after the one at (afterAt, afterID) or from the newest if afterID
// is "". The caller needs webhook:read (tenant-wide); an endpoint it can't
// see is ErrNotFound.
func (s Service) Deliveries(ctx context.Context, id string, limit int, afterAt time.Time, afterID string) ([]Delivery, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	if authz.Require(ctx, authz.WebhookRead, "") != nil || !ids.Valid("whe", id) {
		return nil, ErrNotFound
	}
	if limit < 1 {
		return nil, &InvalidError{"/limit", "at least 1"}
	}
	var out []Delivery
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		if ok, err := tx.WebhookEndpoint.Query().Where(webhookendpoint.ID(id)).Exist(ctx); err != nil || !ok {
			if err == nil {
				err = ErrNotFound
			}
			return err
		}
		q := tx.WebhookDelivery.Query().Where(webhookdelivery.EndpointID(id)).
			Order(ent.Desc(webhookdelivery.FieldAttemptedAt), ent.Desc(webhookdelivery.FieldID)).Limit(limit)
		if afterID != "" {
			q.Where(webhookdelivery.Or(webhookdelivery.AttemptedAtLT(afterAt),
				webhookdelivery.And(webhookdelivery.AttemptedAt(afterAt), webhookdelivery.IDLT(afterID))))
		}
		rows, err := q.All(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, Delivery{ID: r.ID, Seq: r.Seq, EventID: r.EventID, EventType: string(r.EventType), Attempt: r.Attempt,
				Success: r.Outcome == webhookdelivery.OutcomeSuccess, Category: string(r.Category), StatusCode: r.StatusCode,
				Duration: time.Duration(r.DurationMs) * time.Millisecond, AttemptedAt: r.AttemptedAt})
		}
		return nil
	})
	return out, err
}
