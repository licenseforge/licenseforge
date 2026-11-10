package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/webhooks"
)

// Webhook endpoints (ADR-0044). The service checks webhook:read/write and
// tenant-wide scope; handlers translate.

func webhookView(e webhooks.Endpoint) apigen.Webhook {
	events := make([]apigen.WebhookEventType, len(e.Events))
	for i, ev := range e.Events {
		events[i] = apigen.WebhookEventType(ev)
	}
	var reason *string
	if e.DisabledReason != "" {
		reason = &e.DisabledReason
	}
	var next = e.NextAttemptAt
	if next != nil {
		t := next.UTC()
		next = &t
	}
	return apigen.Webhook{Id: e.ID, Url: e.URL, Events: events, Enabled: e.Enabled, DisabledReason: reason,
		CreatedAt: e.CreatedAt.UTC(), UpdatedAt: e.UpdatedAt.UTC(),
		Delivery: apigen.WebhookDeliveryState{Seq: e.Seq, Attempts: e.Attempts, NextAttemptAt: next, InFlight: e.InFlight, NextSeq: nextSeq(e.NextSeq)}}
}

func nextSeq(n int64) *int64 {
	if n == 0 {
		return nil
	}
	return &n
}

func webhookCreated(e webhooks.Endpoint, secret string) apigen.WebhookCreated {
	v := webhookView(e)
	return apigen.WebhookCreated{Id: v.Id, Url: v.Url, Events: v.Events, Enabled: v.Enabled, DisabledReason: v.DisabledReason,
		CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, Delivery: v.Delivery, Secret: secret}
}

func eventNames(es []apigen.WebhookEventType) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = string(e)
	}
	return out
}

func (s *server) ListWebhooks(ctx context.Context, _ apigen.ListWebhooksRequestObject) (apigen.ListWebhooksResponseObject, error) {
	es, err := s.Webhooks.List(ctx)
	if err != nil {
		return nil, err
	}
	out := apigen.ListWebhooks200JSONResponse{Items: []apigen.Webhook{}}
	for _, e := range es {
		out.Items = append(out.Items, webhookView(e))
	}
	return out, nil
}

func (s *server) CreateWebhook(ctx context.Context, req apigen.CreateWebhookRequestObject) (apigen.CreateWebhookResponseObject, error) {
	c, err := s.Webhooks.Create(ctx, req.Body.Url, eventNames(req.Body.Events))
	if err != nil {
		return nil, err
	}
	return apigen.CreateWebhook201JSONResponse(webhookCreated(c.Endpoint, c.Secret)), nil
}

func (s *server) GetWebhook(ctx context.Context, req apigen.GetWebhookRequestObject) (apigen.GetWebhookResponseObject, error) {
	e, err := s.Webhooks.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.GetWebhook200JSONResponse(webhookView(e)), nil
}

func (s *server) UpdateWebhook(ctx context.Context, req apigen.UpdateWebhookRequestObject) (apigen.UpdateWebhookResponseObject, error) {
	var events []string
	if req.Body.Events != nil {
		events = eventNames(*req.Body.Events)
	}
	e, err := s.Webhooks.Update(ctx, req.Id, req.Body.Url, events, nulls(ctx, "url", "events")...)
	if err != nil {
		return nil, err
	}
	return apigen.UpdateWebhook200JSONResponse(webhookView(e)), nil
}

func (s *server) DeleteWebhook(ctx context.Context, req apigen.DeleteWebhookRequestObject) (apigen.DeleteWebhookResponseObject, error) {
	if err := s.Webhooks.Delete(ctx, req.Id); err != nil {
		return nil, err
	}
	return apigen.DeleteWebhook204Response{}, nil
}

func (s *server) RotateWebhookSecret(ctx context.Context, req apigen.RotateWebhookSecretRequestObject) (apigen.RotateWebhookSecretResponseObject, error) {
	e, secret, err := s.Webhooks.RotateSecret(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.RotateWebhookSecret200JSONResponse(webhookCreated(e, secret)), nil
}

func (s *server) DisableWebhook(ctx context.Context, req apigen.DisableWebhookRequestObject) (apigen.DisableWebhookResponseObject, error) {
	e, err := s.Webhooks.Disable(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.DisableWebhook200JSONResponse(webhookView(e)), nil
}

func (s *server) EnableWebhook(ctx context.Context, req apigen.EnableWebhookRequestObject) (apigen.EnableWebhookResponseObject, error) {
	e, err := s.Webhooks.Enable(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.EnableWebhook200JSONResponse(webhookView(e)), nil
}

func (s *server) SkipWebhookEvent(ctx context.Context, req apigen.SkipWebhookEventRequestObject) (apigen.SkipWebhookEventResponseObject, error) {
	e, err := s.Webhooks.SkipEvent(ctx, req.Id, req.Body.Seq) // seq checked after not found and denied (ADR-0032)
	if err != nil {
		return nil, err
	}
	return apigen.SkipWebhookEvent200JSONResponse(webhookView(e)), nil
}

func (s *server) SkipWebhookToNow(ctx context.Context, req apigen.SkipWebhookToNowRequestObject) (apigen.SkipWebhookToNowResponseObject, error) {
	e, err := s.Webhooks.SkipToNow(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.SkipWebhookToNow200JSONResponse(webhookView(e)), nil
}

func (s *server) ListWebhookDeliveries(ctx context.Context, req apigen.ListWebhookDeliveriesRequestObject) (apigen.ListWebhookDeliveriesResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "whd")
	if err != nil {
		return nil, err
	}
	ds, err := s.Webhooks.Deliveries(ctx, req.Id, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListWebhookDeliveries200JSONResponse{Items: []apigen.WebhookDelivery{}}
	for i, d := range ds {
		if i == limit {
			c := encodeCursor(ds[i-1].AttemptedAt, ds[i-1].ID)
			page.NextCursor = &c
			break
		}
		outcome, msg := apigen.WebhookDeliveryOutcome("failure"), deliveryError(d)
		if d.Success {
			outcome, msg = "success", nil
		}
		page.Items = append(page.Items, apigen.WebhookDelivery{Id: d.ID, Seq: d.Seq, EventId: d.EventID, EventType: apigen.WebhookEventType(d.EventType),
			Attempt: d.Attempt, Outcome: outcome, Error: msg, StatusCode: d.StatusCode, DurationMs: int(d.Duration.Milliseconds()), AttemptedAt: d.AttemptedAt.UTC()})
	}
	return page, nil
}

// deliveryError is a failed attempt in the delivery log's fixed words.
func deliveryError(d webhooks.Delivery) *string {
	var s string
	switch d.Category {
	case "http":
		s = "http"
		if d.StatusCode != nil { // always set for http (a CHECK)
			s += " " + strconv.Itoa(*d.StatusCode)
		}
	case "connection":
		s = "connection failed"
	default: // timeout, tls, redirect
		s = d.Category
	}
	return &s
}

// webhookProblem maps the webhook service's refusals.
func webhookProblem(err error) *problem {
	var inv *webhooks.InvalidError
	switch {
	case errors.As(err, &inv):
		return invalid(fieldError{inv.Field, inv.Message})
	case errors.Is(err, webhooks.ErrNotFound):
		return errNotFound
	case errors.Is(err, webhooks.ErrLimit):
		return &problem{status: http.StatusConflict, code: "webhook_limit_reached", detail: "The tenant already has the most webhook endpoints allowed (10)."}
	case errors.Is(err, webhooks.ErrState):
		return &problem{status: http.StatusConflict, code: "invalid_state", detail: "The endpoint's state doesn't allow this (already disabled, not disabled, or not the event held back)."}
	}
	return nil
}
