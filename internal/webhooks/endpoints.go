// Package webhooks manages a tenant's outbound webhook endpoints (ADR-0044).
// URLs and signing secrets are encrypted (secrets purposes, bound to tenant
// and endpoint); reads and audit entries show only the URL's scheme, host and
// port. Every change is audited in the same transaction. The database
// enforces who may write what (webhook tables' grants and policies); this
// package works on the tenant pool.
package webhooks

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/webhookendpoint"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Events is the event catalog (ADR-0044), as the database's CHECKs list it.
var Events = []string{"license.issued", "license.revoked", "license.suspended", "license.reinstated",
	"activation.created", "activation.deactivated"}

const (
	// MaxEndpoints per tenant (ADR-0044).
	MaxEndpoints = 10
	// MaxURL is the longest URL accepted.
	MaxURL = 2048
	// PreviousSecretTTL is how long a rotated-out secret still signs.
	PreviousSecretTTL = 24 * time.Hour
)

var (
	// ErrNotFound means there is no such endpoint in the tenant.
	ErrNotFound = errors.New("webhooks: no such endpoint")
	// ErrInvalid means the request is malformed (URL, events).
	ErrInvalid = errors.New("webhooks: invalid request")
	// ErrState means the endpoint's state doesn't allow the action (enable
	// an enabled endpoint, skip an event that isn't the one held back).
	ErrState = errors.New("webhooks: the endpoint's state doesn't allow this")
	// ErrLimit means the tenant already has MaxEndpoints endpoints.
	ErrLimit = fmt.Errorf("webhooks: at most %d endpoints per tenant", MaxEndpoints)
)

// testHookRead runs in change after the endpoint is read (tests only).
var testHookRead func()

// InvalidError is a malformed request: which field (a JSON pointer into the
// request) and why, in words that never echo the URL. errors.Is(e, ErrInvalid).
type InvalidError struct{ Field, Message string }

func (e *InvalidError) Error() string        { return "webhooks: invalid " + e.Field + ": " + e.Message }
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// Service works on the tenant pool.
type Service struct {
	DB   *store.DB
	Keys *secrets.Keyring
}

// Endpoint is what a tenant sees of an endpoint: never its URL's path or
// query, never a secret, never who is delivering.
type Endpoint struct {
	ID             string
	URL            string // scheme://host:port
	Events         []string
	Enabled        bool
	DisabledReason string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	// Delivery state (ADR-0044): the last seq passed, the failed attempts on
	// the next event, when it is tried again, and whether a send is in flight.
	Seq           int64
	Attempts      int
	NextAttemptAt *time.Time
	InFlight      bool
}

// Created is a new endpoint and its signing secret, shown once.
type Created struct {
	Endpoint
	Secret string
}

// checkURL validates a receiver URL and returns what may be shown of it.
// Where it may point (addresses, ports) is checked when connecting.
func checkURL(raw string) (display string, err error) {
	bad := func(why string) (string, error) { return "", &InvalidError{"/url", why} }
	if len(raw) > MaxURL {
		return bad(fmt.Sprintf("longer than %d bytes", MaxURL))
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return bad("doesn't parse")
	case u.Scheme != "https":
		return bad("must be https")
	case u.User != nil:
		return bad("must not hold credentials")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return bad("must not have a fragment")
	case u.Hostname() == "" || u.Opaque != "":
		return bad("needs a host")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if len(host) > 253 || (net.ParseIP(host) == nil && !dnsName.MatchString(host)) {
		return bad("host must be an IP address or an ASCII DNS name (internationalized names in punycode)")
	}
	port := 443
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return bad("port must be 1 to 65535")
		}
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// dnsName is a DNS name of ASCII labels, at most 253 bytes.
var dnsName = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// checkEvents validates a subscription: known events, at least one, no
// duplicates; returned sorted.
func checkEvents(events []string) ([]string, error) {
	out := slices.Clone(events)
	slices.Sort(out)
	if len(out) == 0 || len(slices.Compact(slices.Clone(out))) != len(out) {
		return nil, &InvalidError{"/events", "at least one, no duplicates"}
	}
	for _, e := range out {
		if !slices.Contains(Events, e) {
			return nil, &InvalidError{"/events", "unknown event " + strconv.Quote(e)}
		}
	}
	return out, nil
}

// newSecret is a Standard Webhooks secret: whsec_ and base64 of 32 random
// bytes.
func newSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails (crypto/rand)
	return "whsec_" + base64.StdEncoding.EncodeToString(b)
}

func (s Service) encrypt(p secrets.Purpose, tenantID, id, plaintext string) ([]byte, error) {
	c, err := s.Keys.Encrypt([]byte(plaintext), secrets.Binding{Purpose: p, TenantID: tenantID, RowID: id})
	return []byte(c), err
}

func (s Service) decrypt(p secrets.Purpose, tenantID, id string, ciphertext []byte) (string, error) {
	b, err := s.Keys.Decrypt(string(ciphertext), secrets.Binding{Purpose: p, TenantID: tenantID, RowID: id})
	return string(b), err
}

// Create adds an endpoint for ctx's tenant, receiving events from now on,
// and returns it with its signing secret (shown once). The caller needs
// webhook:write; at most MaxEndpoints per tenant.
func (s Service) Create(ctx context.Context, rawURL string, events []string) (Created, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Created{}, err
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.By(p, "webhook.create", "webhook_endpoint", "")
	// Authorization first: a caller who may not create endpoints learns
	// nothing about its input.
	if err := authz.Require(ctx, authz.WebhookWrite, ""); err != nil {
		return Created{}, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrLimit)
	}
	display, err := checkURL(rawURL)
	if err == nil {
		events, err = checkEvents(events)
	}
	if err != nil {
		return Created{}, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrLimit)
	}
	id, secret := ids.WebhookEndpoint(), newSecret()
	urlC, err := s.encrypt(secrets.PurposeWebhookURL, tenantID, id, rawURL)
	if err != nil {
		return Created{}, err
	}
	secC, err := s.encrypt(secrets.PurposeWebhookSecret, tenantID, id, secret)
	if err != nil {
		return Created{}, err
	}
	var out Created
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		if err := store.RecheckPrincipal(ctx, tx, p); err != nil {
			return err
		}
		// Creates of one tenant take turns, so the limit holds.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('licenseforge.webhook_endpoints:' || $1, 0))`, tenantID); err != nil {
			return err
		}
		n, err := tx.WebhookEndpoint.Query().Count(ctx)
		if err != nil {
			return err
		}
		if n >= MaxEndpoints {
			return ErrLimit
		}
		row, err := tx.WebhookEndpoint.Create().SetID(id).SetTenantID(tenantID).SetURLCiphertext(urlC).SetURLDisplay(display).
			SetEvents(events).SetSecretCiphertext(secC).Save(ctx)
		if err != nil {
			return err
		}
		// From the chain's end: events from now on, never history. The
		// tenant pool can't use ent here (no INSERT on attempts).
		if _, err := tx.ExecContext(ctx, `INSERT INTO webhook_cursors (id, tenant_id, endpoint_id, seq)
			SELECT $1, $2, $3, COALESCE(max(seq), 0) FROM audit_events WHERE tenant_id = $4`, ids.WebhookCursor(), tenantID, id, tenantID); err != nil {
			return err
		}
		ev.ObjectID, ev.Outcome = id, auditevent.OutcomeSuccess
		ev.Details = map[string]any{"url": display, "events": events}
		if _, err := audit.Record(ctx, tx, tenantID, ev); err != nil {
			return err
		}
		out = Created{Endpoint: view(row), Secret: secret}
		return state(ctx, tx, &out.Endpoint)
	})
	if err != nil {
		ev.ObjectID, ev.Details = "", nil
		return Created{}, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrLimit)
	}
	return out, nil
}

func view(row *ent.WebhookEndpoint) Endpoint {
	e := Endpoint{ID: row.ID, URL: row.URLDisplay, Events: row.Events, Enabled: row.Enabled, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
	if row.DisabledReason != nil {
		e.DisabledReason = *row.DisabledReason
	}
	return e
}

// state fills e's delivery state from its cursor (explicit columns: the
// tenant pool can't read the lease holder).
func state(ctx context.Context, tx *ent.Tx, e *Endpoint) error {
	rows, err := tx.QueryContext(ctx, `SELECT seq, attempts, next_attempt_at, claimed_until IS NOT NULL AND claimed_until > now()
		FROM webhook_cursors WHERE endpoint_id = $1`, e.ID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return errors.Join(fmt.Errorf("webhooks: endpoint %s has no cursor", e.ID), rows.Err())
	}
	return errors.Join(rows.Scan(&e.Seq, &e.Attempts, &e.NextAttemptAt, &e.InFlight), rows.Err())
}

// List returns ctx's tenant's endpoints, oldest first. The caller needs
// webhook:read; endpoints are tenant-wide, so a product-scoped caller sees
// none (lists filter silently to the caller's scope, ADR-0032).
func (s Service) List(ctx context.Context) ([]Endpoint, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	if all, _, err := authz.Products(ctx, authz.WebhookRead); err != nil || !all {
		return nil, err
	}
	var out []Endpoint
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		rows, err := tx.WebhookEndpoint.Query().Order(ent.Asc(webhookendpoint.FieldCreatedAt), ent.Asc(webhookendpoint.FieldID)).All(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			e := view(r)
			if err := state(ctx, tx, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// Get returns one endpoint; ErrNotFound if it isn't the tenant's or the
// caller can't see endpoints (webhook:read, tenant-wide).
func (s Service) Get(ctx context.Context, id string) (Endpoint, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Endpoint{}, err
	}
	if authz.Require(ctx, authz.WebhookRead, "") != nil || !ids.Valid("whe", id) {
		return Endpoint{}, ErrNotFound
	}
	var out Endpoint
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		row, err := tx.WebhookEndpoint.Get(ctx, id)
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = view(row)
		return state(ctx, tx, &out)
	})
	return out, err
}

// change runs fn on endpoint id, locked, for an action needing
// webhook:write, and audits it. A missing endpoint, or any endpoint for a
// caller who can't see endpoints, is ErrNotFound (ADR-0032 order).
func (s Service) change(ctx context.Context, action, id string, fn func(tx *ent.Tx, row *ent.WebhookEndpoint, ev *audit.Event) error) (Endpoint, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Endpoint{}, err
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.By(p, action, "webhook_endpoint", "")
	if authz.Require(ctx, authz.WebhookRead, "") != nil || !ids.Valid("whe", id) {
		return Endpoint{}, audit.Refused(ctx, s.DB, tenantID, ev, ErrNotFound, ErrInvalid, ErrNotFound)
	}
	var out Endpoint
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		if err := store.RecheckPrincipal(ctx, tx, p); err != nil {
			return err
		}
		// Lock order, as the dispatcher's: the cursor, then the endpoint. The
		// endpoint lock doesn't block a delivery record's foreign key check
		// (FOR NO KEY UPDATE); changes of one endpoint take turns.
		for _, q := range []string{`SELECT 1 FROM webhook_cursors WHERE endpoint_id = $1 FOR UPDATE`,
			`SELECT 1 FROM webhook_endpoints WHERE id = $1 FOR NO KEY UPDATE`} {
			if _, err := tx.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
		row, err := tx.WebhookEndpoint.Get(ctx, id)
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if testHookRead != nil {
			testHookRead()
		}
		ev.ObjectID = id
		if err := authz.Require(ctx, authz.WebhookWrite, ""); err != nil {
			return err
		}
		ev.Details = map[string]any{"url": row.URLDisplay}
		if err := fn(tx, row, &ev); err != nil {
			return err
		}
		ev.Outcome = auditevent.OutcomeSuccess
		if _, err := audit.Record(ctx, tx, tenantID, ev); err != nil {
			return err
		}
		if action == "webhook.delete" {
			out = view(row)
			return nil
		}
		row, err = tx.WebhookEndpoint.Get(ctx, id)
		if err != nil {
			return err
		}
		out = view(row)
		return state(ctx, tx, &out)
	})
	if err != nil {
		return Endpoint{}, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrNotFound, ErrState)
	}
	return out, nil
}

// Update changes an endpoint's URL (if rawURL isn't nil) and subscribed
// events (if events isn't nil); at least one. Its delivery position stays.
func (s Service) Update(ctx context.Context, id string, rawURL *string, events []string) (Endpoint, error) {
	var display string
	var err error
	if rawURL == nil && events == nil {
		err = &InvalidError{"", "give url or events"}
	}
	if rawURL != nil {
		display, err = checkURL(*rawURL)
	}
	if err == nil && events != nil {
		events, err = checkEvents(events)
	}
	return s.change(ctx, "webhook.update", id, func(tx *ent.Tx, row *ent.WebhookEndpoint, ev *audit.Event) error {
		if err != nil {
			return err
		}
		u := tx.WebhookEndpoint.UpdateOneID(id)
		if rawURL != nil {
			c, err := s.encrypt(secrets.PurposeWebhookURL, row.TenantID, id, *rawURL)
			if err != nil {
				return err
			}
			u.SetURLCiphertext(c).SetURLDisplay(display)
			ev.Details["url"], ev.Details["from_url"] = display, row.URLDisplay
		}
		if events != nil {
			u.SetEvents(events)
			ev.Details["events"] = events
		}
		return u.Exec(ctx)
	})
}

// RotateSecret gives an endpoint a new signing secret (returned, shown
// once); the current one keeps signing alongside it for PreviousSecretTTL.
// Only one previous secret is kept: rotating again within that time drops
// the older one. A current secret that can't be decrypted any more (its
// master key left the keyring) is replaced without keeping it: rotation is
// how to recover.
func (s Service) RotateSecret(ctx context.Context, id string) (Endpoint, string, error) {
	secret := newSecret()
	e, err := s.change(ctx, "webhook.rotate_secret", id, func(tx *ent.Tx, row *ent.WebhookEndpoint, ev *audit.Event) error {
		next, err := s.encrypt(secrets.PurposeWebhookSecret, row.TenantID, id, secret)
		if err != nil {
			return err
		}
		u := tx.WebhookEndpoint.UpdateOneID(id).SetSecretCiphertext(next)
		cur, err := s.decrypt(secrets.PurposeWebhookSecret, row.TenantID, id, row.SecretCiphertext)
		switch {
		case errors.Is(err, secrets.ErrDecrypt), errors.Is(err, secrets.ErrUnknownKey):
			u.ClearPreviousSecretCiphertext().ClearPreviousSecretUntil()
			ev.Details["previous_kept"] = false
		case err != nil:
			return err
		default:
			prev, err := s.encrypt(secrets.PurposeWebhookPrevious, row.TenantID, id, cur)
			if err != nil {
				return err
			}
			u.SetPreviousSecretCiphertext(prev).SetPreviousSecretUntil(time.Now().Add(PreviousSecretTTL))
		}
		return u.Exec(ctx)
	})
	if err != nil {
		return Endpoint{}, "", err
	}
	return e, secret, nil
}

// Delete removes an endpoint with its cursor and delivery records, in the
// order the foreign keys need. The cursor is locked first (change), as the
// dispatcher locks it before recording a result: a result being written
// finishes first, one written after finds no cursor and records nothing.
func (s Service) Delete(ctx context.Context, id string) error {
	_, err := s.change(ctx, "webhook.delete", id, func(tx *ent.Tx, _ *ent.WebhookEndpoint, _ *audit.Event) error {
		for _, q := range []string{`DELETE FROM webhook_cursors WHERE endpoint_id = $1`, `DELETE FROM webhook_deliveries WHERE endpoint_id = $1`,
			`DELETE FROM webhook_endpoints WHERE id = $1`} {
			if _, err := tx.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}
