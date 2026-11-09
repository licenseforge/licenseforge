package activations

import (
	"context"
	"errors"
	"fmt"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/licenses"
	"licenseforge.io/licenseforge/internal/signing"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// ErrOffline: the license's plan doesn't allow offline use (offline_allowed
// off, or max_offline_seconds 0).
var ErrOffline = errors.New("activations: the plan doesn't allow offline use")

// ErrOnlineSeat: the machine is activated online. Its SDK deactivates it
// first (same fingerprint: no seat move); an online seat never turns
// offline, so online deactivate can't free a seat whose file is out.
var ErrOnlineSeat = errors.New("activations: the machine is activated online; deactivate it there first")

var offlineRefusals = []error{ErrInvalid, ErrNotFound, ErrSuspended, ErrRevoked, ErrExpired, ErrLimit, ErrRehostLimit, ErrBinding, ErrOffline, ErrOnlineSeat}

// Offline answers an offline activation request (ADR-0043): the lfreq1 text
// an air-gapped machine wrote, carried in by p (activation:offline on the
// license's product). It takes or reuses the seat of the request's
// fingerprint as online activation does (ADR-0034), with mode offline, and
// returns a signed lf1 file bound to it whose exp is the license's expiry,
// capped at iat + max_offline_seconds; grace only when the license's expiry
// ends it. No refresh: the file is the offline term. Renewal is a new
// request from the same machine.
//
// Order of checks (ADR-0032): the request's shape and tenant (ErrInvalid),
// the license of its key under p's product scope (unknown and hidden alike:
// ErrNotFound), activation:offline (authz.ErrDenied), then the license as
// for a new online activation. The file is signed in the transaction that
// records it, so a file never leaves unrecorded; the activation keeps the
// file's token hash (the receipt must name it). Refusals are audited in a
// transaction of their own; the request text and the key never are, only
// the request's SHA-256.
func (s Service) Offline(ctx context.Context, p authz.Principal, request string) (Lease, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Lease{}, err
	}
	ev := audit.By(p, "activation.offline", "activation", "")
	ev.Details = map[string]any{"request_sha256": licensefile.OfflineSHA256(request)}
	var out Lease
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		out, err = s.offline(ctx, tx, tenantID, request, &ev)
		return err
	})
	if err != nil {
		err = audit.Refused(ctx, s.DB, tenantID, offlineRefusal(ev, err), err, offlineRefusals...)
		if err == errHidden { //nolint:errorlint // exactly the recorded refusal (a recording failure is joined to it: a 500)
			return Lease{}, ErrNotFound
		}
		return Lease{}, err
	}
	return out, nil
}

// OfflineTx is Offline inside the caller's transaction tx (for
// idempotency.Store.Do, ADR-0032): the file is signed and recorded before
// tx commits, so a stored outcome always carries it, and a refusal is
// audited in tx (the caller commits refusals it stores). Errors that aren't
// refusals are returned unrecorded, for tx to roll back.
func (s Service) OfflineTx(ctx context.Context, tx *ent.Tx, p authz.Principal, request string) (Lease, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Lease{}, err
	}
	ev := audit.By(p, "activation.offline", "activation", "")
	ev.Details = map[string]any{"request_sha256": licensefile.OfflineSHA256(request)}
	out, err := s.offline(ctx, tx, tenantID, request, &ev)
	if err == nil {
		return out, nil
	}
	if outcome, ok := refusalOutcome(err); ok {
		ev = offlineRefusal(ev, err)
		ev.Outcome = outcome
		if _, rerr := audit.Record(ctx, tx, tenantID, ev); rerr != nil {
			return Lease{}, errors.Join(err, rerr)
		}
	}
	if err == errHidden { //nolint:errorlint // exactly the recorded refusal
		return Lease{}, ErrNotFound
	}
	return Lease{}, err
}

// RecheckOffline is the replay check of a stored offline activation
// (ADR-0032: rerun for the original operation): request's key still finds a
// license p may issue offline files for. It reads in tx and changes nothing.
func (s Service) RecheckOffline(ctx context.Context, tx *ent.Tx, p authz.Principal, request string) error {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return err
	}
	ev := audit.Event{Details: map[string]any{}}
	if _, _, err := s.resolve(ctx, tx, tenantID, request, &ev, false); err != nil {
		if err == errHidden { //nolint:errorlint // unrecorded here
			return ErrNotFound
		}
		return err
	}
	return nil
}

// offlineRefusal sets ev's reason for err: invalid requests get a fixed one,
// since their details echo the request, which never goes in the chain.
func offlineRefusal(ev audit.Event, err error) audit.Event {
	ev.Details["reason"] = err.Error()
	if errors.Is(err, ErrInvalid) {
		ev.Details["reason"] = ErrInvalid.Error()
	}
	return ev
}

// refusalOutcome classifies err as audit.Refused does: denied, a failure
// among offlineRefusals, or not a refusal (an outage: unrecorded).
func refusalOutcome(err error) (auditevent.Outcome, bool) {
	if errors.Is(err, authz.ErrDenied) {
		return auditevent.OutcomeDenied, true
	}
	for _, f := range offlineRefusals {
		if errors.Is(err, f) {
			return auditevent.OutcomeFailure, true
		}
	}
	return "", false
}

// resolve parses the request and finds its license, locked as authenticate
// does, under ctx's principal: the checks before the license's own state.
func (s Service) resolve(ctx context.Context, tx *ent.Tx, tenantID, text string, ev *audit.Event, exclusive bool) (*licensefile.Request, *ent.License, error) {
	r, err := licensefile.ParseRequest(text)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if r.Tenant != tenantID {
		return nil, nil, fmt.Errorf("%w: the request is for tenant %q", ErrInvalid, r.Tenant)
	}
	key, err := licensekey.Normalize(r.Key)
	if err != nil {
		return nil, nil, ErrNotFound
	}
	l, err := s.authenticate(ctx, tx, tenantID, key, exclusive)
	if errors.Is(err, ErrUnauthenticated) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	ev.Details["license_id"], ev.Details["product_id"] = l.ID, l.ProductID
	ev.Details["fingerprint"], ev.Details["fp_source"] = r.Binding.Fingerprint, r.FPSource
	if authz.Require(ctx, authz.ActivationRead, l.ProductID) != nil {
		return nil, nil, errHidden
	}
	if err := authz.Require(ctx, authz.ActivationOffline, l.ProductID); err != nil {
		return nil, nil, err
	}
	return r, l, nil
}

func (s Service) offline(ctx context.Context, tx *ent.Tx, tenantID, text string, ev *audit.Event) (Lease, error) {
	r, l, err := s.resolve(ctx, tx, tenantID, text, ev, true)
	if err != nil {
		return Lease{}, err
	}
	p, err := tx.Product.Get(ctx, l.ProductID)
	if err != nil {
		return Lease{}, err
	}
	if r.Product != p.Slug {
		return Lease{}, fmt.Errorf("%w: the request is for product %q, the license for %q", ErrInvalid, r.Product, p.Slug)
	}
	now, err := licenses.DBNow(ctx, tx)
	if err != nil {
		return Lease{}, err
	}
	if err := usable(l, now, false); err != nil {
		return Lease{}, err
	}
	if !l.OfflineAllowed || (l.MaxOfflineSeconds != nil && *l.MaxOfflineSeconds == 0) {
		return Lease{}, ErrOffline
	}
	if string(l.BindType) != string(r.Binding.Type) {
		return Lease{}, fmt.Errorf("%w: the license binds %s", ErrBinding, l.BindType)
	}
	req := Request{TenantID: tenantID, Fingerprint: r.Binding.Fingerprint, Source: activation.FpSource(r.FPSource),
		Hostname: r.Hostname, AppVersion: r.AppVersion, SDKVersion: r.SDKVersion}
	act, err := tx.Activation.Query().Where(activation.LicenseID(l.ID), activation.Fingerprint(req.Fingerprint), activation.DeactivatedAtIsNil()).Only(ctx)
	switch {
	case err == nil && act.Mode != activation.ModeOffline:
		return Lease{}, ErrOnlineSeat
	case err == nil: // renewal
		ev.ObjectID = act.ID
	case ent.IsNotFound(err):
		id, move, err := s.create(ctx, tx, l, req, activation.Binding(r.Binding.Type), activation.ModeOffline, now)
		if err != nil {
			return Lease{}, err
		}
		ev.ObjectID, ev.Details["new_seat"] = id, true
		if move {
			ev.Details["move"], ev.Details["rehost_count"] = true, l.RehostCount
		}
	default:
		return Lease{}, err
	}
	c := offlineClaims(l, p.Slug, now, r.Binding.Fingerprint)
	// Lock order: the license row (above), the audit lock, then the signing
	// key rows (audit.Lock). Signing in tx: no second pool connection.
	if err := audit.Lock(ctx, tx, tenantID); err != nil {
		return Lease{}, err
	}
	is := s.Issuer
	if k, ok := is.Keys.(signing.Local); ok {
		is.Keys = k.WithTx(tx)
	}
	file, kid, err := is.Sign(ctx, tenantID, c)
	if err != nil {
		return Lease{}, err
	}
	h, err := licensefile.FileSHA256(file)
	if err != nil {
		return Lease{}, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE activations SET offline_file_sha256 = $2, last_seen_at = GREATEST(last_seen_at, clock_timestamp()),
		hostname = $3, app_version = $4, sdk_version = $5, updated_at = clock_timestamp() WHERE id = $1 AND deactivated_at IS NULL`,
		ev.ObjectID, h, nilIfEmpty(req.Hostname), nilIfEmpty(req.AppVersion), nilIfEmpty(req.SDKVersion))
	if err != nil {
		return Lease{}, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 { // can't happen under the license lock; never hand out an unrecorded file
		return Lease{}, errors.Join(errors.New("activations: offline seat not updated"), err)
	}
	ev.Outcome, ev.Details["file_sha256"], ev.Details["kid"] = auditevent.OutcomeSuccess, h, kid
	if _, err := audit.Record(ctx, tx, tenantID, *ev); err != nil {
		return Lease{}, err
	}
	return Lease{File: file, KID: kid, Claims: c, ActivationID: ev.ObjectID}, nil
}

// offlineClaims: issued at now; exp the license's expiry, capped at iat +
// max_offline_seconds (none: a perpetual license gets a perpetual file).
// Grace only when exp is the license's own expiry. Whole seconds, rounded
// down, so the file never outlives the license.
func offlineClaims(l *ent.License, productSlug string, now time.Time, fp string) licensefile.Claims {
	iat := now.UTC().Truncate(time.Second)
	var exp *time.Time
	var grace time.Duration
	if l.ExpiresAt != nil {
		e := l.ExpiresAt.UTC().Truncate(time.Second)
		exp, grace = &e, time.Duration(l.GraceSeconds)*time.Second
	}
	if l.MaxOfflineSeconds != nil {
		if e := iat.Add(time.Duration(*l.MaxOfflineSeconds) * time.Second); exp == nil || e.Before(*exp) {
			exp, grace = &e, 0
		}
	}
	c := licensefile.Claims{
		LicenseID: l.ID, Tenant: l.TenantID, Product: productSlug, Plan: l.PlanSlug, CustomerID: l.CustomerID,
		IssuedAt: iat, Expires: exp, Grace: grace,
		Binding:      licensefile.Binding{Type: licensefile.BindingType(l.BindType), Fingerprint: fp},
		Entitlements: licensefile.Entitlements{Features: l.Entitlements.Features, Limits: l.Entitlements.Limits},
	}
	if l.UpdatesUntil != nil {
		u := l.UpdatesUntil.UTC().Truncate(time.Second)
		c.UpdatesUntil = &u
	}
	return c
}
