package activations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

var offlineRefusals = []error{ErrInvalid, ErrNotFound, ErrSuspended, ErrRevoked, ErrExpired, ErrLimit, ErrRehostLimit, ErrBinding, ErrOffline}

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
	sum := sha256.Sum256([]byte(request))
	ev := audit.By(p, "activation.offline", "activation", "")
	ev.Details = map[string]any{"request_sha256": hex.EncodeToString(sum[:])}
	var out Lease
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		out, err = s.offline(ctx, tx, tenantID, request, &ev)
		return err
	})
	if err != nil {
		ev.Details["reason"] = err.Error() // recorded for refusals only
		err = audit.Refused(ctx, s.DB, tenantID, ev, err, offlineRefusals...)
		if err == errHidden { //nolint:errorlint // exactly the recorded refusal (a recording failure is joined to it: a 500)
			return Lease{}, ErrNotFound
		}
		return Lease{}, err
	}
	return out, nil
}

func (s Service) offline(ctx context.Context, tx *ent.Tx, tenantID, text string, ev *audit.Event) (Lease, error) {
	r, err := licensefile.ParseRequest(text)
	if err != nil {
		return Lease{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if r.Tenant != tenantID {
		return Lease{}, fmt.Errorf("%w: the request is for tenant %q", ErrInvalid, r.Tenant)
	}
	key, err := licensekey.Normalize(r.Key)
	if err != nil {
		return Lease{}, ErrNotFound
	}
	l, err := s.authenticate(ctx, tx, tenantID, key, true)
	if errors.Is(err, ErrUnauthenticated) {
		return Lease{}, ErrNotFound
	}
	if err != nil {
		return Lease{}, err
	}
	ev.Details["license_id"], ev.Details["product_id"] = l.ID, l.ProductID
	ev.Details["fingerprint"], ev.Details["fp_source"] = r.Binding.Fingerprint, r.FPSource
	if authz.Require(ctx, authz.ActivationRead, l.ProductID) != nil {
		return Lease{}, errHidden
	}
	if err := authz.Require(ctx, authz.ActivationOffline, l.ProductID); err != nil {
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
	case err == nil: // renewal, or an online seat going offline
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
