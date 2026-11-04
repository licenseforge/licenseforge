// Package activations is the online activation service the SDKs call
// (ADR-0004, ADR-0013, ADR-0017): activate a machine or cluster against a
// license key, refresh its lease, deactivate it. Callers are authenticated by
// the license key alone (lookup hash, then decrypt and compare, ADR-0025),
// under the tenant from the URL. Every answer that grants use is a signed lf1
// lease (License File Format) with a short exp, max_offline and
// refresh_after, so revoking or suspending a license takes effect when the
// lease runs out.
//
// Audited (ADR-0027): new activations, deactivations, and refused
// activations and deactivations of a known license. Refreshes, re-activations
// of the same machine and unknown keys are high-volume and stay in metrics
// and logs.
package activations

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"
	"time"

	"entgo.io/ent/dialect/sql"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/issue"
	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/licenses"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// Refusals the SDK acts on. Every one but ErrUnauthenticated and ErrInvalid
// means the key is valid.
var (
	// ErrUnauthenticated: unknown or malformed key, or another tenant's.
	ErrUnauthenticated = errors.New("activations: invalid license key")
	// ErrInvalid: malformed fingerprint, source or metadata.
	ErrInvalid   = errors.New("activations: invalid request")
	ErrSuspended = errors.New("activations: license suspended")
	ErrRevoked   = errors.New("activations: license revoked")
	ErrExpired   = errors.New("activations: license expired")
	// ErrLimit: every seat (max_activations) is taken; deactivate one first.
	ErrLimit = errors.New("activations: activation limit reached")
	// ErrRehostLimit: the license's seats have moved max_rehosts times
	// (ADR-0034); support can rehost or the vendor can raise the limit.
	ErrRehostLimit = errors.New("activations: rehost limit reached")
	// ErrBinding: the fingerprint's binding isn't the license's (machine vs
	// cluster), or the license is a site license, which has no activations.
	ErrBinding = errors.New("activations: binding doesn't match the license")
	// ErrNotActivated: no active activation for this fingerprint (deactivated
	// or reset); activate again.
	ErrNotActivated = errors.New("activations: not activated")
)

// Service works on the tenant pool. Keys is the master keyring (license
// keys); Issuer signs the leases.
type Service struct {
	DB     *store.DB
	Keys   *secrets.Keyring
	Issuer issue.Issuer
}

// Request is what the SDK sends. TenantID comes from the URL.
type Request struct {
	TenantID    string
	Key         string              // as the user typed it
	Fingerprint string              // the lease's bind.fp: "sha256:" + 64 hex (License File Format)
	Source      activation.FpSource // kubernetes binds the cluster, all others the machine
	// Metadata, recorded at activation and refresh (ADR-0013). Optional.
	Hostname, AppVersion, SDKVersion string
}

// Lease is a signed lf1 lease and the claims it carries. Claims.IssuedAt is
// the server time the SDK uses against clock rollback (ADR-0018).
type Lease struct {
	File         string
	KID          string
	Claims       licensefile.Claims
	ActivationID string
}

var fpRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Activate binds req's fingerprint to the license and returns a lease. An
// active activation of the same fingerprint is reused (no new seat); a new
// one needs a free seat. The first activation starts a from_first_activation
// term.
func (s Service) Activate(ctx context.Context, req Request) (Lease, error) {
	return s.lease(ctx, req, true)
}

// Refresh (also the SDK's validate) returns a new lease for an active
// activation and records its last-seen time and metadata. It never takes a
// seat: ErrNotActivated asks the SDK to activate.
func (s Service) Refresh(ctx context.Context, req Request) (Lease, error) {
	return s.lease(ctx, req, false)
}

func (s Service) lease(ctx context.Context, req Request, activate bool) (Lease, error) {
	key, err := req.check(true)
	if err != nil {
		return Lease{}, err
	}
	binding := activation.BindingMachine
	if req.Source == activation.FpSourceKubernetes {
		binding = activation.BindingCluster
	}
	ev := audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "activation.create", ObjectType: "activation"}
	var claims licensefile.Claims
	var actID string
	err = s.DB.WithTenant(ctx, req.TenantID, func(tx *ent.Tx) error {
		// Activate locks the license FOR NO KEY UPDATE: seats are counted and
		// taken one at a time, and a suspend or revoke (which takes the same
		// lock) waits. Lock order: license row, then the audit lock.
		l, err := s.authenticate(ctx, tx, req.TenantID, key, activate)
		if err != nil {
			return err
		}
		ev.Details = map[string]any{"license_id": l.ID, "fingerprint": req.Fingerprint, "fp_source": string(req.Source)}
		now, err := licenses.DBNow(ctx, tx)
		if err != nil {
			return err
		}
		if err := usable(l, now, !activate); err != nil {
			return err
		}
		if string(l.BindType) != string(binding) {
			return fmt.Errorf("%w: the license binds %s", ErrBinding, l.BindType)
		}
		act, err := tx.Activation.Query().Where(activation.LicenseID(l.ID), activation.Fingerprint(req.Fingerprint), activation.DeactivatedAtIsNil()).Only(ctx)
		switch {
		case err == nil:
			actID = act.ID
			res, err := tx.ExecContext(ctx, `UPDATE activations SET last_seen_at = GREATEST(last_seen_at, clock_timestamp()),
				hostname = $2, app_version = $3, sdk_version = $4, updated_at = clock_timestamp() WHERE id = $1 AND deactivated_at IS NULL`,
				act.ID, nilIfEmpty(req.Hostname), nilIfEmpty(req.AppVersion), nilIfEmpty(req.SDKVersion))
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 { // deactivated concurrently
				return errors.Join(ErrNotActivated, err)
			}
		case ent.IsNotFound(err) && activate:
			if actID, err = s.create(ctx, tx, l, req, binding, now); err != nil {
				return err
			}
			ev.ObjectID, ev.Outcome = actID, auditevent.OutcomeSuccess
			if _, err := audit.Record(ctx, tx, req.TenantID, ev); err != nil {
				return err
			}
		case ent.IsNotFound(err):
			return ErrNotActivated
		default:
			return err
		}
		p, err := tx.Product.Get(ctx, l.ProductID)
		if err != nil {
			return err
		}
		claims = leaseClaims(l, p.Slug, now, req.Fingerprint)
		return nil
	})
	if err != nil {
		if !activate {
			ev.Details = nil // refreshes aren't audited
		}
		return Lease{}, s.refused(ctx, req.TenantID, ev, err)
	}
	// Signed after the commit: if signing fails, the seat stays taken and a
	// retry reuses it.
	file, kid, err := s.Issuer.Sign(ctx, req.TenantID, claims)
	if err != nil {
		return Lease{}, err
	}
	return Lease{File: file, KID: kid, Claims: claims, ActivationID: actID}, nil
}

// create takes a seat for a new activation of l (locked FOR NO KEY UPDATE)
// and starts the term at the first activation. Seat moves (ADR-0034): with
// max_activations set, activating a fingerprint never activated on this
// license before, once it has had max_activations distinct fingerprints, is
// a move. A move increments rehost_count and is refused past max_rehosts
// (unlimited when nil). A fingerprint seen before (uninstall and reinstall on
// the same machine) never counts again.
func (s Service) create(ctx context.Context, tx *ent.Tx, l *ent.License, req Request, binding activation.Binding, now time.Time) (string, error) {
	u := tx.License.UpdateOneID(l.ID).SetUpdatedAt(now)
	changed := false
	if l.MaxActivations != nil {
		n, err := tx.Activation.Query().Where(activation.LicenseID(l.ID), activation.DeactivatedAtIsNil()).Count(ctx)
		if err != nil {
			return "", err
		}
		if n >= *l.MaxActivations {
			return "", fmt.Errorf("%w (%d)", ErrLimit, *l.MaxActivations)
		}
		seen, err := tx.Activation.Query().Where(activation.LicenseID(l.ID), activation.Fingerprint(req.Fingerprint)).Exist(ctx)
		if err != nil {
			return "", err
		}
		if !seen {
			fps, err := tx.Activation.Query().Where(activation.LicenseID(l.ID)).GroupBy(activation.FieldFingerprint).Strings(ctx)
			if err != nil {
				return "", err
			}
			if len(fps) >= *l.MaxActivations { // a move
				if l.MaxRehosts != nil && l.RehostCount >= *l.MaxRehosts {
					return "", fmt.Errorf("%w (%d)", ErrRehostLimit, *l.MaxRehosts)
				}
				u.AddRehostCount(1) // the CHECK licenses_rehosts_within_limit backs the limit
				changed = true
			}
		}
	}
	if l.FirstActivatedAt == nil {
		u.SetFirstActivatedAt(now)
		if l.ExpiryBasis == license.ExpiryBasisFromFirstActivation {
			l.ExpiresAt = licenses.Expiry(now, l.DurationMonths, l.DurationSeconds)
			u.SetNillableExpiresAt(l.ExpiresAt)
		}
		l.FirstActivatedAt = &now
		changed = true
	}
	if changed {
		if err := u.Exec(ctx); err != nil {
			return "", err
		}
	}
	a, err := tx.Activation.Create().SetTenantID(l.TenantID).SetLicenseID(l.ID).SetFingerprint(req.Fingerprint).
		SetFpSource(req.Source).SetBinding(binding).SetMode(activation.ModeOnline).
		SetNillableHostname(nilIfEmpty(req.Hostname)).SetNillableAppVersion(nilIfEmpty(req.AppVersion)).
		SetNillableSdkVersion(nilIfEmpty(req.SDKVersion)).SetFirstSeenAt(now).SetLastSeenAt(now).SetCreatedAt(now).SetUpdatedAt(now).Save(ctx) // one clock for the row
	if err != nil {
		return "", err
	}
	return a.ID, nil
}

// Deactivate frees the seat of req's fingerprint (Key and Fingerprint are
// used; metadata is ignored). Allowed whatever the license's status.
func (s Service) Deactivate(ctx context.Context, req Request) error {
	key, err := req.check(false)
	if err != nil {
		return err
	}
	ev := audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "activation.deactivate", ObjectType: "activation"}
	err = s.DB.WithTenant(ctx, req.TenantID, func(tx *ent.Tx) error {
		l, err := s.authenticate(ctx, tx, req.TenantID, key, true)
		if err != nil {
			return err
		}
		ev.Details = map[string]any{"license_id": l.ID, "fingerprint": req.Fingerprint}
		act, err := tx.Activation.Query().Where(activation.LicenseID(l.ID), activation.Fingerprint(req.Fingerprint), activation.DeactivatedAtIsNil()).Only(ctx)
		if ent.IsNotFound(err) {
			return ErrNotActivated
		}
		if err != nil {
			return err
		}
		ev.ObjectID = act.ID
		res, err := tx.ExecContext(ctx, `UPDATE activations SET deactivated_at = clock_timestamp(), updated_at = clock_timestamp()
			WHERE id = $1 AND deactivated_at IS NULL`, act.ID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(ErrNotActivated, err)
		}
		ev.Outcome = auditevent.OutcomeSuccess
		_, err = audit.Record(ctx, tx, req.TenantID, ev)
		return err
	})
	if err != nil {
		return s.refused(ctx, req.TenantID, ev, err)
	}
	return nil
}

// check validates req and returns the canonical key. A malformed key or
// tenant is ErrUnauthenticated, like an unknown one.
func (req Request) check(metadata bool) (string, error) {
	key, err := licensekey.Normalize(req.Key)
	if err != nil || !ids.Valid("tnt", req.TenantID) {
		return "", ErrUnauthenticated
	}
	if !fpRE.MatchString(req.Fingerprint) || (metadata && activation.FpSourceValidator(req.Source) != nil) {
		return "", fmt.Errorf("%w: fingerprint or source", ErrInvalid)
	}
	if metadata && (!hostnameRE.MatchString(req.Hostname) || !versionRE.MatchString(req.AppVersion) || !versionRE.MatchString(req.SDKVersion)) {
		return "", fmt.Errorf("%w: hostname of up to 253 letters, digits, '-', '.' or '_'; versions of up to 64 printable ASCII characters", ErrInvalid)
	}
	return key, nil
}

var (
	hostnameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{0,253}$`)
	versionRE  = regexp.MustCompile(`^[ -~]{0,64}$`)
)

// authenticate finds the license of key in tenantID, locked FOR NO KEY
// UPDATE (exclusive: activate, deactivate) or FOR SHARE (refresh), and
// checks the key against its ciphertext: the lookup hash finds it, the decrypted key proves it (ADR-0025). The hashes under every
// keyring key are tried, so lookups keep working during a rotation.
func (s Service) authenticate(ctx context.Context, tx *ent.Tx, tenantID, key string, exclusive bool) (*ent.License, error) {
	q := tx.License.Query().Where(license.KeyLookupIn(s.Keys.LookupHashes(secrets.PurposeLicenseKey, []byte(key))...))
	if exclusive {
		// NO KEY UPDATE, what licenses' transitions take: activation inserts
		// (FOR KEY SHARE through the foreign key) don't wait for it.
		q = q.ForUpdate(func(o *sql.LockOptions) { o.Strength = sql.LockNoKeyUpdate })
	} else {
		q = q.ForShare()
	}
	l, err := q.Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	pt, err := s.Keys.Decrypt(l.KeyCiphertext, secrets.Binding{Purpose: secrets.PurposeLicenseKey, TenantID: tenantID, RowID: l.ID})
	if err != nil {
		return nil, fmt.Errorf("activations: license %s: key ciphertext: %w", l.ID, err) // tampering or a lost master key, not the caller's error
	}
	if subtle.ConstantTimeCompare(pt, []byte(key)) != 1 {
		return nil, ErrUnauthenticated
	}
	return l, nil
}

// usable: active and not expired at now (the database clock). With inGrace
// (refresh of an existing activation), the license's grace after its expiry
// still counts.
func usable(l *ent.License, now time.Time, inGrace bool) error {
	switch {
	case l.Status == license.StatusRevoked:
		return ErrRevoked
	case l.Status == license.StatusSuspended:
		return ErrSuspended
	case l.Status != license.StatusActive:
		return fmt.Errorf("activations: license status %q", l.Status)
	case l.ExpiresAt == nil || l.ExpiresAt.After(now):
		return nil
	case !inGrace || !l.ExpiresAt.Add(time.Duration(l.GraceSeconds)*time.Second).After(now):
		return ErrExpired
	}
	return nil // term ended, within grace: refresh only (ADR-0034)
}

// leaseClaims (ADR-0034): issued at now; exp after the license's lease,
// never past the license's own expiry; refresh after half of the shorter of
// the lease and max_offline (so the SDK refreshes before it must), never
// after the lease's end. Whole seconds, rounded down, so the lease never
// outlives the license.
//
// Grace only when exp is the license's own expiry (the term ends; keep
// working while it is renewed). An unrefreshed lease ends at exp, so a
// revoked or suspended machine stops within one lease (ADR-0004). Perpetual
// licenses get no grace online. During grace (exp before iat) the lease ends
// at exp + grace.
func leaseClaims(l *ent.License, productSlug string, now time.Time, fp string) licensefile.Claims {
	iat := now.UTC().Truncate(time.Second)
	lease := time.Duration(l.LeaseSeconds) * time.Second
	exp := iat.Add(lease)
	var grace time.Duration
	if l.ExpiresAt != nil && !l.ExpiresAt.UTC().Truncate(time.Second).After(exp) { // to the second, as signed
		exp = l.ExpiresAt.UTC().Truncate(time.Second)
		grace = time.Duration(l.GraceSeconds) * time.Second
	}
	window := lease
	if l.MaxOfflineSeconds != nil { // 0 is a real limit: refresh at once
		window = min(window, time.Duration(*l.MaxOfflineSeconds)*time.Second)
	}
	refresh := iat.Add((window / 2).Truncate(time.Second))
	end := exp
	if !exp.After(iat) {
		end = exp.Add(grace)
	}
	if refresh.After(end) {
		refresh = end
	}
	c := licensefile.Claims{
		LicenseID: l.ID, Tenant: l.TenantID, Product: productSlug, Plan: l.PlanSlug, CustomerID: l.CustomerID,
		IssuedAt: iat, Expires: &exp, RefreshAfter: &refresh,
		Grace:        grace,
		Binding:      licensefile.Binding{Type: licensefile.BindingType(l.BindType), Fingerprint: fp},
		Entitlements: licensefile.Entitlements{Features: l.Entitlements.Features, Limits: l.Entitlements.Limits},
	}
	if l.MaxOfflineSeconds != nil {
		d := time.Duration(*l.MaxOfflineSeconds) * time.Second
		c.MaxOffline = &d
	}
	if l.UpdatesUntil != nil {
		u := l.UpdatesUntil.UTC().Truncate(time.Second)
		c.UpdatesUntil = &u
	}
	return c
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// refused records a refused activation or deactivation of a known license
// (ev.Details set once the key matched) in its own transaction, and returns
// err. Unknown keys and refreshes aren't recorded.
func (s Service) refused(ctx context.Context, tenantID string, ev audit.Event, err error) error {
	switch {
	case ev.Details == nil:
		return err
	case errors.Is(err, ErrSuspended), errors.Is(err, ErrRevoked), errors.Is(err, ErrExpired),
		errors.Is(err, ErrLimit), errors.Is(err, ErrRehostLimit), errors.Is(err, ErrBinding), errors.Is(err, ErrNotActivated):
		ev.Outcome, ev.ObjectID = auditevent.OutcomeFailure, ""
		ev.Details["reason"] = err.Error()
	default:
		return err
	}
	if rerr := s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, tenantID, ev)
		return err
	}); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}
