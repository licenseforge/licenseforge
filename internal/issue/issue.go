// Package issue turns stored licenses into signed lf1 files (License File
// Format). Every file is signed with the tenant's active key and recorded in
// the audit log (ADR-0027) before it is returned.
package issue

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/signing"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// ErrNotIssuable means the license can't get this kind of file; the error
// says why.
var ErrNotIssuable = errors.New("issue: license can't be issued as a file")

var errBadSignature = errors.New("issue: signer produced an invalid signature")

// Keys is the tenant's signing keys: the active kid and a Signer for it.
// signing.Local implements it.
type Keys interface {
	signing.Signer
	Active(ctx context.Context, tenantID string) (string, error)
}

// Issuer issues license files.
type Issuer struct {
	DB   *store.DB
	Keys Keys
	Now  func() time.Time // nil: time.Now
}

func (i Issuer) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// OfflineFile returns a signed license file for an air-gapped install of a
// site license (binding none, offline allowed, active, not expired). It needs
// activation:offline on the license's product. Machine- and cluster-bound
// files need a fingerprint and come with offline activation.
//
// The file is valid until the license's expiry (plus grace) and can't be
// revoked once handed out, like any offline license: the audit entry records
// who exported it and when.
func (i Issuer) OfflineFile(ctx context.Context, licenseID string) (string, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return "", err
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.Event{ActorType: actorType(p), ActorID: p.ID, Action: "license.offline_file", ObjectType: "license"}
	if !ids.Valid("lic", licenseID) { // hostile input: refuse before any query; not stored in the entry
		return "", i.refused(ctx, tenantID, ev, authz.ErrDenied)
	}
	ev.ObjectID = licenseID
	now := i.now()

	var claims licensefile.Claims
	err = i.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		claims, err = i.check(ctx, tx, licenseID, now, false)
		return err
	})
	if err != nil {
		return "", i.refused(ctx, tenantID, ev, err)
	}
	payload, err := licensefile.Encode(claims)
	if err != nil {
		return "", err
	}
	file, kid, err := i.sign(ctx, tenantID, payload)
	if err != nil {
		return "", i.signFailed(ctx, tenantID, ev, err)
	}

	// Record before returning. The license is read again under a share lock
	// (a concurrent revoke waits for this commit) and must still give the
	// same claims: an export of a license that changed while signing, or an
	// unrecorded export, must not leave. Lock order: license row, then the
	// audit lock; writers that change a license and audit it must update the
	// row first, then call audit.Record.
	ev.Outcome, ev.Details = auditevent.OutcomeSuccess, map[string]any{"kid": kid}
	err = i.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		again, err := i.check(ctx, tx, licenseID, now, true)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(again, claims) {
			return fmt.Errorf("%w: license changed while issuing; retry", ErrNotIssuable)
		}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		ev.Details = nil
		return "", i.refused(ctx, tenantID, ev, err)
	}
	return file, nil
}

// check reads the license (FOR SHARE if lock), applies the permission and
// issuability checks, and returns its claims at now.
func (i Issuer) check(ctx context.Context, tx *ent.Tx, licenseID string, now time.Time, lock bool) (licensefile.Claims, error) {
	q := tx.License.Query().Where(license.ID(licenseID)).WithProduct()
	if lock {
		q = q.ForShare()
	}
	l, err := q.Only(ctx)
	if lock && ent.IsNotFound(err) {
		// A revoked license can't be locked (license_transitions) and needs
		// no lock: it never changes again.
		l, err = tx.License.Query().Where(license.ID(licenseID), license.RevokedAtNotNil()).WithProduct().Only(ctx)
	}
	if ent.IsNotFound(err) {
		return licensefile.Claims{}, authz.ErrDenied // as for another tenant's license: don't reveal it exists
	}
	if err != nil {
		return licensefile.Claims{}, err
	}
	if err := authz.Require(ctx, authz.ActivationOffline, l.ProductID); err != nil {
		return licensefile.Claims{}, err
	}
	return offlineClaims(l, now)
}

// Sign encodes c and signs it with tenantID's active key, as OfflineFile
// does. It checks no principal: callers must have authenticated the request
// for this license first and checked that it may be issued (online leases:
// internal/activations, by license key), and record it themselves. The
// claims must name tenantID, so one tenant's caller can't get another
// tenant's key to sign.
func (i Issuer) Sign(ctx context.Context, tenantID string, c licensefile.Claims) (file, kid string, err error) {
	if c.Tenant != tenantID {
		return "", "", fmt.Errorf("issue: claims name tenant %q, not the signing tenant", c.Tenant)
	}
	payload, err := licensefile.Encode(c)
	if err != nil {
		return "", "", err
	}
	return i.sign(ctx, tenantID, payload)
}

// sign signs payload with the tenant's active key, reading the kid again once
// if a rotation retired it in between (signing.Signer). The signature is
// verified before the file is used, so a faulty signer (KMS) can't hand out
// a broken file.
func (i Issuer) sign(ctx context.Context, tenantID string, payload []byte) (file, kid string, err error) {
	for attempt := 0; ; attempt++ {
		if kid, err = i.Keys.Active(ctx, tenantID); err != nil {
			return "", "", err
		}
		pk, err := i.Keys.Public(ctx, tenantID, kid)
		if err != nil {
			return "", "", err
		}
		if pk.Alg != "ed25519" || len(pk.Key) != ed25519.PublicKeySize {
			return "", "", fmt.Errorf("issue: key %s is %s; only ed25519 is supported", kid, pk.Alg)
		}
		file, err = licensefile.Sign(kid, &signer{ctx: ctx, keys: i.Keys, tenantID: tenantID, kid: kid, pub: pk.Key}, payload)
		if errors.Is(err, signing.ErrNotActive) && attempt == 0 {
			continue
		}
		if err != nil {
			return "", "", err
		}
		keys := licensefile.KeySet{{KID: kid, Alg: licensefile.AlgEd25519, Key: pk.Key}}
		if _, _, err := licensefile.Verify(file, keys); err != nil {
			return "", "", fmt.Errorf("%w: %w", errBadSignature, err)
		}
		return file, kid, nil
	}
}

// offlineClaims checks that l can be exported as an offline site license now
// and builds its claims. Times are whole seconds: iat rounds down, expiry
// rounds down, so the file never outlives the license.
func offlineClaims(l *ent.License, now time.Time) (licensefile.Claims, error) {
	switch {
	case l.Status != license.StatusActive:
		return licensefile.Claims{}, fmt.Errorf("%w: license is %s", ErrNotIssuable, l.Status)
	case !l.OfflineAllowed:
		return licensefile.Claims{}, fmt.Errorf("%w: the plan doesn't allow offline use", ErrNotIssuable)
	case l.BindType != license.BindTypeNone:
		return licensefile.Claims{}, fmt.Errorf("%w: %s-bound licenses need an offline activation", ErrNotIssuable, l.BindType)
	case l.ExpiresAt != nil && !l.ExpiresAt.After(now):
		return licensefile.Claims{}, fmt.Errorf("%w: license expired", ErrNotIssuable)
	}
	c := licensefile.Claims{
		LicenseID: l.ID, Tenant: l.TenantID, Product: l.Edges.Product.Slug, Plan: l.PlanSlug,
		CustomerID: l.CustomerID, IssuedAt: now.UTC().Truncate(time.Second),
		Grace:        time.Duration(l.GraceSeconds) * time.Second,
		Binding:      licensefile.Binding{Type: licensefile.BindNone},
		Entitlements: licensefile.Entitlements{Features: l.Entitlements.Features, Limits: l.Entitlements.Limits},
	}
	if l.ExpiresAt != nil {
		exp := l.ExpiresAt.UTC().Truncate(time.Second)
		c.Expires = &exp
	}
	if l.UpdatesUntil != nil {
		u := l.UpdatesUntil.UTC().Truncate(time.Second)
		c.UpdatesUntil = &u
	}
	return c, nil
}

// refused records a denied or failed attempt in a transaction of its own
// (ADR-0027) and returns err. Errors that aren't the caller's (database
// down, no active key) aren't attempts and aren't recorded.
func (i Issuer) refused(ctx context.Context, tenantID string, ev audit.Event, err error) error {
	switch {
	case errors.Is(err, authz.ErrDenied):
		ev.Outcome = auditevent.OutcomeDenied
	case errors.Is(err, ErrNotIssuable):
		ev.Outcome, ev.Details = auditevent.OutcomeFailure, map[string]any{"reason": err.Error()}
	default:
		return err
	}
	if rerr := i.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, tenantID, ev)
		return err
	}); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}

// signFailed records a signing failure with a fixed reason (never the
// signer's error text) and returns err. An invalid signature from a signer
// is a security signal (a faulty or tampered KMS), so it is always recorded.
func (i Issuer) signFailed(ctx context.Context, tenantID string, ev audit.Event, err error) error {
	reason := "signing failed"
	switch {
	case errors.Is(err, signing.ErrNoActiveKey):
		reason = "the tenant has no active signing key"
	case errors.Is(err, signing.ErrNotActive):
		reason = "the signing key was rotated while issuing; retry"
	case errors.Is(err, errBadSignature):
		reason = "the signer produced an invalid signature"
	}
	ev.Outcome, ev.Details = auditevent.OutcomeFailure, map[string]any{"reason": reason}
	if rerr := i.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, tenantID, ev)
		return err
	}); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}

func actorType(p authz.Principal) auditevent.ActorType {
	if p.Kind == authz.Token {
		return auditevent.ActorTypeToken
	}
	return auditevent.ActorTypeUser
}

// signer adapts the tenant's Signer to crypto.Signer for licensefile.Sign.
type signer struct {
	ctx      context.Context
	keys     Keys
	tenantID string
	kid      string
	pub      ed25519.PublicKey
}

func (s *signer) Public() crypto.PublicKey { return s.pub }

func (s *signer) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.keys.Sign(s.ctx, s.tenantID, s.kid, msg)
}
