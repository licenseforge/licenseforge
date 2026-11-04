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
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/signing"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// ErrNotIssuable means the license can't get this kind of file; the error
// says why.
var ErrNotIssuable = errors.New("issue: license can't be issued as a file")

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
	ev := audit.Event{ActorType: actorType(p), ActorID: p.ID, Action: "license.offline_file", ObjectType: "license", ObjectID: licenseID}

	var claims licensefile.Claims
	var updated time.Time
	err = i.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		l, err := tx.License.Query().Where(license.ID(licenseID)).WithProduct().Only(ctx)
		if ent.IsNotFound(err) {
			return authz.ErrDenied // as for another tenant's license: don't reveal it exists
		}
		if err != nil {
			return err
		}
		if err := authz.Require(ctx, authz.ActivationOffline, l.ProductID); err != nil {
			return err
		}
		claims, err = offlineClaims(l, i.now())
		updated = l.UpdatedAt
		return err
	})
	if err != nil {
		return "", i.refused(ctx, tenantID, ev, err)
	}

	kid, err := i.Keys.Active(ctx, tenantID)
	if err != nil {
		return "", err
	}
	payload, err := licensefile.Encode(claims)
	if err != nil {
		return "", err
	}
	file, err := licensefile.Sign(kid, &signer{ctx: ctx, keys: i.Keys, tenantID: tenantID, kid: kid}, payload)
	if err != nil {
		return "", err
	}

	// Record before returning, and only if the license didn't change while
	// signing (e.g. revoked): an unrecorded export must not leave.
	ev.Outcome, ev.Details = auditevent.OutcomeSuccess, map[string]any{"kid": kid}
	err = i.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		l, err := tx.License.Query().Where(license.ID(licenseID)).ForShare().Only(ctx)
		if err != nil {
			return err
		}
		if !l.UpdatedAt.Equal(updated) {
			return fmt.Errorf("%w: license changed while issuing; retry", ErrNotIssuable)
		}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return "", err
	}
	return file, nil
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
// down) aren't attempts and aren't recorded.
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
}

func (s *signer) Public() crypto.PublicKey {
	pk, err := s.keys.Public(s.ctx, s.tenantID, s.kid)
	if err != nil || pk.Alg != "ed25519" {
		return nil // licensefile.Sign refuses a non-Ed25519 key
	}
	return ed25519.PublicKey(pk.Key)
}

func (s *signer) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.keys.Sign(s.ctx, s.tenantID, s.kid, msg)
}
