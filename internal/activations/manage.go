package activations

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// The management side (the dashboard and API tokens, ADR-0019, ADR-0032):
// list a license's activations, deactivate one, count seats.

// ErrNotFound: no such license or activation that the caller can see;
// outside the caller's product scope looks the same (ADR-0032).
var ErrNotFound = errors.New("activations: not found")

// ErrState: the license's status doesn't allow the change (a revoked
// license's rehosts can't be reset).
var ErrState = errors.New("activations: the license is revoked")

// errHidden: a license outside the principal's product scope. Audited as
// denied, answered as ErrNotFound.
var errHidden = fmt.Errorf("%w: license outside the product scope", authz.ErrDenied)

// visible reads licenseID, unlocked, if ctx's principal may see its
// activations: ErrNotFound if missing, the license and errHidden if hidden.
func visible(ctx context.Context, tx *ent.Tx, licenseID string) (*ent.License, error) {
	l, err := tx.License.Query().Where(license.ID(licenseID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if authz.Require(ctx, authz.ActivationRead, l.ProductID) != nil {
		return l, errHidden
	}
	return l, nil
}

// List returns up to limit of licenseID's activations, deactivated ones
// included, newest first, after (afterAt, afterID) or from the start if
// afterID is "". p needs activation:read on the license's product.
func (s Service) List(ctx context.Context, p authz.Principal, licenseID string, limit int, afterAt time.Time, afterID string) ([]*ent.Activation, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	if !ids.Valid("lic", licenseID) {
		return nil, ErrNotFound
	}
	var out []*ent.Activation
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		if _, err := visible(ctx, tx, licenseID); err != nil {
			if errors.Is(err, errHidden) {
				return ErrNotFound
			}
			return err
		}
		q := tx.Activation.Query().Where(activation.LicenseID(licenseID)).
			Order(ent.Desc(activation.FieldCreatedAt), ent.Desc(activation.FieldID)).Limit(limit)
		if afterID != "" {
			q.Where(activation.Or(activation.CreatedAtLT(afterAt), activation.And(activation.CreatedAt(afterAt), activation.IDLT(afterID))))
		}
		out, err = q.All(ctx)
		return err
	})
	return out, err
}

// DeactivateByID frees an activation's seat for p, as the SDK's Deactivate
// does (the same lock and update), whatever the license's status. Order of
// checks (ADR-0032): the license under p's product scope and the activation
// (missing and hidden alike: ErrNotFound), then activation:manage
// (authz.ErrDenied). An activation already deactivated is returned as it
// is, unchanged and not audited. Deactivating isn't a seat move
// (ADR-0034): activating a new machine afterwards may be. Refusals are
// audited in a transaction of their own.
func (s Service) DeactivateByID(ctx context.Context, p authz.Principal, licenseID, activationID string) (*ent.Activation, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	ev := audit.By(p, "activation.deactivate", "activation", "")
	if !ids.Valid("lic", licenseID) || !ids.Valid("act", activationID) { // hostile input: not stored in the entry
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, ErrNotFound, ErrNotFound)
	}
	var out *ent.Activation
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		l, err := visible(ctx, tx, licenseID)
		if l != nil {
			ev.Details = map[string]any{"license_id": l.ID, "product_id": l.ProductID}
		}
		if err != nil {
			return err
		}
		act, err := tx.Activation.Query().Where(activation.ID(activationID), activation.LicenseID(l.ID)).Only(ctx)
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ev.ObjectID, ev.Details["fingerprint"] = act.ID, act.Fingerprint
		if err := authz.Require(ctx, authz.ActivationManage, l.ProductID); err != nil {
			return err
		}
		// Lock order: the license row (what Activate and Deactivate lock to
		// count and free seats), then the audit lock.
		if _, err := tx.License.Query().Where(license.ID(l.ID)).
			ForUpdate(func(o *sql.LockOptions) { o.Strength = sql.LockNoKeyUpdate }).Only(ctx); ent.IsNotFound(err) {
			// Revoked: it can't be locked (license_transitions) and takes no
			// new seats, so freeing one needs no lock.
			if revoked, err := tx.License.Query().Where(license.ID(l.ID), license.RevokedAtNotNil()).Exist(ctx); err != nil || !revoked {
				return errors.Join(ErrNotFound, err)
			}
		} else if err != nil {
			return err
		}
		if act, err = tx.Activation.Get(ctx, act.ID); err != nil { // after the lock: a concurrent deactivate is visible
			return err
		}
		if act.DeactivatedAt != nil {
			out = act
			return nil
		}
		if err := free(ctx, tx, act.ID); errors.Is(err, ErrNotActivated) {
			// Freed concurrently (a revoked license is read unlocked): the same
			// answer as an already deactivated activation, with no new entry.
			out, err = tx.Activation.Get(ctx, act.ID)
			return err
		} else if err != nil {
			return err
		}
		ev.Outcome = auditevent.OutcomeSuccess
		if _, err := audit.Record(ctx, tx, tenantID, ev); err != nil {
			return err
		}
		out, err = tx.Activation.Get(ctx, act.ID)
		return err
	})
	if err != nil {
		err = audit.Refused(ctx, s.DB, tenantID, ev, err, ErrNotFound)
		if err == errHidden { //nolint:errorlint // exactly the recorded refusal (a recording failure is joined to it: a 500)
			return nil, ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

// ResetRehosts sets licenseID's rehost_count to 0 for p, the support side
// of a rehost (ADR-0039): with the old machine deactivated, the customer's
// new one can move in although the license had reached max_rehosts. Order
// of checks (ADR-0032): the license under p's product scope (missing and
// hidden alike: ErrNotFound), then activation:manage (authz.ErrDenied),
// then not revoked (ErrState). A count already at 0 is returned unchanged
// and not audited. The license lock is the one activations take, so a
// reset and a seat move serialize. Refusals are audited in a transaction of
// their own.
func (s Service) ResetRehosts(ctx context.Context, p authz.Principal, licenseID string) (*ent.License, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	ev := audit.By(p, "license.rehosts_reset", "license", "")
	if !ids.Valid("lic", licenseID) { // hostile input: not stored in the entry
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, ErrNotFound, ErrNotFound)
	}
	var out *ent.License
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		l, err := visible(ctx, tx, licenseID)
		if l != nil {
			ev.ObjectID, ev.Details = l.ID, map[string]any{"product_id": l.ProductID}
		}
		if err != nil {
			return err
		}
		if err := authz.Require(ctx, authz.ActivationManage, l.ProductID); err != nil {
			return err
		}
		// A revoked license can't be locked (license_transitions): nothing
		// to reset there.
		l, err = tx.License.Query().Where(license.ID(l.ID)).
			ForUpdate(func(o *sql.LockOptions) { o.Strength = sql.LockNoKeyUpdate }).Only(ctx)
		if ent.IsNotFound(err) {
			return ErrState
		}
		if err != nil {
			return err
		}
		if l.RehostCount == 0 {
			out = l
			return nil
		}
		ev.Details["previous_rehost_count"], ev.Details["max_rehosts"] = l.RehostCount, l.MaxRehosts
		if out, err = tx.License.UpdateOne(l).SetRehostCount(0).Save(ctx); err != nil {
			return err
		}
		ev.Outcome = auditevent.OutcomeSuccess
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		err = audit.Refused(ctx, s.DB, tenantID, ev, err, ErrNotFound, ErrState)
		if err == errHidden { //nolint:errorlint // exactly the recorded refusal (a recording failure is joined to it: a 500)
			return nil, ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

// ActiveSeats counts the activations holding a seat (not deactivated) of
// each of licenseIDs in p's product scope (license:read); licenses with
// none, or hidden, are absent.
func (s Service) ActiveSeats(ctx context.Context, p authz.Principal, licenseIDs ...string) (map[string]int, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	all, products, err := authz.Products(ctx, authz.LicenseRead)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		LicenseID string `json:"license_id"`
		Count     int    `json:"count"`
	}
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := tx.Activation.Query().Where(activation.LicenseIDIn(licenseIDs...), activation.DeactivatedAtIsNil())
		if !all {
			q.Where(activation.HasLicenseWith(license.ProductIDIn(products...)))
		}
		return q.GroupBy(activation.FieldLicenseID).Aggregate(ent.Count()).Scan(ctx, &rows)
	})
	out := map[string]int{}
	for _, r := range rows {
		out[r.LicenseID] = r.Count
	}
	return out, err
}
