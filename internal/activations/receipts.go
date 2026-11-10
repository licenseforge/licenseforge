package activations

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// ErrSuperseded: the machine's seat is out, but the receipt names another
// file than its current one (an older one: renewed since; or none issued for
// it); only the current file's receipt returns it (ADR-0043).
var ErrSuperseded = errors.New("activations: the receipt isn't for the seat's current file (renewed since, or not a file issued for it)")

var receiptRefusals = []error{ErrInvalid, ErrNotFound, ErrSuperseded}

// Return frees an offline seat on a deactivation receipt (ADR-0043): the
// lfrcpt1 text the machine's SDK wrote after deleting its license file,
// carried in by p (activation:offline on the license's product). The seat
// is freed when the receipt's file_sha256 is the activation's current file.
// A receipt for a file whose seat is already free (returned before, or
// deactivated from the dashboard) answers that activation unchanged and
// isn't audited again; an older file of a seat still out is ErrSuperseded.
//
// Order of checks (ADR-0032): the receipt's shape and tenant (ErrInvalid),
// the license under p's product scope (missing and hidden alike:
// ErrNotFound), activation:offline (authz.ErrDenied), then the seat
// (ErrNotFound when no file of that machine matches). Allowed whatever the
// license's status, as DeactivateByID. Audited with the receipt's hash;
// refusals in a transaction of their own.
func (s Service) Return(ctx context.Context, p authz.Principal, receipt string) (*ent.Activation, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	ev := audit.By(p, "activation.offline_return", "activation", "")
	ev.Details = map[string]any{"receipt_sha256": licensefile.OfflineSHA256(receipt)}
	var out *ent.Activation
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		out, err = s.ret(ctx, tx, tenantID, receipt, &ev)
		return err
	})
	if err == nil {
		return out, nil
	}
	outcome, ok := refusalOutcome(err, receiptRefusals)
	if !ok { // an outage: a 500, whatever it wraps
		return nil, fmt.Errorf("activations: offline return: %v", err) //nolint:errorlint // deliberately not matchable
	}
	ev.Outcome, ev.Details["reason"] = outcome, err.Error()
	if errors.Is(err, ErrInvalid) {
		ev.Details["reason"] = ErrInvalid.Error() // the details echo the receipt: never in the chain
	}
	if rerr := s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, tenantID, ev)
		return err
	}); rerr != nil { // not the refusal: an unrecorded refusal is a 500
		return nil, fmt.Errorf("activations: recording a refused offline return: %w", rerr)
	}
	if err == errHidden { //nolint:errorlint // exactly the recorded refusal
		return nil, ErrNotFound
	}
	return nil, err
}

func (s Service) ret(ctx context.Context, tx *ent.Tx, tenantID, text string, ev *audit.Event) (*ent.Activation, error) {
	r, err := licensefile.ParseReceipt(text)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if r.Tenant != tenantID {
		return nil, fmt.Errorf("%w: the receipt is for tenant %q", ErrInvalid, r.Tenant)
	}
	if !ids.Valid("lic", r.LicenseID) {
		return nil, ErrNotFound
	}
	l, err := tx.License.Query().Where(license.ID(r.LicenseID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ev.Details["license_id"], ev.Details["product_id"], ev.Details["fingerprint"], ev.Details["file_sha256"] = l.ID, l.ProductID, r.Fingerprint, r.FileSHA256
	licenseDetails(ev.Details, l, "offline")
	if authz.Require(ctx, authz.ActivationRead, l.ProductID) != nil {
		return nil, errHidden
	}
	if err := authz.Require(ctx, authz.ActivationOffline, l.ProductID); err != nil {
		return nil, err
	}
	// Lock order: the license row (what seat takers lock), then the audit
	// lock. A revoked license can't be locked (license_transitions) and takes
	// no new seats, so freeing one needs no lock.
	if _, err := tx.License.Query().Where(license.ID(l.ID)).
		ForUpdate(func(o *sql.LockOptions) { o.Strength = sql.LockNoKeyUpdate }).Only(ctx); ent.IsNotFound(err) {
		revoked, err := tx.License.Query().Where(license.ID(l.ID), license.RevokedAtNotNil()).Exist(ctx)
		if err != nil {
			return nil, err // an outage, not "not found"
		}
		if !revoked {
			return nil, ErrNotFound
		}
	} else if err != nil {
		return nil, err
	}
	mine := tx.Activation.Query().Where(activation.LicenseID(l.ID), activation.Fingerprint(r.Fingerprint), activation.ModeEQ(activation.ModeOffline))
	act, err := mine.Clone().Where(activation.OfflineFileSha256(r.FileSHA256)).Order(ent.Desc(activation.FieldCreatedAt)).First(ctx)
	switch {
	case err == nil:
		ev.ObjectID = act.ID
		if err := free(ctx, tx, act.ID); errors.Is(err, ErrNotActivated) {
			// Already free (returned before, deactivated from the dashboard, or
			// concurrently: a revoked license is read unlocked): the seat
			// unchanged, no new entry.
			return tx.Activation.Get(ctx, act.ID)
		} else if err != nil {
			return nil, err
		}
		ev.Outcome = auditevent.OutcomeSuccess
		if _, err := audit.Record(ctx, tx, tenantID, *ev); err != nil {
			return nil, err
		}
		return tx.Activation.Get(ctx, act.ID)
	case !ent.IsNotFound(err):
		return nil, err
	}
	out, err := mine.Where(activation.DeactivatedAtIsNil()).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if out {
		return nil, ErrSuperseded
	}
	return nil, ErrNotFound
}

// refusalOutcome classifies err like audit.Refused: denied, a failure
// among refusals, or not a refusal (an outage: unrecorded).
func refusalOutcome(err error, refusals []error) (auditevent.Outcome, bool) {
	if errors.Is(err, authz.ErrDenied) {
		return auditevent.OutcomeDenied, true
	}
	for _, f := range refusals {
		if errors.Is(err, f) {
			return auditevent.OutcomeFailure, true
		}
	}
	return "", false
}
