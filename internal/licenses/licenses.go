// Package licenses issues licenses and moves them through their lifecycle:
// active, suspended, revoked (ADR-0013). Issuing copies the plan's terms and
// features, with per-license overrides checked against the product's feature
// catalog (ADR-0015), into the license, so later plan edits don't change it.
// The key is stored encrypted with a lookup hash (ADR-0025). Every change is
// written to the audit log in the same transaction, and every refused
// attempt in one of its own (ADR-0027).
package licenses

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/customer"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/ent/plan"
	"licenseforge.io/licenseforge/internal/store/ent/planfeature"
	"licenseforge.io/licenseforge/internal/store/ent/product"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/schema"
)

var (
	// ErrInvalid means the request is malformed or names a plan, customer or
	// feature that doesn't exist in the tenant (another tenant's looks the same).
	ErrInvalid = errors.New("licenses: invalid request")
	// ErrNotFound means there is no such license, or no such product, that the
	// caller can see: outside the caller's product scope looks the same
	// (ADR-0032: not found rather than forbidden).
	ErrNotFound = errors.New("licenses: not found")
	// ErrState means the license's status doesn't allow the change (e.g.
	// reinstating a revoked license; revocation is final).
	ErrState = errors.New("licenses: not allowed in the license's status")

	// errNoProduct answers a missing, hidden or malformed product_id alike
	// (ADR-0032: a body reference).
	errNoProduct = fmt.Errorf("%w: no such product", ErrInvalid)
)

// hidden is an object outside the principal's product scope: recorded as
// denied, answered with visible, the same error as a missing object.
type hidden struct{ visible error }

func (h hidden) Error() string { return "licenses: outside the principal's product scope" }

const maxLimit = 1<<53 - 1 // license format: limits are -1 … 2^53-1

// Service works on the tenant pool. Keys encrypts license keys.
type Service struct {
	DB   *store.DB
	Keys *secrets.Keyring
}

// Override changes one feature for one license (an enterprise deal): Remove
// drops it (a no-op if the plan doesn't grant it); otherwise a boolean feature is granted, and a limit feature gets
// Limit (required, -1 = unlimited).
type Override struct {
	Remove bool
	Limit  *int64
}

// IssueRequest is a license to issue.
type IssueRequest struct {
	ProductID, PlanID, CustomerID string
	Type                          license.Type        // "" = paid
	Overrides                     map[string]Override // by feature key
	ExternalRefs                  map[string]string   // order, CRM, ERP IDs; see validRefs
}

// Issued is a new license. Key is the plaintext license key: returned here
// once, stored only encrypted.
type Issued struct {
	License *ent.License
	Key     string
}

// Issue issues a license for p's tenant. Order of checks (ADR-0032): the
// request's format, the product (missing, hidden and malformed alike:
// ErrInvalid), license:issue on it (authz.ErrDenied), then plan, customer
// and overrides.
func (s Service) Issue(ctx context.Context, p authz.Principal, req IssueRequest) (Issued, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Issued{}, err
	}
	ev := event(p, "license.issue", "")
	if req.Type == "" {
		req.Type = license.TypePaid
	}
	if req.ExternalRefs == nil {
		req.ExternalRefs = map[string]string{}
	}
	switch {
	case !ids.Valid("prd", req.ProductID):
		return Issued{}, s.refused(ctx, tenantID, ev, errNoProduct)
	case !ids.Valid("pln", req.PlanID) || !ids.Valid("cus", req.CustomerID) || license.TypeValidator(req.Type) != nil:
		return Issued{}, s.refused(ctx, tenantID, ev, fmt.Errorf("%w: plan, customer or type", ErrInvalid))
	case !validRefs(req.ExternalRefs):
		return Issued{}, s.refused(ctx, tenantID, ev, fmt.Errorf("%w: external_refs: at most 20, keys of 1-64 [a-z0-9_.-], values of up to 255 bytes of UTF-8 without control characters", ErrInvalid))
	}
	id, key := ids.License(), licensekey.New() // New returns the canonical form, which Normalize gives at lookup
	ct, err := s.Keys.Encrypt([]byte(key), secrets.Binding{Purpose: secrets.PurposeLicenseKey, TenantID: tenantID, RowID: id})
	if err != nil {
		return Issued{}, err
	}
	lookup, err := s.Keys.LookupHash(secrets.PurposeLicenseKey, []byte(key))
	if err != nil {
		return Issued{}, err
	}
	var row *ent.License
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		if authz.Require(ctx, authz.LicenseRead, req.ProductID) != nil {
			return hidden{errNoProduct}
		}
		ok, err := tx.Product.Query().Where(product.ID(req.ProductID)).Exist(ctx) // another tenant's: not visible under RLS
		if err != nil {
			return err
		}
		if !ok {
			return errNoProduct
		}
		if err := authz.Require(ctx, authz.LicenseIssue, req.ProductID); err != nil {
			return err
		}
		now, err := dbNow(ctx, tx)
		if err != nil {
			return err
		}
		// FOR SHARE: plan-feature writers lock the plan row FOR UPDATE first
		// (schema.PlanFeature), so the terms and features copied below are
		// from one version of the plan.
		pl, err := tx.Plan.Query().Where(plan.ID(req.PlanID), plan.ArchivedAtIsNil()).ForShare().Only(ctx)
		if ent.IsNotFound(err) || err == nil && pl.ProductID != req.ProductID {
			return fmt.Errorf("%w: no such plan for the product", ErrInvalid)
		}
		if err != nil {
			return err
		}
		ok, err = tx.Customer.Query().Where(customer.ID(req.CustomerID), customer.ArchivedAtIsNil()).Exist(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: no such customer", ErrInvalid)
		}
		ents, err := entitlements(ctx, tx, pl, req.Overrides)
		if err != nil {
			return err
		}
		c := tx.License.Create().SetID(id).SetTenantID(tenantID).SetProductID(pl.ProductID).SetPlanID(pl.ID).
			SetCustomerID(req.CustomerID).SetType(req.Type).
			SetKeyCiphertext(ct).SetKeyLookup(lookup).SetKeyHint(key[len(key)-6:]).
			SetPlanSlug(pl.Slug).SetExpiryBasis(license.ExpiryBasis(pl.ExpiryBasis)).
			SetNillableDurationMonths(pl.DurationMonths).SetNillableDurationSeconds(pl.DurationSeconds).
			SetNillableMaxActivations(pl.MaxActivations).SetNillableMaxRehosts(pl.MaxRehosts).
			SetBindType(license.BindType(pl.BindType)).SetOfflineAllowed(pl.OfflineAllowed).
			SetLeaseSeconds(pl.LeaseSeconds).SetNillableMaxOfflineSeconds(pl.MaxOfflineSeconds).
			SetGraceSeconds(pl.GraceSeconds).SetEntitlements(ents).SetExternalRefs(req.ExternalRefs).
			SetIssuedAt(now)
		// from_first_activation: the term starts at first activation (nil until then).
		if pl.ExpiryBasis == plan.ExpiryBasisFromIssue {
			c.SetNillableExpiresAt(expiry(now, pl.DurationMonths, pl.DurationSeconds))
		}
		if row, err = c.Save(ctx); err != nil {
			return err
		}
		ev.ObjectID, ev.Outcome = row.ID, auditevent.OutcomeSuccess
		// What was granted: no key material.
		overrides := map[string]any{}
		for k, o := range req.Overrides {
			switch {
			case o.Remove:
				overrides[k] = "removed"
			case o.Limit != nil:
				overrides[k] = *o.Limit
			default:
				overrides[k] = "granted"
			}
		}
		var expires any
		if row.ExpiresAt != nil {
			expires = row.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		ev.Details = map[string]any{"product_id": row.ProductID, "plan_id": row.PlanID, "plan_slug": row.PlanSlug,
			"customer_id": row.CustomerID, "type": string(row.Type), "expires_at": expires, "overrides": overrides}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		ev.ObjectID, ev.Details = "", nil
		return Issued{}, s.refused(ctx, tenantID, ev, err)
	}
	return Issued{License: row, Key: key}, nil
}

// entitlements resolves the plan's features with the overrides applied. Each
// override must name a feature of the product, match its type and range, and
// may only add a feature that isn't archived.
func entitlements(ctx context.Context, tx *ent.Tx, pl *ent.Plan, overrides map[string]Override) (schema.LicenseEntitlements, error) {
	pfs, err := tx.PlanFeature.Query().Where(planfeature.PlanID(pl.ID)).WithFeature().All(ctx)
	if err != nil {
		return schema.LicenseEntitlements{}, err
	}
	bools, limits := map[string]bool{}, map[string]int64{}
	for _, pf := range pfs {
		if pf.LimitValue != nil {
			limits[pf.Edges.Feature.Key] = *pf.LimitValue
		} else {
			bools[pf.Edges.Feature.Key] = true
		}
	}
	if len(overrides) > 0 {
		catalog, err := tx.Feature.Query().Where(feature.ProductID(pl.ProductID), feature.KeyIn(slices.Collect(maps.Keys(overrides))...)).All(ctx)
		if err != nil {
			return schema.LicenseEntitlements{}, err
		}
		byKey := map[string]*ent.Feature{}
		for _, f := range catalog {
			byKey[f.Key] = f
		}
		for _, k := range slices.Sorted(maps.Keys(overrides)) { // sorted: the same error for the same request
			o, f := overrides[k], byKey[k]
			switch {
			case f == nil:
				return schema.LicenseEntitlements{}, fmt.Errorf("%w: unknown feature %q", ErrInvalid, k)
			case o.Remove && o.Limit != nil, f.Type == feature.TypeBoolean && o.Limit != nil:
				return schema.LicenseEntitlements{}, fmt.Errorf("%w: feature %q takes no limit", ErrInvalid, k)
			case o.Remove:
				delete(bools, k)
				delete(limits, k)
			case f.ArchivedAt != nil:
				return schema.LicenseEntitlements{}, fmt.Errorf("%w: feature %q is archived", ErrInvalid, k)
			case f.Type == feature.TypeBoolean:
				bools[k] = true
			case o.Limit == nil || *o.Limit < -1 || *o.Limit > maxLimit:
				return schema.LicenseEntitlements{}, fmt.Errorf("%w: feature %q needs a limit from -1 to 2^53-1", ErrInvalid, k)
			default:
				limits[k] = *o.Limit
			}
		}
	}
	return schema.LicenseEntitlements{Features: slices.Sorted(maps.Keys(bools)), Limits: limits}, nil
}

// expiry is start plus the term; nil for a perpetual plan. Months are
// calendar months, clamped to the month's last day (Jan 31 + 1 month = Feb
// 28/29), as billing periods are, rather than Go's normalisation into March.
func expiry(start time.Time, months *int, seconds *int64) *time.Time {
	var t time.Time
	switch {
	case months != nil:
		y, m, d := start.Date()
		first := time.Date(y, m+time.Month(*months), 1, 0, 0, 0, 0, start.Location())
		last := first.AddDate(0, 1, -1).Day()
		h, mi, s := start.Clock()
		t = time.Date(first.Year(), first.Month(), min(d, last), h, mi, s, start.Nanosecond(), start.Location())
	case seconds != nil:
		t = start.Add(time.Duration(*seconds) * time.Second)
	default:
		return nil
	}
	return &t
}

// transition is one status change: the statuses it starts from and the SQL
// that applies it. Times come from the database clock.
type transition struct {
	action string
	from   []license.Status
	set    string
}

var (
	suspend   = transition{"license.suspend", []license.Status{license.StatusActive}, `status = 'suspended', suspended_at = clock_timestamp()`}
	reinstate = transition{"license.reinstate", []license.Status{license.StatusSuspended}, `status = 'active', suspended_at = NULL`}
	// Revocation is final: no transition starts from revoked.
	revoke = transition{"license.revoke", []license.Status{license.StatusActive, license.StatusSuspended}, `status = 'revoked', revoked_at = clock_timestamp(), suspended_at = NULL`}
)

// Suspend suspends an active license. p needs license:write on its product.
func (s Service) Suspend(ctx context.Context, p authz.Principal, licenseID string) (*ent.License, error) {
	return s.change(ctx, p, licenseID, suspend)
}

// Reinstate makes a suspended license active again. A revoked license can't
// be reinstated.
func (s Service) Reinstate(ctx context.Context, p authz.Principal, licenseID string) (*ent.License, error) {
	return s.change(ctx, p, licenseID, reinstate)
}

// Revoke revokes an active or suspended license, finally.
func (s Service) Revoke(ctx context.Context, p authz.Principal, licenseID string) (*ent.License, error) {
	return s.change(ctx, p, licenseID, revoke)
}

func (s Service) change(ctx context.Context, p authz.Principal, licenseID string, t transition) (*ent.License, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	ev := event(p, t.action, "")
	// Order of checks (ADR-0032): ID format, lookup under the product scope
	// (missing and hidden alike: ErrNotFound), then license:write.
	if !ids.Valid("lic", licenseID) { // hostile input: not stored in the entry
		return nil, s.refused(ctx, tenantID, ev, ErrNotFound)
	}
	var row *ent.License
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		// Lock order (internal/issue): the license row, then the audit lock.
		l, err := tx.License.Query().Where(license.ID(licenseID)).ForUpdate().Only(ctx)
		if ent.IsNotFound(err) {
			return ErrNotFound // the entry names no object: it isn't this tenant's
		}
		if err != nil {
			return err
		}
		ev.ObjectID = l.ID // recorded even when hidden; only the answer hides it
		if authz.Require(ctx, authz.LicenseRead, l.ProductID) != nil {
			return hidden{ErrNotFound}
		}
		if err := authz.Require(ctx, authz.LicenseWrite, l.ProductID); err != nil {
			return err
		}
		if !slices.Contains(t.from, l.Status) {
			return fmt.Errorf("%w: license is %s", ErrState, l.Status)
		}
		// Guarded and counted: ent's UpdateOneID would hide a zero-row update.
		res, err := tx.ExecContext(ctx, `UPDATE licenses SET `+t.set+`, updated_at = clock_timestamp() WHERE id = $1 AND status = $2`, l.ID, l.Status)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(fmt.Errorf("%w: license changed concurrently", ErrState), err)
		}
		if row, err = tx.License.Get(ctx, l.ID); err != nil {
			return err
		}
		ev.Outcome = auditevent.OutcomeSuccess
		ev.Details = map[string]any{"from": string(l.Status), "to": string(row.Status), "product_id": l.ProductID}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		ev.Details = nil
		if errors.Is(err, ErrState) {
			ev.Details = map[string]any{"reason": err.Error()}
		}
		return nil, s.refused(ctx, tenantID, ev, err)
	}
	return row, nil
}

// dbNow is the database clock, as stored (microseconds), in UTC so calendar
// months are counted in UTC.
func dbNow(ctx context.Context, tx *ent.Tx) (time.Time, error) {
	rows, err := tx.QueryContext(ctx, `SELECT clock_timestamp()`)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = rows.Close() }()
	var now time.Time
	if !rows.Next() {
		return time.Time{}, errors.Join(errors.New("licenses: clock query returned no row"), rows.Err())
	}
	if err := rows.Scan(&now); err != nil {
		return time.Time{}, err
	}
	return now.UTC().Truncate(time.Microsecond), nil
}

// validRefs: at most 20 entries, keys of 1-64 bytes of [a-z0-9_.-], values
// of up to 255 bytes of valid UTF-8 without control characters (incl. NUL).
func validRefs(refs map[string]string) bool {
	if len(refs) > 20 {
		return false
	}
	for k, v := range refs {
		if !refKeyRE.MatchString(k) || len(v) > 255 || !utf8.ValidString(v) || strings.ContainsFunc(v, unicode.IsControl) {
			return false
		}
	}
	return true
}

var refKeyRE = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

func event(p authz.Principal, action, objectID string) audit.Event {
	actor := auditevent.ActorTypeUser
	if p.Kind == authz.Token {
		actor = auditevent.ActorTypeToken
	}
	return audit.Event{ActorType: actor, ActorID: p.ID, Action: action, ObjectType: "license", ObjectID: objectID}
}

// refused records a denied or failed attempt in its own transaction
// (ADR-0027) and returns the caller's error. Infrastructure errors aren't
// attempts.
func (s Service) refused(ctx context.Context, tenantID string, ev audit.Event, err error) error {
	var h hidden
	switch {
	case errors.As(err, &h):
		ev.Outcome, err = auditevent.OutcomeDenied, h.visible
	case errors.Is(err, authz.ErrDenied):
		ev.Outcome = auditevent.OutcomeDenied
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrNotFound), errors.Is(err, ErrState):
		ev.Outcome = auditevent.OutcomeFailure
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
