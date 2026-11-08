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
	"entgo.io/ent/dialect/sql"
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
	"licenseforge.io/licenseforge/internal/store/ent/activation"
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
	errNoProduct = &InvalidError{"/product_id", "no such product"}
)

// InvalidError is an ErrInvalid naming the request field it is about, as a
// JSON Pointer into the issue request (product_id, plan_id, customer_id,
// type, external_refs, overrides/<feature key>).
type InvalidError struct{ Field, Message string }

func (e *InvalidError) Error() string {
	return "licenses: invalid request: " + e.Field + ": " + e.Message
}
func (e *InvalidError) Unwrap() error { return ErrInvalid }

// pointer escapes a JSON object key as a JSON Pointer token (RFC 6901).
var pointer = strings.NewReplacer("~", "~0", "/", "~1")

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
	ExternalRefs                  map[string]string   // order, CRM, ERP IDs; see ValidRefs
}

// Issued is a new license. Key is the plaintext license key: returned here
// once, stored only encrypted.
type Issued struct {
	License *ent.License
	Key     string
}

// Issue issues a license for p's tenant. Order of checks (ADR-0032): the
// product (missing, hidden and malformed alike: an InvalidError on
// /product_id), license:issue on it (authz.ErrDenied), then plan, customer,
// type, external refs and overrides (InvalidError). A refusal is recorded in
// a transaction of its own.
func (s Service) Issue(ctx context.Context, p authz.Principal, req IssueRequest) (Issued, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Issued{}, err
	}
	var out Issued
	var ev audit.Event
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		out, ev, err = s.issue(ctx, tx, tenantID, p, req)
		return err
	})
	if err != nil {
		return Issued{}, s.refused(ctx, tenantID, ev, err)
	}
	return out, nil
}

// IssueTx is Issue in tx, a WithTenant transaction of p's tenant (an
// idempotency.Store.Do operation): a refusal is recorded in tx, so it
// commits with the stored outcome.
func (s Service) IssueTx(ctx context.Context, tx *ent.Tx, p authz.Principal, req IssueRequest) (Issued, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Issued{}, err
	}
	out, ev, err := s.issue(ctx, tx, tenantID, p, req)
	if err != nil {
		o, visible, ok := classify(err)
		if !ok {
			return Issued{}, err
		}
		ev.Outcome = o
		if _, rerr := audit.Record(ctx, tx, tenantID, ev); rerr != nil {
			// Not the refusal (a 4xx would be stored without its entry): an
			// outage, so Do rolls back and stores nothing.
			return Issued{}, fmt.Errorf("licenses: recording a refused issue: %w", rerr)
		}
		return Issued{}, visible
	}
	return out, nil
}

// RecheckIssue repeats Issue's product and permission checks in tx, for a
// replayed idempotent issue (idempotency.Store.Do's recheck): p must still
// see productID and hold license:issue on it. Only the product is checked
// again: plans and customers have no visibility beyond the tenant, and
// licenses are never deleted. A refusal is recorded in a transaction of its
// own (Do rolls back tx). The replayed body is the issue-time snapshot;
// clients GET the license for its current status.
func (s Service) RecheckIssue(ctx context.Context, tx *ent.Tx, p authz.Principal, productID string) error {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return err
	}
	if err := checkProduct(ctx, tx, productID); err != nil {
		ev := event(p, "license.issue", "")
		ev.Details = map[string]any{"replay": true}
		if ids.Valid("prd", productID) {
			ev.Details["product_id"] = productID
		}
		return s.refused(ctx, tenantID, ev, err)
	}
	return nil
}

// RecordKeyReveal records that p was shown licenseID's key again (a replayed
// idempotent issue), as every key reveal is (ADR-0025): no key material.
func (s Service) RecordKeyReveal(ctx context.Context, p authz.Principal, licenseID, productID string) error {
	if !ids.Valid("lic", licenseID) || !ids.Valid("prd", productID) {
		return errors.New("licenses: key reveal of a malformed license or product ID")
	}
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return err
	}
	ev := event(p, "license.key_reveal", licenseID)
	ev.Outcome, ev.Details = auditevent.OutcomeSuccess, map[string]any{"reason": "idempotent_replay", "product_id": productID}
	return s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, tenantID, ev)
		return err
	})
}

// checkProduct: the product exists, p sees it and may issue for it. One
// lookup, then the scope: missing and hidden do the same work.
func checkProduct(ctx context.Context, tx *ent.Tx, productID string) error {
	if !ids.Valid("prd", productID) {
		return errNoProduct
	}
	ok, err := tx.Product.Query().Where(product.ID(productID)).Exist(ctx) // another tenant's: not visible under RLS
	if err != nil {
		return err
	}
	if !ok {
		return errNoProduct
	}
	if authz.Require(ctx, authz.LicenseRead, productID) != nil {
		return hidden{errNoProduct}
	}
	return authz.Require(ctx, authz.LicenseIssue, productID)
}

// issue does Issue's work in tx and returns the audit event: the success
// entry is recorded in tx; on error ev is the refusal to record.
func (s Service) issue(ctx context.Context, tx *ent.Tx, tenantID string, p authz.Principal, req IssueRequest) (Issued, audit.Event, error) {
	ev := event(p, "license.issue", "")
	// Refusals name the well-formed IDs the caller sent (never anything else).
	refusal := map[string]any{}
	for k, v := range map[string]string{"product_id": req.ProductID, "plan_id": req.PlanID, "customer_id": req.CustomerID} {
		if ids.Valid(map[string]string{"product_id": "prd", "plan_id": "pln", "customer_id": "cus"}[k], v) {
			refusal[k] = v
		}
	}
	if len(refusal) > 0 {
		ev.Details = refusal
	}
	refused := func(err error) (Issued, audit.Event, error) {
		ev.ObjectID, ev.Details = "", nil
		if len(refusal) > 0 {
			ev.Details = refusal
		}
		return Issued{}, ev, err
	}
	if req.Type == "" {
		req.Type = license.TypePaid
	}
	if req.ExternalRefs == nil {
		req.ExternalRefs = map[string]string{}
	}
	// Steps 4-5 first; the values only after (ADR-0032).
	if err := checkProduct(ctx, tx, req.ProductID); err != nil {
		return refused(err)
	}
	// No new license on an archived product (ADR-0015). FOR SHARE: an archive
	// (FOR UPDATE, internal/catalog) waits for this issue, or wins first.
	lock := func() (*ent.Product, error) {
		return tx.Product.Query().Where(product.ID(req.ProductID)).ForShare().Only(ctx)
	}
	pr, err := lock()
	if ent.IsNotFound(err) {
		// Locked after waiting for a concurrent archive, the row is rechecked
		// as its newer version, which archive_once filters (its subquery reads
		// this statement's snapshot): a second statement sees it archived.
		pr, err = lock()
	}
	if ent.IsNotFound(err) { // gone since checkProduct: like a missing product
		return refused(errNoProduct)
	}
	if err != nil {
		return Issued{}, ev, err
	} else if pr.ArchivedAt != nil {
		return refused(&InvalidError{"/product_id", "the product is archived"})
	}
	switch {
	case !ids.Valid("pln", req.PlanID):
		return refused(&InvalidError{"/plan_id", "no such plan for the product"})
	case !ids.Valid("cus", req.CustomerID):
		return refused(&InvalidError{"/customer_id", "no such customer"})
	case license.TypeValidator(req.Type) != nil:
		return refused(&InvalidError{"/type", "unknown license type"})
	case !ValidRefs(req.ExternalRefs):
		return refused(&InvalidError{"/external_refs", "at most 20, keys of 1-64 [a-z0-9_.-], values of up to 255 bytes of UTF-8 without control characters"})
	}
	id, key := ids.License(), licensekey.New() // New returns the canonical form, which Normalize gives at lookup
	ct, err := s.Keys.Encrypt([]byte(key), secrets.Binding{Purpose: secrets.PurposeLicenseKey, TenantID: tenantID, RowID: id})
	if err != nil {
		return Issued{}, ev, err
	}
	lookup, err := s.Keys.LookupHash(secrets.PurposeLicenseKey, []byte(key))
	if err != nil {
		return Issued{}, ev, err
	}
	now, err := DBNow(ctx, tx)
	if err != nil {
		return Issued{}, ev, err
	}
	// FOR SHARE: plan-feature writers lock the plan row FOR UPDATE first
	// (schema.PlanFeature), so the terms and features copied below are
	// from one version of the plan.
	pl, err := tx.Plan.Query().Where(plan.ID(req.PlanID), plan.ArchivedAtIsNil()).ForShare().Only(ctx)
	if ent.IsNotFound(err) || err == nil && pl.ProductID != req.ProductID {
		return refused(&InvalidError{"/plan_id", "no such plan for the product"})
	}
	if err != nil {
		return Issued{}, ev, err
	}
	// FOR SHARE: a concurrent archive waits for this issue (or wins first).
	cus, err := tx.Customer.Query().Where(customer.ID(req.CustomerID), customer.ArchivedAtIsNil()).ForShare().IDs(ctx)
	if err != nil {
		return Issued{}, ev, err
	}
	if len(cus) == 0 {
		return refused(&InvalidError{"/customer_id", "no such customer"})
	}
	ents, err := entitlements(ctx, tx, pl, req.Overrides)
	if errors.Is(err, ErrInvalid) {
		return refused(err)
	}
	if err != nil {
		return Issued{}, ev, err
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
		SetIssuedAt(now).SetCreatedAt(now).SetUpdatedAt(now) // one clock for the row (ADR-0032 lists sort by created_at)
	// from_first_activation: the term starts at first activation (nil until then).
	if pl.ExpiryBasis == plan.ExpiryBasisFromIssue {
		c.SetNillableExpiresAt(Expiry(now, pl.DurationMonths, pl.DurationSeconds))
	}
	row, err := c.Save(ctx)
	if err != nil {
		return Issued{}, ev, err
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
	if _, err := audit.Record(ctx, tx, tenantID, ev); err != nil {
		return Issued{}, ev, err
	}
	return Issued{License: row, Key: key}, ev, nil
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
		lock := func() ([]*ent.Feature, error) {
			return tx.Feature.Query().Where(feature.ProductID(pl.ProductID), feature.KeyIn(slices.Collect(maps.Keys(overrides))...)).ForShare().All(ctx)
		}
		catalog, err := lock()
		if err == nil && len(catalog) < len(overrides) {
			// A feature locked after waiting for a concurrent archive is
			// rechecked as its newer version, which archive_once filters: a
			// second statement sees it (archived), or it is really unknown.
			catalog, err = lock()
		}
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
				return schema.LicenseEntitlements{}, &InvalidError{"/overrides/" + pointer.Replace(k), "unknown feature"}
			case o.Remove && o.Limit != nil, f.Type == feature.TypeBoolean && o.Limit != nil:
				return schema.LicenseEntitlements{}, &InvalidError{"/overrides/" + pointer.Replace(k), "takes no limit"}
			case o.Remove:
				delete(bools, k)
				delete(limits, k)
			case f.ArchivedAt != nil:
				return schema.LicenseEntitlements{}, &InvalidError{"/overrides/" + pointer.Replace(k), "feature is archived"}
			case f.Type == feature.TypeBoolean:
				bools[k] = true
			case o.Limit == nil || *o.Limit < -1 || *o.Limit > maxLimit:
				return schema.LicenseEntitlements{}, &InvalidError{"/overrides/" + pointer.Replace(k), "needs a limit from -1 to 2^53-1"}
			default:
				limits[k] = *o.Limit
			}
		}
	}
	return schema.LicenseEntitlements{Features: slices.Sorted(maps.Keys(bools)), Limits: limits}, nil
}

// Expiry is start plus the term; nil for a perpetual plan. Months are
// calendar months, clamped to the month's last day (Jan 31 + 1 month = Feb
// 28/29), as billing periods are, rather than Go's normalisation into March.
func Expiry(start time.Time, months *int, seconds *int64) *time.Time {
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

// Changed is a license after a status change, with its seats taken
// (activations not deactivated), counted in the change's transaction so a
// committed change always has its answer.
type Changed struct {
	*ent.License
	ActiveActivations int
}

// Suspend suspends an active license. p needs license:write on its product.
func (s Service) Suspend(ctx context.Context, p authz.Principal, licenseID string) (Changed, error) {
	return s.change(ctx, p, licenseID, suspend)
}

// Reinstate makes a suspended license active again. A revoked license can't
// be reinstated.
func (s Service) Reinstate(ctx context.Context, p authz.Principal, licenseID string) (Changed, error) {
	return s.change(ctx, p, licenseID, reinstate)
}

// Revoke revokes an active or suspended license, finally.
func (s Service) Revoke(ctx context.Context, p authz.Principal, licenseID string) (Changed, error) {
	return s.change(ctx, p, licenseID, revoke)
}

func (s Service) change(ctx context.Context, p authz.Principal, licenseID string, t transition) (Changed, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Changed{}, err
	}
	ev := event(p, t.action, "")
	// Order of checks (ADR-0032): ID format, lookup under the product scope
	// (missing and hidden alike: ErrNotFound), then license:write.
	if !ids.Valid("lic", licenseID) { // hostile input: not stored in the entry
		return Changed{}, s.refused(ctx, tenantID, ev, ErrNotFound)
	}
	var row Changed
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		// Authorize on an unlocked read (product_id is immutable), so callers
		// who may not change the license can't hold its lock.
		l, err := tx.License.Query().Where(license.ID(licenseID)).Only(ctx)
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
		// Lock order (internal/issue): the license row, then the audit lock.
		// NO KEY UPDATE: what the UPDATE takes anyway; it still waits for an
		// export's FOR SHARE but not for activations' FK checks.
		rows, err := tx.QueryContext(ctx, `SELECT status FROM licenses WHERE id = $1 FOR NO KEY UPDATE`, l.ID)
		if err != nil {
			return err
		}
		if !rows.Next() {
			if err := errors.Join(rows.Err(), rows.Close()); err != nil {
				return err
			}
			// A revoked license can't be locked (license_transitions): it never
			// changes again, so the answer is the state error, read unlocked.
			rows, err = tx.QueryContext(ctx, `SELECT status FROM licenses WHERE id = $1 AND revoked_at IS NOT NULL`, l.ID)
			if err != nil {
				return err
			}
			if !rows.Next() {
				_ = rows.Close()
				return errors.Join(ErrNotFound, rows.Err())
			}
		}
		err = rows.Scan(&l.Status)
		if cerr := rows.Close(); err == nil {
			err = cerr
		}
		if err != nil {
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
		if row.License, err = tx.License.Get(ctx, l.ID); err != nil {
			return err
		}
		if row.ActiveActivations, err = tx.Activation.Query().Where(activation.LicenseID(l.ID), activation.DeactivatedAtIsNil()).Count(ctx); err != nil {
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
		return Changed{}, s.refused(ctx, tenantID, ev, err)
	}
	return row, nil
}

// Filter narrows List; zero fields don't filter. A filter naming a missing
// or hidden object gives an empty list (ADR-0032).
type Filter struct {
	ProductID, CustomerID       string
	Status                      license.Status
	CreatedAfter, CreatedBefore *time.Time
}

// Counts returns how many licenses p can see have each status, exactly
// (license:read; a product-scoped principal counts its products only), with
// every status present. One GROUP BY query under the tenant's RLS. Lists
// carry no totals (ADR-0032); this is for the dashboard summary.
func (s Service) Counts(ctx context.Context, p authz.Principal) (map[license.Status]int, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	all, products, err := authz.Products(ctx, authz.LicenseRead)
	if err != nil {
		return nil, err
	}
	out := map[license.Status]int{license.StatusActive: 0, license.StatusSuspended: 0, license.StatusRevoked: 0}
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := tx.License.Query()
		if !all {
			q.Where(license.ProductIDIn(products...))
		}
		var rows []struct {
			Status license.Status `json:"status"`
			Count  int            `json:"count"`
		}
		if err := q.GroupBy(license.FieldStatus).Aggregate(ent.Count()).Scan(ctx, &rows); err != nil {
			return err
		}
		for _, r := range rows {
			out[r.Status] = r.Count
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// List returns up to limit of p's tenant's licenses in p's product scope
// (silently filtered), matching f, newest first, after (afterAt, afterID)
// or from the start if afterID is "".
func (s Service) List(ctx context.Context, p authz.Principal, f Filter, limit int, afterAt time.Time, afterID string) ([]*ent.License, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	all, products, err := authz.Products(ctx, authz.LicenseRead)
	if err != nil {
		return nil, err
	}
	var out []*ent.License
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := tx.License.Query().Order(ent.Desc(license.FieldCreatedAt), ent.Desc(license.FieldID)).Limit(limit)
		if !all {
			q.Where(license.ProductIDIn(products...))
		}
		if f.ProductID != "" {
			q.Where(license.ProductID(f.ProductID))
		}
		if f.CustomerID != "" {
			q.Where(license.CustomerID(f.CustomerID))
		}
		if f.Status != "" {
			q.Where(license.StatusEQ(f.Status))
		}
		if f.CreatedAfter != nil {
			q.Where(license.CreatedAtGT(*f.CreatedAfter))
		}
		if f.CreatedBefore != nil {
			q.Where(license.CreatedAtLT(*f.CreatedBefore))
		}
		if afterID != "" {
			// A row comparison, so the (tenant_id, created_at, id) index seeks
			// to the cursor instead of filtering every newer row.
			q.Where(func(s *sql.Selector) {
				s.Where(sql.CompositeLT([]string{s.C(license.FieldCreatedAt), s.C(license.FieldID)}, afterAt, afterID))
			})
		}
		var err error
		out, err = q.All(ctx)
		return err
	})
	return out, err
}

// Get returns one of p's tenant's licenses; missing, malformed and outside
// p's product scope are ErrNotFound alike.
func (s Service) Get(ctx context.Context, p authz.Principal, licenseID string) (*ent.License, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	if !ids.Valid("lic", licenseID) {
		return nil, ErrNotFound
	}
	var l *ent.License
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		l, err = tx.License.Query().Where(license.ID(licenseID)).Only(ctx)
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if authz.Require(ctx, authz.LicenseRead, l.ProductID) != nil {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

// DBNow is the database clock, as stored (microseconds), in UTC so calendar
// months are counted in UTC.
func DBNow(ctx context.Context, tx *ent.Tx) (time.Time, error) {
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

// ValidRefs reports whether external refs (licenses, customers) are valid: at most 20 entries, keys of 1-64 bytes of [a-z0-9_.-], values
// of up to 255 bytes of valid UTF-8 without control, format or separator
// characters (incl. NUL, zero-width and bidi controls).
func ValidRefs(refs map[string]string) bool {
	if len(refs) > 20 {
		return false
	}
	for k, v := range refs {
		if !refKeyRE.MatchString(k) || len(v) > 255 || !utf8.ValidString(v) || strings.ContainsFunc(v, invisible) {
			return false
		}
	}
	return true
}

var refKeyRE = regexp.MustCompile(`^[a-z0-9_.-]{1,64}$`)

// invisible: control and format characters (zero-width, bidi overrides) and
// line or paragraph separators, which make a value read differently than it is.
func invisible(r rune) bool { return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) }

func event(p authz.Principal, action, objectID string) audit.Event {
	actor := auditevent.ActorTypeUser
	if p.Kind == authz.Token {
		actor = auditevent.ActorTypeToken
	}
	return audit.Event{ActorType: actor, ActorID: p.ID, Action: action, ObjectType: "license", ObjectID: objectID}
}

// classify returns a refusal's audit outcome and the error to answer with
// (a hidden object answers like a missing one); ok is false for an outage,
// which isn't an attempt.
func classify(err error) (o auditevent.Outcome, visible error, ok bool) {
	var h hidden
	switch {
	case errors.As(err, &h):
		return auditevent.OutcomeDenied, h.visible, true
	case errors.Is(err, authz.ErrDenied):
		return auditevent.OutcomeDenied, err, true
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrNotFound), errors.Is(err, ErrState):
		return auditevent.OutcomeFailure, err, true
	}
	return "", err, false
}

// refused records a denied or failed attempt in its own transaction
// (ADR-0027) and returns the caller's error. Infrastructure errors aren't
// attempts.
func (s Service) refused(ctx context.Context, tenantID string, ev audit.Event, err error) error {
	o, visible, ok := classify(err)
	if !ok {
		return err
	}
	ev.Outcome, err = o, visible
	if rerr := s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, tenantID, ev)
		return err
	}); rerr != nil {
		// Fail closed: an outage (500), never the refusal without its entry.
		// Not covered by a test: the audit write can't be made to fail here
		// without a fault-injection hook.
		return fmt.Errorf("licenses: recording a refusal: %w", rerr)
	}
	return err
}
