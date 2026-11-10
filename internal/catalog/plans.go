package catalog

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/plan"
	"licenseforge.io/licenseforge/internal/store/ent/product"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// maxSeconds is the license format's duration limit (36,500 days), as the
// plans CHECKs.
const maxSeconds = 3153600000

// Plans works on the tenant pool. A plan is one way of selling a product
// (ADR-0015); licenses copy its terms when issued (ADR-0013), so changing a
// plan never changes licenses already sold. Its slug and bind type never
// change; plans are archived, never deleted. Lock order: the product FOR
// SHARE, then the plan FOR UPDATE (schema.PlanFeature).
type Plans struct{ DB *store.DB }

// Terms are a plan's license terms.
type Terms struct {
	DurationMonths    *int   // calendar months; nil and no seconds: perpetual
	DurationSeconds   *int64 // whole seconds (trials, fixed periods)
	ExpiryBasis       plan.ExpiryBasis
	MaxActivations    *int // nil: unlimited
	MaxRehosts        *int // nil: unlimited
	BindType          plan.BindType
	OfflineAllowed    bool
	LeaseSeconds      int64
	MaxOfflineSeconds *int64
	GraceSeconds      int64
	UpdatesMonths     *int // maintenance from issue (ADR-0045); nil: every build covered
}

// PlanInput is a new plan.
type PlanInput struct {
	ProductID, Slug, Name string
	Terms
}

// PlanPatch is a merge patch of a plan: nil fields stay; Null lists fields
// set to null (the nullable terms are cleared; the others are invalid). The
// result is checked whole.
type PlanPatch struct {
	Name                                       *string
	DurationMonths, MaxActivations, MaxRehosts *int
	UpdatesMonths                              *int
	DurationSeconds, MaxOfflineSeconds         *int64
	ExpiryBasis                                *plan.ExpiryBasis
	OfflineAllowed                             *bool
	LeaseSeconds, GraceSeconds                 *int64
	Null                                       []string
}

// List returns up to limit of the tenant's plans in the caller's scope, of
// productID if not "", archived ones included, newest first.
func (s Plans) List(ctx context.Context, productID string, limit int, afterAt time.Time, afterID string) ([]*ent.Plan, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	all, scope, err := authz.Products(ctx, authz.CatalogRead)
	if err != nil {
		return nil, err
	}
	var out []*ent.Plan
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := tx.Plan.Query().Order(ent.Desc(plan.FieldCreatedAt), ent.Desc(plan.FieldID)).Limit(limit)
		if !all {
			q.Where(plan.ProductIDIn(scope...))
		}
		if productID != "" {
			q.Where(plan.ProductID(productID))
		}
		if afterID != "" {
			q.Where(plan.Or(plan.CreatedAtLT(afterAt), plan.And(plan.CreatedAt(afterAt), plan.IDLT(afterID))))
		}
		out, err = q.All(ctx)
		return err
	})
	return out, err
}

// Get returns a plan; missing, malformed and out of scope are ErrNotFound.
func (s Plans) Get(ctx context.Context, id string) (*ent.Plan, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	var p *ent.Plan
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		p, err = lookupPlan(ctx, tx, id, false)
		return err
	})
	return p, err
}

// lookupPlan finds a visible plan (catalog:read on its product); one lookup,
// then the scope. With lock, the product is locked FOR SHARE, then the plan
// FOR UPDATE, each looked up again after waiting for a concurrent archive
// (archive_once filters the row waited for).
func lookupPlan(ctx context.Context, tx *ent.Tx, id string, lock bool) (*ent.Plan, error) {
	if !ids.Valid("pln", id) {
		return nil, ErrNotFound
	}
	p, err := tx.Plan.Query().Where(plan.ID(id)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if authz.Require(ctx, authz.CatalogRead, p.ProductID) != nil {
		return nil, ErrNotFound
	}
	if !lock {
		return p, nil
	}
	again := func(q func() error) error {
		if err := q(); !ent.IsNotFound(err) {
			return err
		}
		return q()
	}
	if err := again(func() error {
		_, err := tx.Product.Query().Where(product.ID(p.ProductID)).ForShare().Only(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	if err := again(func() error {
		var err error
		p, err = tx.Plan.Query().Where(plan.ID(id)).ForUpdate().Only(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	return p, nil
}

// Create adds a plan to a product: the product reference (missing and hidden
// alike), catalog:write on it, then the values; not on an archived product.
func (s Plans) Create(ctx context.Context, in PlanInput) (*ent.Plan, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	pr, _ := authz.FromContext(ctx)
	ev := audit.By(pr, "plan.create", "plan", "")
	var p *ent.Plan
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		if err := activeProduct(ctx, tx, in.ProductID); err != nil {
			return err
		}
		if err := validSlug(in.Slug); err != nil {
			return err
		}
		if err := validName(in.Name); err != nil {
			return err
		}
		if err := validTerms(in.Terms); err != nil {
			return err
		}
		t := in.Terms
		var err error
		p, err = tx.Plan.Create().SetTenantID(tenantID).SetProductID(in.ProductID).SetSlug(in.Slug).SetName(in.Name).
			SetNillableDurationMonths(t.DurationMonths).SetNillableDurationSeconds(t.DurationSeconds).SetExpiryBasis(t.ExpiryBasis).
			SetNillableMaxActivations(t.MaxActivations).SetNillableMaxRehosts(t.MaxRehosts).SetBindType(t.BindType).
			SetOfflineAllowed(t.OfflineAllowed).SetLeaseSeconds(t.LeaseSeconds).SetNillableMaxOfflineSeconds(t.MaxOfflineSeconds).
			SetGraceSeconds(t.GraceSeconds).SetNillableUpdatesMonths(t.UpdatesMonths).Save(ctx)
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "plan_product_id_slug" {
			return &InvalidError{Field: "/slug", Message: "already used by a plan of this product", Conflict: true}
		}
		if err != nil {
			return err
		}
		ev.ObjectID, ev.Outcome = p.ID, auditevent.OutcomeSuccess
		ev.Details = map[string]any{"product_id": p.ProductID, "slug": p.Slug, "bind_type": string(p.BindType)}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		ev.ObjectID, ev.Details = "", nil
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrConflict)
	}
	return p, nil
}

// Update changes a plan's name or terms. Order (ADR-0032): visible (else
// ErrNotFound), catalog:write on its product, then the values, checked on
// the merged result. Issues read the plan FOR SHARE, so a license copies
// the terms before or after the change, never half of it.
func (s Plans) Update(ctx context.Context, id string, patch PlanPatch) (*ent.Plan, error) {
	return s.change(ctx, "plan.update", id, func(tx *ent.Tx, p *ent.Plan) (*ent.Plan, map[string]any, error) {
		for _, n := range patch.Null {
			if !slices.Contains([]string{"duration_months", "duration_seconds", "max_activations", "max_rehosts", "max_offline_seconds", "updates_months"}, n) {
				return nil, nil, &InvalidError{Field: "/" + n, Message: "can't be null"}
			}
		}
		name := p.Name
		t := Terms{DurationMonths: p.DurationMonths, DurationSeconds: p.DurationSeconds, ExpiryBasis: p.ExpiryBasis,
			MaxActivations: p.MaxActivations, MaxRehosts: p.MaxRehosts, BindType: p.BindType, OfflineAllowed: p.OfflineAllowed,
			LeaseSeconds: p.LeaseSeconds, MaxOfflineSeconds: p.MaxOfflineSeconds, GraceSeconds: p.GraceSeconds,
			UpdatesMonths: p.UpdatesMonths}
		var changed []string
		set := func(field string, given bool, apply func()) {
			if given {
				apply()
				changed = append(changed, field)
			}
		}
		null := func(f string) bool { return slices.Contains(patch.Null, f) }
		set("name", patch.Name != nil, func() { name = *patch.Name })
		set("duration_months", patch.DurationMonths != nil || null("duration_months"), func() { t.DurationMonths = patch.DurationMonths })
		set("duration_seconds", patch.DurationSeconds != nil || null("duration_seconds"), func() { t.DurationSeconds = patch.DurationSeconds })
		set("expiry_basis", patch.ExpiryBasis != nil, func() { t.ExpiryBasis = *patch.ExpiryBasis })
		set("max_activations", patch.MaxActivations != nil || null("max_activations"), func() { t.MaxActivations = patch.MaxActivations })
		set("max_rehosts", patch.MaxRehosts != nil || null("max_rehosts"), func() { t.MaxRehosts = patch.MaxRehosts })
		set("offline_allowed", patch.OfflineAllowed != nil, func() { t.OfflineAllowed = *patch.OfflineAllowed })
		set("lease_seconds", patch.LeaseSeconds != nil, func() { t.LeaseSeconds = *patch.LeaseSeconds })
		set("max_offline_seconds", patch.MaxOfflineSeconds != nil || null("max_offline_seconds"), func() { t.MaxOfflineSeconds = patch.MaxOfflineSeconds })
		set("grace_seconds", patch.GraceSeconds != nil, func() { t.GraceSeconds = *patch.GraceSeconds })
		set("updates_months", patch.UpdatesMonths != nil || null("updates_months"), func() { t.UpdatesMonths = patch.UpdatesMonths })
		if err := validName(name); err != nil {
			return nil, nil, err
		}
		if err := validTerms(t); err != nil {
			return nil, nil, err
		}
		u := tx.Plan.UpdateOne(p).SetName(name).SetExpiryBasis(t.ExpiryBasis).SetOfflineAllowed(t.OfflineAllowed).
			SetLeaseSeconds(t.LeaseSeconds).SetGraceSeconds(t.GraceSeconds).
			SetNillableDurationMonths(t.DurationMonths).SetNillableDurationSeconds(t.DurationSeconds).
			SetNillableMaxActivations(t.MaxActivations).SetNillableMaxRehosts(t.MaxRehosts).SetNillableMaxOfflineSeconds(t.MaxOfflineSeconds).
			SetNillableUpdatesMonths(t.UpdatesMonths)
		// SetNillable leaves a column as is for nil: clear the unset terms.
		if t.DurationMonths == nil {
			u.ClearDurationMonths()
		}
		if t.DurationSeconds == nil {
			u.ClearDurationSeconds()
		}
		if t.MaxActivations == nil {
			u.ClearMaxActivations()
		}
		if t.MaxRehosts == nil {
			u.ClearMaxRehosts()
		}
		if t.MaxOfflineSeconds == nil {
			u.ClearMaxOfflineSeconds()
		}
		if t.UpdatesMonths == nil {
			u.ClearUpdatesMonths()
		}
		p, err := u.Save(ctx)
		return p, map[string]any{"changed": changed}, err
	})
}

// Archive archives a plan, once (ErrState after): no new license is issued
// from it; licenses already sold keep their terms.
func (s Plans) Archive(ctx context.Context, id string) (*ent.Plan, error) {
	return s.change(ctx, "plan.archive", id, func(tx *ent.Tx, p *ent.Plan) (*ent.Plan, map[string]any, error) {
		// Atomic and counted: only an unarchived plan is archived, once.
		res, err := tx.ExecContext(ctx, `UPDATE plans SET archived_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1 AND archived_at IS NULL`, p.ID)
		if err != nil {
			return nil, nil, err
		}
		if n, err := res.RowsAffected(); err != nil {
			return nil, nil, err
		} else if n != 1 {
			return nil, nil, ErrState
		}
		p, err = tx.Plan.Get(ctx, p.ID)
		return p, nil, err
	})
}

// change runs fn on the locked, visible plan after catalog:write on its
// product, and records the outcome.
func (s Plans) change(ctx context.Context, action, id string, fn func(*ent.Tx, *ent.Plan) (*ent.Plan, map[string]any, error)) (*ent.Plan, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	pr, _ := authz.FromContext(ctx)
	ev := audit.By(pr, action, "plan", "")
	var out *ent.Plan
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		p, err := lookupPlan(ctx, tx, id, true)
		if err != nil {
			return err
		}
		ev.ObjectID = p.ID
		if err := authz.Require(ctx, authz.CatalogWrite, p.ProductID); err != nil {
			return err
		}
		var details map[string]any
		if out, details, err = fn(tx, p); err != nil {
			return err
		}
		ev.Outcome, ev.Details = auditevent.OutcomeSuccess, details
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrNotFound, ErrState)
	}
	return out, nil
}

// validTerms checks a plan's terms as the plans CHECKs do, naming the field.
func validTerms(t Terms) error {
	bad := func(field, msg string) error { return &InvalidError{Field: field, Message: msg} }
	switch {
	case t.DurationMonths != nil && (*t.DurationMonths < 1 || *t.DurationMonths > 1200):
		return bad("/duration_months", "1 to 1200")
	case t.DurationSeconds != nil && (*t.DurationSeconds < 1 || *t.DurationSeconds > maxSeconds):
		return bad("/duration_seconds", "1 to 3153600000 (36,500 days)")
	case t.DurationMonths != nil && t.DurationSeconds != nil:
		return bad("/duration_seconds", "give duration_months or duration_seconds, not both")
	case plan.ExpiryBasisValidator(t.ExpiryBasis) != nil:
		return bad("/expiry_basis", "from_issue or from_first_activation")
	case plan.BindTypeValidator(t.BindType) != nil:
		return bad("/bind_type", "none, machine or cluster")
	case t.MaxActivations != nil && (*t.MaxActivations < 1 || *t.MaxActivations > 1_000_000):
		return bad("/max_activations", "1 to 1000000, or null for unlimited")
	case t.MaxRehosts != nil && (*t.MaxRehosts < 0 || *t.MaxRehosts > 1_000_000):
		return bad("/max_rehosts", "0 to 1000000, or null for unlimited")
	case t.LeaseSeconds < 1 || t.LeaseSeconds > maxSeconds:
		return bad("/lease_seconds", "1 to 3153600000")
	case t.MaxOfflineSeconds != nil && (*t.MaxOfflineSeconds < 0 || *t.MaxOfflineSeconds > maxSeconds):
		return bad("/max_offline_seconds", "0 to 3153600000, or null")
	case t.GraceSeconds < 0 || t.GraceSeconds > maxSeconds:
		return bad("/grace_seconds", "0 to 3153600000")
	case t.UpdatesMonths != nil && (*t.UpdatesMonths < 1 || *t.UpdatesMonths > 1200):
		return bad("/updates_months", "1 to 1200, or null for every build")
	case t.BindType == plan.BindTypeNone && t.ExpiryBasis == plan.ExpiryBasisFromFirstActivation:
		return bad("/expiry_basis", "a site license (bind_type none) has no activation to start from")
	case t.BindType == plan.BindTypeNone && t.MaxActivations != nil:
		return bad("/max_activations", "a site license (bind_type none) has no activations")
	}
	return nil
}
