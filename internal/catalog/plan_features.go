package catalog

import (
	"context"
	"maps"
	"math"
	"slices"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ent/planfeature"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/schema"
)

// maxPatchKeys bounds one feature patch (a matrix column has one key per
// feature of the product).
const maxPatchKeys = 1000

// maxLimit is the largest limit value, as the plan_features CHECK (and
// JSON's exact integers).
const maxLimit = 1<<53 - 1

// Features returns what plan id grants, by feature key: true for a boolean
// feature, the limit (int64, -1 unlimited) for a limit feature (ADR-0015).
// Missing, malformed and out of scope are ErrNotFound.
func (s Plans) Features(ctx context.Context, id string) (map[string]any, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		p, err := lookupPlan(ctx, tx, id, false)
		if err != nil {
			return err
		}
		out, err = planGrants(ctx, tx, p.ID)
		return err
	})
	return out, err
}

func planGrants(ctx context.Context, tx *ent.Tx, planID string) (map[string]any, error) {
	rows, err := tx.PlanFeature.Query().Where(planfeature.PlanID(planID)).WithFeature().All(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(rows))
	for _, r := range rows {
		if r.LimitValue != nil {
			out[r.Edges.Feature.Key] = *r.LimitValue
		} else {
			out[r.Edges.Feature.Key] = true
		}
	}
	return out, nil
}

// PatchFeatures applies a merge patch (RFC 7396) to plan id's grants, keyed
// by feature key: true grants a boolean feature, a whole number from -1
// (unlimited) to 2^53-1 sets a limit feature's value (JSON numbers arrive as
// float64), nil removes the grant. Every key must be a feature of the plan's
// product; an archived feature can't be granted anew, but its grant can
// change or go. All or nothing. Order (ADR-0032): visible (else
// ErrNotFound), catalog:write on the product, then the values. Licenses
// already issued keep their snapshot (ADR-0013). Returns the grants after
// the patch; a patch that changes nothing isn't audited.
func (s Plans) PatchFeatures(ctx context.Context, id string, patch map[string]any) (map[string]any, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	pr, _ := authz.FromContext(ctx)
	ev := audit.By(pr, "plan.features.update", "plan", "")
	var out map[string]any
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		// The product FOR SHARE, then the plan FOR UPDATE: the plan_features
		// lock contract (schema.PlanFeature), so an issue copies the grants
		// before or after the patch, never half of it.
		p, err := lookupPlan(ctx, tx, id, true)
		if err != nil {
			return err
		}
		ev.ObjectID = p.ID
		if err := authz.Require(ctx, authz.CatalogWrite, p.ProductID); err != nil {
			return err
		}
		if len(patch) > maxPatchKeys {
			return &InvalidError{Message: "at most 1000 features at once"}
		}
		keys := slices.Sorted(maps.Keys(patch))
		for _, k := range keys {
			if len(k) > 63 || !schema.KeyRE.MatchString(k) {
				return &InvalidError{Message: "feature keys are snake_case (lowercase letters and digits joined by single underscores), at most 63"}
			}
		}
		feats, err := tx.Feature.Query().Where(feature.ProductID(p.ProductID), feature.KeyIn(keys...)).All(ctx)
		if err != nil {
			return err
		}
		byKey := make(map[string]*ent.Feature, len(feats))
		for _, f := range feats {
			byKey[f.Key] = f
		}
		rows, err := tx.PlanFeature.Query().Where(planfeature.PlanID(p.ID)).All(ctx)
		if err != nil {
			return err
		}
		granted := make(map[string]*ent.PlanFeature, len(rows))
		for _, r := range rows {
			granted[r.FeatureID] = r
		}
		// Check everything before writing anything.
		type change struct {
			f     *ent.Feature
			limit *int64 // limit features
			drop  bool
		}
		var changes []change
		for _, k := range keys {
			f := byKey[k]
			if f == nil {
				return &InvalidError{Field: "/" + k, Message: "no such feature of the plan's product"}
			}
			c := change{f: f}
			switch v := patch[k].(type) {
			case nil:
				c.drop = true
			case bool:
				if !v || f.Type != feature.TypeBoolean {
					return &InvalidError{Field: "/" + k, Message: valueRule(f.Type)}
				}
			case float64:
				if f.Type != feature.TypeLimit || v != math.Trunc(v) || v < -1 || v > maxLimit {
					return &InvalidError{Field: "/" + k, Message: valueRule(f.Type)}
				}
				n := int64(v)
				c.limit = &n
			default:
				return &InvalidError{Field: "/" + k, Message: valueRule(f.Type)}
			}
			if !c.drop && f.ArchivedAt != nil && granted[f.ID] == nil {
				return &InvalidError{Field: "/" + k, Message: "archived: it can't be granted anew"}
			}
			changes = append(changes, c)
		}
		var set, removed []string
		for _, c := range changes {
			cur := granted[c.f.ID]
			switch {
			case c.drop && cur != nil:
				if err := tx.PlanFeature.DeleteOneID(cur.ID).Exec(ctx); err != nil {
					return err
				}
				removed = append(removed, c.f.Key)
			case c.drop:
			case cur == nil:
				if err := tx.PlanFeature.Create().SetID(ids.PlanFeature()).SetTenantID(tenantID).SetProductID(p.ProductID).SetPlanID(p.ID).
					SetFeatureID(c.f.ID).SetFeatureType(planfeature.FeatureType(c.f.Type)).SetNillableLimitValue(c.limit).Exec(ctx); err != nil {
					return err
				}
				set = append(set, c.f.Key)
			case c.limit != nil && *c.limit != *cur.LimitValue:
				if err := tx.PlanFeature.UpdateOne(cur).SetLimitValue(*c.limit).Exec(ctx); err != nil {
					return err
				}
				set = append(set, c.f.Key)
			}
		}
		if out, err = planGrants(ctx, tx, p.ID); err != nil {
			return err
		}
		if len(set)+len(removed) == 0 {
			return nil
		}
		ev.Outcome, ev.Details = auditevent.OutcomeSuccess, map[string]any{"product_id": p.ProductID}
		if set != nil {
			ev.Details["set"] = set
		}
		if removed != nil {
			ev.Details["removed"] = removed
		}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrNotFound)
	}
	return out, nil
}

func valueRule(t feature.Type) string {
	if t == feature.TypeLimit {
		return "a limit feature takes a whole number from -1 (unlimited) to 9007199254740991, or null to remove it"
	}
	return "a boolean feature takes true, or null to remove it"
}
